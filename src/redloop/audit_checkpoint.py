"""Protected, external audit checkpoints for the RedLoop hash-chained ledger.

The SQLite ledger already contains an internal ``audit_chain_anchor`` table, but
an attacker who can replace the whole database can also replace that table.  This
module keeps an independent, HMAC-authenticated checkpoint in a file next to the
database, plus a separate key file and a monotonic sequence sidecar.

Threat model and guarantees
---------------------------
* Modification of the checkpoint file is detected (HMAC mismatch).
* Replacement with another well-formed checkpoint from the same key is detected
  through the append-only history and the sequence sidecar.
* Truncation of the audit ledger after a checkpoint is detected by comparing the
  current event count/head with the checkpoint.
* Rollback of the checkpoint file to an older sequence is detected by the
  sequence sidecar.
* Rotating the key without re-signing is reported as ``KEY_MISMATCH``.

There is no absolute protection against an attacker who can atomically replace
the database, checkpoint, sequence sidecar *and* key file with a consistent old
copy.  Such a rollback must be anchored outside this host (for example in a WORM
store or a remote transparency log); that limitation is reported explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

CHECKPOINT_VERSION = 1
CHECKPOINT_VALID = "CHECKPOINT_VALID"
CHECKPOINT_VALID_UNANCHORED_TAIL = "CHECKPOINT_VALID_UNANCHORED_TAIL"
CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
CHECKPOINT_TAMPERED = "CHECKPOINT_TAMPERED"
CHECKPOINT_TRUNCATED = "CHECKPOINT_TRUNCATED"
CHECKPOINT_ROLLBACK = "CHECKPOINT_ROLLBACK"
CHECKPOINT_KEY_MISSING = "CHECKPOINT_KEY_MISSING"
CHECKPOINT_KEY_MISMATCH = "CHECKPOINT_KEY_MISMATCH"
CHECKPOINT_CHAIN_INVALID = "CHECKPOINT_CHAIN_INVALID"
CHECKPOINT_INCOMPLETE = "CHECKPOINT_INCOMPLETE"


class AuditCheckpointError(ValueError):
    """Raised when a checkpoint cannot be created safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CheckpointPaths:
    checkpoint: Path
    key: Path
    sequence: Path


class AuditCheckpointStore:
    """Create and verify external checkpoints for an :class:`AuditLogger`."""

    def __init__(
        self,
        db_path: str | Path,
        checkpoint_path: str | Path | None = None,
        key_path: str | Path | None = None,
    ):
        db = Path(db_path).expanduser().resolve()
        self.db_path = db
        self.paths = CheckpointPaths(
            checkpoint=Path(checkpoint_path).expanduser().resolve()
            if checkpoint_path
            else db.with_name(db.name + ".checkpoint.json"),
            key=Path(key_path).expanduser().resolve()
            if key_path
            else db.with_name(db.name + ".checkpoint.key"),
            sequence=(
                Path(checkpoint_path).expanduser().resolve().with_name(
                    Path(checkpoint_path).name + ".seq"
                )
                if checkpoint_path
                else db.with_name(db.name + ".checkpoint.seq")
            ),
        )

    # ------------------------------------------------------------------
    # Key handling
    # ------------------------------------------------------------------
    def _read_key(self) -> bytes:
        if not self.paths.key.exists():
            raise FileNotFoundError(str(self.paths.key))
        raw = self.paths.key.read_bytes().strip()
        try:
            key = bytes.fromhex(raw.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditCheckpointError("Checkpoint key file is not valid hexadecimal.") from exc
        if len(key) < 32:
            raise AuditCheckpointError("Checkpoint key must be at least 256 bits.")
        return key

    def _write_key(self, key: bytes) -> None:
        self.paths.key.parent.mkdir(parents=True, exist_ok=True)
        self.paths.key.write_bytes(key.hex().encode("ascii"))
        try:
            os.chmod(self.paths.key, 0o600)
        except OSError:
            pass

    @staticmethod
    def key_id(key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()[:16]

    def ensure_key(self) -> bytes:
        try:
            return self._read_key()
        except FileNotFoundError:
            key = secrets.token_bytes(32)
            self._write_key(key)
            return key

    # ------------------------------------------------------------------
    # Checkpoint file handling
    # ------------------------------------------------------------------
    def _sign(self, payload: dict[str, Any], key: bytes) -> str:
        return hmac.new(key, _canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def _load(self) -> dict[str, Any] | None:
        if not self.paths.checkpoint.exists():
            return None
        try:
            data = json.loads(self.paths.checkpoint.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuditCheckpointError("Checkpoint file is unreadable or malformed.") from exc
        if not isinstance(data, dict):
            raise AuditCheckpointError("Checkpoint file must contain a JSON object.")
        return data

    def _load_verified(self, key: bytes) -> dict[str, Any]:
        data = self._load()
        if data is None:
            raise FileNotFoundError(str(self.paths.checkpoint))
        signature = str(data.pop("hmac", ""))
        expected = self._sign(data, key)
        if not signature or not hmac.compare_digest(signature, expected):
            raise AuditCheckpointError("Checkpoint HMAC verification failed.")
        data["hmac"] = signature
        return data

    def _save(self, data: dict[str, Any], key: bytes) -> None:
        payload = {k: v for k, v in data.items() if k != "hmac"}
        data = dict(payload)
        data["hmac"] = self._sign(payload, key)
        self.paths.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.paths.checkpoint.with_name(self.paths.checkpoint.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.paths.checkpoint)
        try:
            os.chmod(self.paths.checkpoint, 0o600)
        except OSError:
            pass

    def _read_sequence_sidecar(self) -> int:
        if not self.paths.sequence.exists():
            return 0
        try:
            value = self.paths.sequence.read_text(encoding="utf-8").strip() or "0"
            sequence = int(value)
        except (OSError, ValueError) as exc:
            raise AuditCheckpointError("Checkpoint sequence sidecar is unreadable or malformed.") from exc
        if sequence < 0:
            raise AuditCheckpointError("Checkpoint sequence sidecar contains a negative sequence.")
        return sequence

    def _write_sequence_sidecar(self, sequence: int) -> None:
        self.paths.sequence.parent.mkdir(parents=True, exist_ok=True)
        self.paths.sequence.write_text(str(sequence), encoding="utf-8")
        try:
            os.chmod(self.paths.sequence, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def create(self, audit: Any) -> dict[str, Any]:
        """Append a checkpoint for the current verified ledger head.

        Refuses to checkpoint an empty or internally invalid ledger.  Calling
        this repeatedly without new events returns the existing checkpoint
        instead of growing the history.
        """
        chain = audit.verify_chain(require_anchor=False, compare_anchor=False)
        if chain.get("status") != "INTEGRITY_VERIFIED":
            raise AuditCheckpointError(
                f"Cannot checkpoint a ledger that is not internally verified: {chain.get('status')}."
            )
        if int(chain.get("total_events") or 0) == 0:
            raise AuditCheckpointError("Cannot checkpoint an empty audit ledger.")
        if self.paths.checkpoint.exists() and not self.paths.key.exists():
            raise AuditCheckpointError(
                "Checkpoint exists but its key file is missing. Restore the original key; "
                "refusing to create a replacement key over an existing checkpoint."
            )

        key = self.ensure_key()
        now = _utc_now()
        head_hash = str(chain.get("head_hash") or "")
        total = int(chain.get("total_events") or 0)
        last_id = int(chain.get("last_id") or 0)

        try:
            existing = self._load_verified(key)
        except FileNotFoundError:
            existing = None
        except AuditCheckpointError:
            # A tampered file must not be silently overwritten.
            raise

        if existing:
            history = list(existing.get("history") or [])
            if not history:
                history = [
                    {
                        k: existing.get(k)
                        for k in (
                            "sequence",
                            "event_count",
                            "last_id",
                            "head_hash",
                            "key_id",
                            "created_at",
                            "previous_checkpoint_hash",
                            "checkpoint_hash",
                        )
                    }
                ]
            latest = history[-1]
            if (
                int(latest.get("event_count") or 0) == total
                and str(latest.get("head_hash") or "") == head_hash
                and int(latest.get("last_id") or 0) == last_id
            ):
                return {
                    "created": False,
                    "status": CHECKPOINT_VALID,
                    "checkpoint": self._public_view(existing),
                }
            sequence = int(existing.get("sequence") or 0) + 1
            previous_hash = str(latest.get("checkpoint_hash") or existing.get("hmac") or "")
        else:
            history = []
            sequence = 1
            previous_hash = ""

        entry = {
            "sequence": sequence,
            "event_count": total,
            "last_id": last_id,
            "head_hash": head_hash,
            "key_id": self.key_id(key),
            "created_at": now,
            "previous_checkpoint_hash": previous_hash,
        }
        entry["checkpoint_hash"] = _digest(entry)
        history.append(entry)
        data = {
            "version": CHECKPOINT_VERSION,
            "sequence": sequence,
            "event_count": total,
            "last_id": last_id,
            "head_hash": head_hash,
            "key_id": self.key_id(key),
            "created_at": now,
            "previous_checkpoint_hash": previous_hash,
            "history": history,
        }
        self._save(data, key)
        self._write_sequence_sidecar(sequence)
        return {
            "created": True,
            "status": CHECKPOINT_VALID,
            "checkpoint": self._public_view({**data, "hmac": self._sign(data, key)}),
        }

    def verify(self, audit: Any) -> dict[str, Any]:
        """Verify the external checkpoint against the current audit ledger."""
        if not self.paths.checkpoint.exists():
            return self._result(
                CHECKPOINT_MISSING,
                "No external checkpoint exists for this ledger. Run checkpoint creation explicitly.",
            )
        if not self.paths.key.exists():
            return self._result(
                CHECKPOINT_KEY_MISSING,
                "Checkpoint key file is missing; the external checkpoint cannot be authenticated.",
            )
        try:
            sidecar = self._read_sequence_sidecar()
        except AuditCheckpointError as exc:
            return self._result(CHECKPOINT_TAMPERED, str(exc))

        try:
            key = self._read_key()
        except (AuditCheckpointError, OSError) as exc:
            return self._result(CHECKPOINT_TAMPERED, str(exc))

        # Compare the advertised key id before HMAC verification so a missing or
        # rotated key is reported as such instead of as generic tampering.
        try:
            unverified = self._load()
        except AuditCheckpointError as exc:
            return self._result(CHECKPOINT_TAMPERED, str(exc))
        if unverified and unverified.get("key_id"):
            if str(unverified.get("key_id")) != self.key_id(key):
                return self._result(
                    CHECKPOINT_KEY_MISMATCH,
                    "Checkpoint was signed with a different key. Rotate the key explicitly to re-sign.",
                    checkpoint=self._public_view(unverified),
                )

        try:
            data = self._load_verified(key)
        except FileNotFoundError:
            return self._result(
                CHECKPOINT_MISSING,
                "No external checkpoint exists for this ledger. Run checkpoint creation explicitly.",
            )
        except AuditCheckpointError as exc:
            return self._result(CHECKPOINT_TAMPERED, str(exc))

        if int(data.get("version") or 0) != CHECKPOINT_VERSION:
            return self._result(CHECKPOINT_TAMPERED, "Unsupported checkpoint version.")
        if str(data.get("key_id") or "") != self.key_id(key):
            return self._result(
                CHECKPOINT_KEY_MISMATCH,
                "Checkpoint was signed with a different key. Rotate the key explicitly to re-sign.",
            )

        history = data.get("history") or []
        if not isinstance(history, list) or not history:
            return self._result(CHECKPOINT_TAMPERED, "Checkpoint history is missing.")
        if int(data.get("sequence") or 0) != len(history):
            return self._result(CHECKPOINT_TAMPERED, "Checkpoint sequence does not match history length.")
        for index, entry in enumerate(history, start=1):
            if not isinstance(entry, dict) or int(entry.get("sequence") or 0) != index:
                return self._result(CHECKPOINT_TAMPERED, "Checkpoint history sequence is not contiguous.")
            expected = _digest({k: v for k, v in entry.items() if k != "checkpoint_hash"})
            if not hmac.compare_digest(str(entry.get("checkpoint_hash") or ""), expected):
                return self._result(CHECKPOINT_TAMPERED, "Checkpoint history entry hash mismatch.")
            if index > 1:
                prior = str(history[index - 2].get("checkpoint_hash") or "")
                if str(entry.get("previous_checkpoint_hash") or "") != prior:
                    return self._result(CHECKPOINT_TAMPERED, "Checkpoint history chain is broken.")

        sequence = int(data.get("sequence") or 0)
        if sidecar and sequence < sidecar:
            return self._result(
                CHECKPOINT_ROLLBACK,
                f"Checkpoint sequence {sequence} is older than previously observed sequence {sidecar}.",
                checkpoint=self._public_view(data),
            )

        chain = audit.verify_chain(require_anchor=False, compare_anchor=False)
        if chain.get("status") != "INTEGRITY_VERIFIED":
            return self._result(
                CHECKPOINT_CHAIN_INVALID,
                f"Audit ledger is not internally valid: {chain.get('status')}.",
                checkpoint=self._public_view(data),
                audit=chain,
            )

        total = int(chain.get("total_events") or 0)
        if total == 0:
            return self._result(
                CHECKPOINT_INCOMPLETE,
                "Audit ledger is empty but a checkpoint exists.",
                checkpoint=self._public_view(data),
                audit=chain,
            )

        last_id = int(chain.get("last_id") or 0)
        head_hash = str(chain.get("head_hash") or "")
        anchored_events = int(data.get("event_count") or 0)
        anchored_id = int(data.get("last_id") or 0)
        anchored_head = str(data.get("head_hash") or "")

        if total < anchored_events or last_id < anchored_id:
            return self._result(
                CHECKPOINT_TRUNCATED,
                f"Ledger has {total} events (last id {last_id}) but checkpoint anchors "
                f"{anchored_events} events (last id {anchored_id}).",
                checkpoint=self._public_view(data),
                audit=chain,
            )

        if total == anchored_events:
            if head_hash != anchored_head or last_id != anchored_id:
                return self._result(
                    CHECKPOINT_TAMPERED,
                    "Ledger head differs from the checkpoint for the same event count.",
                    checkpoint=self._public_view(data),
                    audit=chain,
                )
            return self._result(
                CHECKPOINT_VALID,
                "Ledger exactly matches the external checkpoint.",
                checkpoint=self._public_view(data),
                audit=chain,
            )

        return self._result(
            CHECKPOINT_VALID_UNANCHORED_TAIL,
            f"Checkpoint is valid; {total - anchored_events} newer event(s) are not yet anchored.",
            checkpoint=self._public_view(data),
            audit=chain,
            extra={"tail_events": total - anchored_events},
        )

    def rotate_key(self, audit: Any, new_key: bytes | None = None) -> dict[str, Any]:
        """Re-sign the latest checkpoint with a new key and archive the old one."""
        if not self.paths.key.exists():
            raise AuditCheckpointError("Cannot rotate a key that does not exist.")
        old_key = self._read_key()
        data = self._load_verified(old_key)
        key = new_key or secrets.token_bytes(32)
        if len(key) < 32:
            raise AuditCheckpointError("New checkpoint key must be at least 256 bits.")
        archive = self.paths.key.with_name(self.paths.key.name + f".{self.key_id(old_key)}.old")
        archive.write_bytes(self.paths.key.read_bytes())
        try:
            os.chmod(archive, 0o600)
        except OSError:
            pass
        self._write_key(key)
        data["key_id"] = self.key_id(key)
        data["rotated_at"] = _utc_now()
        self._save(data, key)
        return {
            "rotated": True,
            "status": CHECKPOINT_VALID,
            "old_key_id": self.key_id(old_key),
            "new_key_id": self.key_id(key),
            "archived_key": str(archive),
        }

    def status(self, audit: Any) -> dict[str, Any]:
        return self.verify(audit)

    # ------------------------------------------------------------------
    # Internal result helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _public_view(data: dict[str, Any]) -> dict[str, Any]:
        history = data.get("history") or []
        return {
            "sequence": data.get("sequence"),
            "event_count": data.get("event_count"),
            "last_id": data.get("last_id"),
            "head_hash": data.get("head_hash"),
            "key_id": data.get("key_id"),
            "created_at": data.get("created_at"),
            "history_length": len(history),
            "hmac_present": bool(data.get("hmac")),
        }

    @staticmethod
    def _result(
        status: str,
        message: str,
        *,
        checkpoint: dict[str, Any] | None = None,
        audit: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {
            "status": status,
            "valid": status in (CHECKPOINT_VALID, CHECKPOINT_VALID_UNANCHORED_TAIL),
            "message": message,
            "checkpoint": checkpoint,
            "audit": audit,
            "external": True,
            "database_independent": True,
            "limitations": [
                "An attacker who atomically replaces the ledger, checkpoint, sequence sidecar, and key "
                "with a consistent old copy can still roll the host back; anchor outside the host for "
                "absolute rollback protection."
            ],
        }
        if extra:
            result.update(extra)
        return result


__all__ = [
    "AuditCheckpointError",
    "AuditCheckpointStore",
    "CHECKPOINT_CHAIN_INVALID",
    "CHECKPOINT_INCOMPLETE",
    "CHECKPOINT_KEY_MISMATCH",
    "CHECKPOINT_KEY_MISSING",
    "CHECKPOINT_MISSING",
    "CHECKPOINT_ROLLBACK",
    "CHECKPOINT_TAMPERED",
    "CHECKPOINT_TRUNCATED",
    "CHECKPOINT_VALID",
    "CHECKPOINT_VALID_UNANCHORED_TAIL",
]
