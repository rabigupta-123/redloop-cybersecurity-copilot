"""Cryptographically chained tamper-evident SQLite activity records for RedLoop workflows.

Implements hash chaining:
    event_hash = SHA256(canonical_event_json + previous_event_hash)

Provides verification against:
    - modified events
    - deleted events
    - reordered events
    - broken chains
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
import re
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    module      TEXT    NOT NULL,
    status      TEXT    NOT NULL,   -- started | success | failed | blocked
    details     TEXT,                  -- JSON blob
    scope_entry TEXT,                  -- scope.yaml entry label that authorized this
    prev_hash   TEXT,                  -- SHA-256 of preceding row (or GENESIS_HASH)
    event_hash  TEXT                   -- SHA-256(canonical_json + prev_hash)
);

CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_mod   ON audit_log(module);

-- Trusted chain anchor. Holds the last known-good head so truncation and
-- tail deletion can be detected. It is only written by seal_chain(), never
-- rewritten automatically during verification.
CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    head_hash   TEXT    NOT NULL,
    last_id     INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    sealed_at   TEXT    NOT NULL
);
"""

# Canonical verification outcomes. These are the only statuses the API and UI
# may display; `valid` is retained for backwards compatibility and is true only
# for INTEGRITY_VERIFIED.
INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
TAMPER_DETECTED = "TAMPER_DETECTED"
VERIFICATION_INCOMPLETE = "VERIFICATION_INCOMPLETE"
CHAIN_GAP_DETECTED = "CHAIN_GAP_DETECTED"

SECRET_PATTERNS = [
    re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"AIza[a-zA-Z0-9_\-]{30,}"),
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE),
]


SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "auth_token",
        "bearer",
        "client_secret",
        "cookie",
        "credentials",
        "password",
        "passwd",
        "private_key",
        "secret",
        "set_cookie",
        "token",
        "x_api_key",
    }
)

SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_auth_token",
    "_authorization",
    "_client_secret",
    "_cookie",
    "_credentials",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)

# Numeric metrics whose names contain a sensitive-looking word but are counts,
# not credentials (e.g. token_count, total_tokens, prompt_tokens).
USAGE_METRIC_KEYS = frozenset(
    {
        "completion_tokens",
        "prompt_tokens",
        "token_count",
        "tokens",
        "total_tokens",
    }
)


def _normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def _is_sensitive_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    if normalized in USAGE_METRIC_KEYS:
        return False
    if normalized in SENSITIVE_KEYS:
        return True
    return any(normalized.endswith(suffix) for suffix in SENSITIVE_KEY_SUFFIXES)


def sanitize_audit_data(data: Any) -> Any:
    """Recursively redact secrets, API keys, and sensitive tokens from audit records."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if _is_sensitive_key(k):
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    normalized = _normalize_key(k)
                    if normalized in USAGE_METRIC_KEYS or normalized.endswith("_count"):
                        sanitized[k] = v
                        continue
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_data(v)
        return sanitized
    elif isinstance(data, (list, tuple)):
        return [sanitize_audit_data(item) for item in data]
    elif isinstance(data, str):
        cleaned = data
        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        return cleaned
    return data


def compute_canonical_event_json(
    timestamp: str,
    target: str,
    action: str,
    module: str,
    status: str,
    details_str: str,
    scope_entry: str | None,
) -> str:
    """Produce deterministic, sort-keyed canonical JSON for an audit event."""
    try:
        parsed_details = json.loads(details_str)
    except Exception:
        parsed_details = details_str

    canonical_dict = {
        "action": action,
        "details": parsed_details,
        "module": module,
        "scope_entry": scope_entry or "",
        "status": status,
        "target": target,
        "timestamp": timestamp,
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))


def compute_event_hash(canonical_event_json: str, prev_hash: str) -> str:
    """event_hash = SHA256(canonical_event_json + previous_event_hash)"""
    return hashlib.sha256((canonical_event_json + prev_hash).encode("utf-8")).hexdigest()


class AuditLogger:
    """Write cryptographically chained audit rows using a per-call SQLite connection."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            try:
                from redloop.config import settings
                self.db_path = Path(settings.audit_db)
            except Exception:
                self.db_path = Path("redloop_audit.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            self._ensure_columns(conn)

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        """Migrate legacy schema if prev_hash or event_hash are absent, and seal legacy rows."""
        cur = conn.execute("PRAGMA table_info(audit_log)")
        existing_cols = {row[1] for row in cur.fetchall()}
        if "prev_hash" not in existing_cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "event_hash" not in existing_cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN event_hash TEXT")

        # Backfill any legacy rows that were created prior to tamper-evident chaining
        unhashed = conn.execute(
            "SELECT id, timestamp, target, action, module, status, details, scope_entry, prev_hash, event_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()
        if unhashed and any(r[9] is None or r[9] == "" for r in unhashed):
            current_prev = GENESIS_HASH
            for r in unhashed:
                row_id, ts, target, action, module, status, details_str, scope_entry, p_hash, e_hash = r
                if not e_hash:
                    canonical = compute_canonical_event_json(
                        ts, target, action, module, status, details_str or "{}", scope_entry
                    )
                    e_hash = compute_event_hash(canonical, current_prev)
                    conn.execute(
                        "UPDATE audit_log SET prev_hash = ?, event_hash = ? WHERE id = ?",
                        (current_prev, e_hash, row_id),
                    )
                current_prev = e_hash
            conn.commit()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def log(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> int:
        """Insert one cryptographically chained audit row. Returns the new row id."""
        if len(args) >= 4:
            actual_target = str(args[0])
            actual_action = str(args[1])
            actual_module = str(args[2])
            actual_status = str(args[3])
            actual_details = dict(args[4]) if len(args) > 4 and isinstance(args[4], dict) else {}
            actual_scope_entry = str(args[5]) if len(args) > 5 and args[5] else kwargs.get("scope_entry")
            actual_details.update(kwargs)
        elif len(args) == 1:
            actual_action = str(args[0])
            actual_target = str(kwargs.pop("target", "system"))
            actual_module = str(kwargs.pop("module", "assessment"))
            actual_status = str(kwargs.pop("status", "INFO"))
            actual_scope_entry = kwargs.pop("scope_entry", None)
            actual_details = kwargs
        else:
            actual_action = str(kwargs.pop("action", args[1] if len(args) > 1 else "event"))
            actual_target = str(kwargs.pop("target", args[0] if len(args) > 0 else "system"))
            actual_module = str(kwargs.pop("module", "assessment"))
            actual_status = str(kwargs.pop("status", "INFO"))
            actual_scope_entry = kwargs.pop("scope_entry", None)
            actual_details = kwargs

        ts = datetime.now(timezone.utc).isoformat()
        sanitized_details = sanitize_audit_data(actual_details)
        details_str = json.dumps(sanitized_details, default=str)

        with self._conn() as conn:
            # Serialize the read-previous-hash / insert sequence across processes.
            # Without an immediate write transaction two concurrent writers can
            # both read the same predecessor and fork the hash chain.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT event_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row[0] if (row and row[0]) else GENESIS_HASH

            canonical_json = compute_canonical_event_json(
                ts, actual_target, actual_action, actual_module, actual_status, details_str, actual_scope_entry
            )
            event_hash = compute_event_hash(canonical_json, prev_hash)

            cur = conn.execute(
                "INSERT INTO audit_log "
                "(timestamp, target, action, module, status, details, scope_entry, prev_hash, event_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    actual_target,
                    actual_action,
                    actual_module,
                    actual_status,
                    details_str,
                    actual_scope_entry,
                    prev_hash,
                    event_hash,
                ),
            )
            return cur.lastrowid or 0

    def started(self, target: str, action: str, module: str, **details: Any) -> int:
        return self.log(target, action, module, "started", details)

    def success(self, target: str, action: str, module: str, **details: Any) -> int:
        return self.log(target, action, module, "success", details)

    def failed(self, target: str, action: str, module: str, **details: Any) -> int:
        return self.log(target, action, module, "failed", details)

    def blocked(self, target: str, action: str, module: str, reason: str = "") -> int:
        return self.log(
            target, action, module, "blocked", {"reason": reason}, scope_entry=None
        )

    def _read_anchor(self, conn: sqlite3.Connection) -> dict[str, Any] | None:
        try:
            row = conn.execute(
                "SELECT head_hash, last_id, event_count, sealed_at FROM audit_chain_anchor WHERE id = 1"
            ).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        return {
            "head_hash": row[0],
            "last_id": row[1],
            "event_count": row[2],
            "sealed_at": row[3],
        }

    @staticmethod
    def _anchor_summary(anchor: dict[str, Any] | None, status: str) -> dict[str, Any]:
        return {
            "present": anchor is not None,
            "status": status,
            "head_hash": anchor["head_hash"] if anchor else None,
            "last_id": anchor["last_id"] if anchor else None,
            "event_count": anchor["event_count"] if anchor else None,
            "sealed_at": anchor["sealed_at"] if anchor else None,
        }

    @staticmethod
    def _failure(
        status: str,
        summary: str,
        *,
        event_id: int | None,
        sequence: int | None,
        reason: str,
        kind: str,
        checks: dict[str, Any],
        total_events: int,
        verified_events: int,
        first_id: int | None = None,
        last_id: int | None = None,
        head_hash: str | None = None,
        anchor: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build one complete, self-consistent failure result."""
        result = {
            "status": status,
            "valid": False,
            "verified": False,
            "total_events": total_events,
            "verified_events": verified_events,
            "expected_events": None,
            "first_id": first_id,
            "last_id": last_id,
            "head_hash": head_hash,
            "message": summary,
            "error": summary,
            "broken_at_id": event_id,
            "failure": {
                "event_id": event_id,
                "sequence": sequence,
                "reason": reason,
                "kind": kind,
            },
            "checks": checks,
            "anchor": anchor or AuditLogger._anchor_summary(None, "NOT_CHECKED"),
        }
        if extra:
            result.update(extra)
        return result

    def verify_chain(
        self, *, require_anchor: bool = False, compare_anchor: bool = True
    ) -> dict[str, Any]:
        """Verify the tamper-evident cryptographic integrity of the audit log chain.

        Detects modified events, deleted/reordered events, broken previous-hash
        links, and divergence from the trusted chain anchor when one exists.

        Outcomes (``status``):
            INTEGRITY_VERIFIED     every event hash, link, and sequence passes
            TAMPER_DETECTED        a cryptographic mismatch was confirmed
            CHAIN_GAP_DETECTED     an expected event/id is missing or continuity
                                   fails (including truncation vs the anchor)
            VERIFICATION_INCOMPLETE verification could not be completed (empty
                                   log, unreadable/absent required data, required
                                   anchor absent)

        An empty log is never reported as successful verification.
        """
        checks = {
            "hashes": False,
            "previous_hash_links": False,
            "sequence_continuity": False,
            "canonical_serialization": False,
            "anchor": False,
        }
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT id, timestamp, target, action, module, status, details, scope_entry, prev_hash, event_hash "
                    "FROM audit_log ORDER BY id ASC"
                ).fetchall()
                anchor = self._read_anchor(conn)
        except sqlite3.Error as exc:
            return self._failure(
                VERIFICATION_INCOMPLETE,
                f"Audit log could not be read: {exc}",
                event_id=None,
                sequence=None,
                reason=str(exc),
                kind="READ_ERROR",
                checks=checks,
                total_events=0,
                verified_events=0,
                anchor=self._anchor_summary(None, "UNAVAILABLE"),
            )

        if not rows:
            if anchor and anchor["event_count"] > 0:
                return self._failure(
                    CHAIN_GAP_DETECTED,
                    (
                        f"Audit log is empty but the trusted anchor records "
                        f"{anchor['event_count']} events (last id {anchor['last_id']})."
                    ),
                    event_id=None,
                    sequence=0,
                    reason="All anchored events are missing.",
                    kind="TRUNCATED_LOG",
                    checks=checks,
                    total_events=0,
                    verified_events=0,
                    anchor=self._anchor_summary(anchor, "MISMATCH"),
                )
            if require_anchor and not anchor:
                return self._failure(
                    VERIFICATION_INCOMPLETE,
                    "Audit log is empty and no trusted chain anchor is available; nothing was verified.",
                    event_id=None,
                    sequence=0,
                    reason="No events and no anchor.",
                    kind="EMPTY_LOG",
                    checks=checks,
                    total_events=0,
                    verified_events=0,
                    anchor=self._anchor_summary(anchor, "MISSING"),
                )
            return {
                "status": VERIFICATION_INCOMPLETE,
                "valid": False,
                "verified": False,
                "total_events": 0,
                "verified_events": 0,
                "expected_events": anchor["event_count"] if anchor else None,
                "first_id": None,
                "last_id": None,
                "head_hash": GENESIS_HASH,
                "message": "Audit log is empty; there is nothing to verify.",
                "error": None,
                "broken_at_id": None,
                "failure": {
                    "event_id": None,
                    "sequence": 0,
                    "reason": "No audit events are present.",
                    "kind": "EMPTY_LOG",
                },
                "verification_state": "EMPTY_LOG",
                "empty_log": True,
                "checks": checks,
                "anchor": self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
            }

        first_id = rows[0][0]
        expected_prev = GENESIS_HASH
        expected_id = first_id
        verified_events = 0
        previous_row_id: int | None = None

        for idx, r in enumerate(rows):
            row_id, ts, target, action, module, status, details_str, scope_entry, prev_hash, event_hash = r

            # Sequence continuity: ids must be strictly increasing by exactly 1.
            if previous_row_id is not None and row_id != expected_id:
                return self._failure(
                    CHAIN_GAP_DETECTED,
                    f"Deleted event detected: expected row ID {expected_id}, found {row_id}",
                    event_id=expected_id,
                    sequence=idx + 1,
                    reason=f"Expected event id {expected_id} is missing from the sequence.",
                    kind="MISSING_EVENT",
                    checks=checks,
                    total_events=len(rows),
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=rows[-1][0],
                    head_hash=expected_prev,
                    anchor=self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
                )
            if previous_row_id is not None and row_id <= previous_row_id:
                return self._failure(
                    CHAIN_GAP_DETECTED,
                    f"Event reordering detected at row {row_id}: ids are not strictly increasing",
                    event_id=row_id,
                    sequence=idx + 1,
                    reason="Event sequence is out of order or duplicated.",
                    kind="REORDERED_EVENT",
                    checks=checks,
                    total_events=len(rows),
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=rows[-1][0],
                    head_hash=expected_prev,
                    anchor=self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
                )
            expected_id = row_id + 1
            previous_row_id = row_id

            # Previous-hash linkage.
            if prev_hash != expected_prev:
                return self._failure(
                    TAMPER_DETECTED,
                    f"Broken chain link at row {row_id}: prev_hash does not match preceding event hash",
                    event_id=row_id,
                    sequence=idx + 1,
                    reason="previous_hash link mismatch.",
                    kind="BROKEN_LINK",
                    checks=checks,
                    total_events=len(rows),
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=rows[-1][0],
                    head_hash=expected_prev,
                    anchor=self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
                    extra={
                        "expected_prev_hash": expected_prev,
                        "actual_prev_hash": prev_hash,
                    },
                )

            # Recalculate the event hash from the canonical serialization.
            try:
                canonical_json = compute_canonical_event_json(
                    ts, target, action, module, status, details_str, scope_entry
                )
                recomputed_hash = compute_event_hash(canonical_json, prev_hash)
            except Exception as exc:
                return self._failure(
                    VERIFICATION_INCOMPLETE,
                    f"Could not recompute hash for event {row_id}: {exc}",
                    event_id=row_id,
                    sequence=idx + 1,
                    reason=f"Hash recomputation failed: {exc}",
                    kind="HASH_ERROR",
                    checks=checks,
                    total_events=len(rows),
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=rows[-1][0],
                    head_hash=expected_prev,
                    anchor=self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
                )
            if recomputed_hash != event_hash:
                return self._failure(
                    TAMPER_DETECTED,
                    f"Tampered event detected at row {row_id}: event_hash mismatch",
                    event_id=row_id,
                    sequence=idx + 1,
                    reason="event_hash does not match the canonical event payload.",
                    kind="MODIFIED_EVENT",
                    checks=checks,
                    total_events=len(rows),
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=rows[-1][0],
                    head_hash=expected_prev,
                    anchor=self._anchor_summary(anchor, "PRESENT" if anchor else "MISSING"),
                    extra={
                        "expected_event_hash": recomputed_hash,
                        "actual_event_hash": event_hash,
                    },
                )

            expected_prev = event_hash
            verified_events += 1

        checks.update(
            {
                "hashes": True,
                "previous_hash_links": True,
                "sequence_continuity": True,
                "canonical_serialization": True,
            }
        )
        head_hash = expected_prev
        last_id = rows[-1][0]
        total = len(rows)

        # Trusted anchor comparison (detects tail truncation / extension).
        anchor_summary = self._anchor_summary(anchor, "MISSING")
        if anchor and not compare_anchor:
            # Explicit operator reseal: internal chain is still fully checked,
            # but the old anchor is intentionally ignored, not silently rewritten.
            anchor_summary = self._anchor_summary(anchor, "SKIPPED")
        elif anchor:
            if anchor["head_hash"] == head_hash and anchor["last_id"] == last_id and anchor["event_count"] == total:
                checks["anchor"] = True
                anchor_summary = self._anchor_summary(anchor, "MATCH")
            elif anchor["event_count"] and (
                anchor["last_id"] != last_id or anchor["event_count"] != total
            ):
                return self._failure(
                    CHAIN_GAP_DETECTED,
                    (
                        f"Trusted anchor mismatch: anchor records {anchor['event_count']} events "
                        f"ending at id {anchor['last_id']}, log contains {total} events ending at id {last_id}."
                    ),
                    event_id=last_id + 1 if last_id >= anchor["last_id"] else anchor["last_id"],
                    sequence=min(total, anchor["event_count"]) + 1,
                    reason="Event count/id continuity diverges from the trusted anchor.",
                    kind="ANCHOR_GAP",
                    checks=checks,
                    total_events=total,
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=last_id,
                    head_hash=head_hash,
                    anchor=self._anchor_summary(anchor, "MISMATCH"),
                )
            else:
                return self._failure(
                    TAMPER_DETECTED,
                    "Trusted anchor mismatch: the chain head differs from the sealed head hash.",
                    event_id=last_id,
                    sequence=total,
                    reason="head_hash diverges from the trusted anchor.",
                    kind="ANCHOR_HASH_MISMATCH",
                    checks=checks,
                    total_events=total,
                    verified_events=verified_events,
                    first_id=first_id,
                    last_id=last_id,
                    head_hash=head_hash,
                    anchor=self._anchor_summary(anchor, "MISMATCH"),
                )
        elif require_anchor:
            return self._failure(
                VERIFICATION_INCOMPLETE,
                (
                    f"Internal hash chain is consistent for {total} events, but no trusted "
                    "chain anchor exists, so completeness/truncation cannot be verified."
                ),
                event_id=None,
                sequence=None,
                reason="Required trusted anchor is missing.",
                kind="MISSING_ANCHOR",
                checks=checks,
                total_events=total,
                verified_events=verified_events,
                first_id=first_id,
                last_id=last_id,
                head_hash=head_hash,
                anchor=self._anchor_summary(None, "MISSING"),
            )

        anchored = anchor_summary.get("status") == "MATCH"
        message = (
            f"All {total} events cryptographically verified without tampering and "
            "match the trusted chain anchor."
            if anchored
            else (
                f"All {total} events are internally consistent, but no trusted chain "
                "anchor exists, so truncation cannot be excluded."
            )
        )
        return {
            "status": INTEGRITY_VERIFIED,
            "valid": True,
            "verified": True,
            "verification_state": "ANCHORED" if anchored else "UNANCHORED",
            "anchored": anchored,
            "total_events": total,
            "verified_events": verified_events,
            "expected_events": anchor["event_count"] if anchor else None,
            "first_id": first_id,
            "last_id": last_id,
            "head_hash": head_hash,
            "message": message,
            "error": None,
            "broken_at_id": None,
            "failure": None,
            "checks": checks,
            "anchor": anchor_summary,
        }

    def seal_chain(self) -> dict[str, Any]:
        """Record the current verified head as the trusted anchor.

        Refuses to seal a chain that does not pass verification, and never
        rewrites event hashes. Re-sealing is an explicit operator action.
        """
        result = self.verify_chain(require_anchor=False, compare_anchor=False)
        if result.get("status") != INTEGRITY_VERIFIED:
            return {
                "sealed": False,
                "reason": "Chain did not pass verification; refusing to seal.",
                "verification": result,
            }
        sealed_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_chain_anchor (id, head_hash, last_id, event_count, sealed_at) "
                "VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET head_hash=excluded.head_hash, "
                "last_id=excluded.last_id, event_count=excluded.event_count, "
                "sealed_at=excluded.sealed_at",
                (
                    result["head_hash"],
                    result["last_id"],
                    result["total_events"],
                    sealed_at,
                ),
            )
        return {
            "sealed": True,
            "head_hash": result["head_hash"],
            "last_id": result["last_id"],
            "event_count": result["total_events"],
            "sealed_at": sealed_at,
        }

    def fetch(
        self,
        target: str | None = None,
        module: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Read back rows for inspection / reporting."""
        where, params = [], []
        if target:
            where.append("target = ?")
            params.append(target)
        if module:
            where.append("module = ?")
            params.append(module)
        sql = "SELECT id, timestamp, target, action, module, status, details, scope_entry, prev_hash, event_hash FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        cols = [
            "id",
            "timestamp",
            "target",
            "action",
            "module",
            "status",
            "details",
            "scope_entry",
            "prev_hash",
            "event_hash",
        ]
        out = []
        for r in rows:
            d = dict(zip(cols, r, strict=False))
            try:
                d["details"] = json.loads(d["details"])
            except (TypeError, ValueError):
                pass
            out.append(d)
        return out

    def get_entries(
        self,
        target: str | None = None,
        module: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Alias for fetch() for seamless compatibility with test suites and inspection tools."""
        return self.fetch(target=target, module=module, limit=limit)