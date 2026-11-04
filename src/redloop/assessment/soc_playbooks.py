"""SOC Incident Response Playbooks Engine (Phase 5).

Provides 8 structured, actionable response playbooks:
1. PB-PHISH: Phishing Investigation & Triage
2. PB-CRED: Suspected Credential Compromise & Session Revocation
3. PB-BRUTE: Brute-Force Activity & Perimeter Containment
4. PB-PSHELL: Suspicious Obfuscated PowerShell Execution
5. PB-MALWARE: Malware Indicator Triage & Host Quarantine
6. PB-WEB: Web Attack (SQLi / Traversal / Web Shell) Remediation
7. PB-EXFIL: Potential Data Exfiltration & Channel Blocking
8. PB-OUTBOUND: Suspicious Outbound C2 Connection Disruption

Security Policy:
All containment and state-changing actions are recommendation-only or require
explicit per-action human approval (requires_approval=True). Never executes
destructive changes automatically without authorized approval audit.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class PlaybookStepStatus(str, Enum):
    PENDING = "PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"


@dataclass
class ApprovalCapability:
    """Cryptographic, single-use, expiring execution capability for high-risk containment actions.
    
    NOTE: Represents a local operator approval capability within the REDLOOP host environment;
    does not constitute cryptographically verified identity proof of an authenticated remote user.
    """
    capability_id: str
    token_hash: str
    playbook_id: str
    step_id: str
    action_command: str
    approver: str
    created_at: str
    expires_at: str
    provider_id: str = ""
    action_name: str = ""
    resource_id: str = ""
    case_id: Optional[str] = None
    requesting_actor: str = "operator"
    action_params_hash: str = ""
    consumed: bool = False
    consumed_at: Optional[str] = None
    nonce: str = ""
    token_secret: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "playbook_id": self.playbook_id,
            "step_id": self.step_id,
            "provider_id": self.provider_id,
            "action_name": self.action_name,
            "resource_id": self.resource_id,
            "case_id": self.case_id,
            "requesting_actor": self.requesting_actor,
            "action_command": self.action_command,
            "approver": self.approver,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "consumed": self.consumed,
            "consumed_at": self.consumed_at,
            "nonce": self.nonce,
            # token_secret is strictly redacted for audit and API safety
        }


class PlaybookApprovalStore:
    """Thread-safe, SQLite-backed store for cryptographic playbook execution capabilities."""

    _instance: Optional["PlaybookApprovalStore"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.Lock()
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = self._default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "PlaybookApprovalStore":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path=db_path)
            return cls._instance

    @staticmethod
    def _default_db_path() -> Path:
        try:
            from redloop.config import get_config
            cfg = get_config()
            if hasattr(cfg, "audit_db") and cfg.audit_db:
                return Path(cfg.audit_db)
        except Exception:
            pass
        return Path("data/audit.db")

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS playbook_approval_capabilities (
                            capability_id TEXT PRIMARY KEY,
                            token_hash TEXT UNIQUE NOT NULL,
                            playbook_id TEXT NOT NULL,
                            step_id TEXT NOT NULL,
                            action_command TEXT,
                            approver TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            expires_at TEXT NOT NULL,
                            consumed INTEGER NOT NULL DEFAULT 0,
                            consumed_at TEXT,
                            nonce TEXT NOT NULL,
                            provider_id TEXT DEFAULT '',
                            action_name TEXT DEFAULT '',
                            resource_id TEXT DEFAULT '',
                            case_id TEXT,
                            requesting_actor TEXT DEFAULT 'operator',
                            action_params_hash TEXT DEFAULT ''
                        )
                    """)
                    # Schema migration for existing database
                    cur = conn.execute("PRAGMA table_info(playbook_approval_capabilities)")
                    cols = [r["name"] for r in cur.fetchall()]
                    for col, defn in [
                        ("provider_id", "TEXT DEFAULT ''"),
                        ("action_name", "TEXT DEFAULT ''"),
                        ("resource_id", "TEXT DEFAULT ''"),
                        ("case_id", "TEXT"),
                        ("requesting_actor", "TEXT DEFAULT 'operator'"),
                        ("action_params_hash", "TEXT DEFAULT ''"),
                    ]:
                        if col not in cols:
                            conn.execute(f"ALTER TABLE playbook_approval_capabilities ADD COLUMN {col} {defn}")
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS playbook_audit_trail (
                            event_id TEXT PRIMARY KEY,
                            timestamp TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            capability_id TEXT,
                            playbook_id TEXT NOT NULL,
                            step_id TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            action_command TEXT,
                            status TEXT NOT NULL,
                            details TEXT
                        )
                    """)
            finally:
                conn.close()

    @staticmethod
    def _compute_params_hash(cmd: Optional[str], params: Optional[dict[str, Any]] = None) -> str:
        """Computes canonical SHA-256 hash over action command and action parameters."""
        import json
        payload = {"cmd": (cmd or "").strip(), "params": params or {}}
        canon = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    def issue_capability(
        self,
        playbook_id: str,
        step_id: str,
        action_command: Optional[str] = None,
        approver: str = "security_lead",
        ttl_minutes: int = 15,
        action_params: Optional[dict[str, Any]] = None,
        provider_id: str = "",
        action_name: str = "",
        resource_id: str = "",
        case_id: Optional[str] = None,
        requesting_actor: str = "operator",
    ) -> tuple[ApprovalCapability, str]:
        """Issues a one-time cryptographic execution capability token."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=ttl_minutes)
        capability_id = f"cap-{uuid.uuid4().hex[:12]}"
        nonce = uuid.uuid4().hex
        
        token_secret = f"rl-cap-{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(token_secret.encode("utf-8")).hexdigest()

        params_hash = self._compute_params_hash(action_command, action_params)
        cap = ApprovalCapability(
            capability_id=capability_id,
            token_hash=token_hash,
            playbook_id=playbook_id,
            step_id=step_id,
            action_command=action_command or "",
            action_params_hash=params_hash,
            approver=approver,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            provider_id=provider_id,
            action_name=action_name,
            resource_id=resource_id,
            case_id=case_id,
            requesting_actor=requesting_actor,
            consumed=False,
            consumed_at=None,
            nonce=nonce,
            token_secret=token_secret,
        )

        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO playbook_approval_capabilities
                        (capability_id, token_hash, playbook_id, step_id, action_command, approver, created_at, expires_at, consumed, consumed_at, nonce, provider_id, action_name, resource_id, case_id, requesting_actor, action_params_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cap.capability_id,
                            cap.token_hash,
                            cap.playbook_id,
                            cap.step_id,
                            cap.action_command,
                            cap.approver,
                            cap.created_at,
                            cap.expires_at,
                            cap.nonce,
                            cap.provider_id,
                            cap.action_name,
                            cap.resource_id,
                            cap.case_id,
                            cap.requesting_actor,
                            cap.action_params_hash,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO playbook_audit_trail
                        (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"aud-{uuid.uuid4().hex[:10]}",
                            cap.created_at,
                            "CAPABILITY_ISSUED",
                            cap.capability_id,
                            cap.playbook_id,
                            cap.step_id,
                            cap.approver,
                            cap.action_command,
                            "ISSUED",
                            f"Execution capability issued with 15-min TTL until {cap.expires_at}",
                        ),
                    )
            finally:
                conn.close()

        return cap, token_secret

    def validate_and_consume(
        self,
        playbook_id: str,
        step_id: str,
        token_secret: str,
        operator: str = "operator",
        expected_action_command: Optional[str] = None,
        expected_action_params: Optional[dict[str, Any]] = None,
        expected_provider_id: Optional[str] = None,
        expected_action_name: Optional[str] = None,
        expected_resource_id: Optional[str] = None,
        expected_case_id: Optional[str] = None,
    ) -> tuple[bool, str, Optional[dict[str, Any]]]:
        """Atomically validates and consumes the capability token with strict multi-attribute binding."""
        if not token_secret or not isinstance(token_secret, str):
            return False, "Missing or invalid authorization token.", None

        token_hash = hashlib.sha256(token_secret.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        "SELECT * FROM playbook_approval_capabilities WHERE token_hash = ?",
                        (token_hash,),
                    )
                    row = cur.fetchone()

                    if not row:
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                None,
                                playbook_id,
                                step_id,
                                operator,
                                None,
                                "REJECTED_UNKNOWN_TOKEN",
                                "Provided token does not match any known capability hash.",
                            ),
                        )
                        return False, "Execution rejected: Invalid or unrecognized capability authorization token hash.", None

                    cap_id = row["capability_id"]
                    bound_pb = row["playbook_id"]
                    bound_step = row["step_id"]
                    bound_cmd = row["action_command"]
                    consumed = bool(row["consumed"])
                    expires_str = row["expires_at"]
                    cols = row.keys()
                    bound_provider = row["provider_id"] if "provider_id" in cols else ""
                    bound_action = row["action_name"] if "action_name" in cols else ""
                    bound_resource = row["resource_id"] if "resource_id" in cols else ""
                    bound_case = row["case_id"] if "case_id" in cols else None
                    bound_params_hash = row["action_params_hash"] if "action_params_hash" in cols else ""

                    # 1. Check playbook and step binding
                    if bound_pb != playbook_id or bound_step != step_id:
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_BINDING_MISMATCH",
                                f"Capability token bound to {bound_pb}/{bound_step}, cannot execute {playbook_id}/{step_id}.",
                            ),
                        )
                        return (
                            False,
                            f"Execution rejected: Capability token is bound to playbook '{bound_pb}' step '{bound_step}', not '{playbook_id}'/'{step_id}'.",
                            None,
                        )

                    # 2. Check provider ID binding
                    if expected_provider_id and bound_provider and bound_provider.lower() != expected_provider_id.lower():
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_PROVIDER_MISMATCH",
                                f"Capability token bound to provider '{bound_provider}', cannot authorize provider '{expected_provider_id}'.",
                            ),
                        )
                        return (
                            False,
                            f"Execution rejected: Capability token was issued for provider '{bound_provider}', not '{expected_provider_id}'.",
                            None,
                        )

                    # 3. Check action name binding (prevent cross-action authorization)
                    if expected_action_name and bound_action and bound_action.lower() != expected_action_name.lower():
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_ACTION_MISMATCH",
                                f"Capability token bound to action '{bound_action}', cannot authorize action '{expected_action_name}'.",
                            ),
                        )
                        return (
                            False,
                            f"Execution rejected: Capability token was issued for action '{bound_action}', not '{expected_action_name}'.",
                            None,
                        )

                    # 4. Check resource identifier binding
                    if expected_resource_id and bound_resource and bound_resource.strip() != expected_resource_id.strip():
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_RESOURCE_MISMATCH",
                                f"Capability token bound to resource '{bound_resource}', cannot authorize resource '{expected_resource_id}'.",
                            ),
                        )
                        return (
                            False,
                            f"Execution rejected: Capability token was issued for resource '{bound_resource}', not '{expected_resource_id}'.",
                            None,
                        )

                    # 5. Check associated case ID binding
                    if expected_case_id and bound_case and bound_case.strip() != expected_case_id.strip():
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "EXECUTION_REJECTED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_CASE_MISMATCH",
                                f"Capability token bound to case '{bound_case}', cannot authorize case '{expected_case_id}'.",
                            ),
                        )
                        return (
                            False,
                            f"Execution rejected: Capability token was issued for case '{bound_case}', not '{expected_case_id}'.",
                            None,
                        )

                    # 6. Check replay / consumed
                    if consumed:
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "REPLAY_ATTEMPT_BLOCKED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_REPLAY",
                                f"Capability token was already consumed at {row['consumed_at']}.",
                            ),
                        )
                        return False, "Execution rejected: Capability token already consumed. Replay attempt blocked.", None

                    # 7. Check expiration
                    try:
                        exp_dt = datetime.fromisoformat(expires_str)
                        if now > exp_dt:
                            conn.execute(
                                """
                                INSERT INTO playbook_audit_trail
                                (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"aud-{uuid.uuid4().hex[:10]}",
                                    now_iso,
                                    "CAPABILITY_EXPIRED",
                                    cap_id,
                                    playbook_id,
                                    step_id,
                                    operator,
                                    bound_cmd,
                                    "REJECTED_EXPIRED",
                                    f"Capability token expired at {expires_str}.",
                                ),
                            )
                            return False, f"Execution rejected: Capability token expired at {expires_str}.", None
                    except Exception:
                        pass

                    # 8. Check parameter tampering
                    if expected_action_command is not None and bound_cmd:
                        if expected_action_command.strip() != bound_cmd.strip():
                            conn.execute(
                                """
                                INSERT INTO playbook_audit_trail
                                (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"aud-{uuid.uuid4().hex[:10]}",
                                    now_iso,
                                    "EXECUTION_REJECTED",
                                    cap_id,
                                    playbook_id,
                                    step_id,
                                    operator,
                                    expected_action_command,
                                    "REJECTED_PARAMS_ALTERED",
                                    f"Action command altered from approved '{bound_cmd}' to '{expected_action_command}'. Approval invalidated.",
                                ),
                            )
                            return False, "Execution rejected: Action command or parameters have been altered since approval was granted.", None

                    if bound_params_hash and expected_action_params is not None:
                        computed_h = self._compute_params_hash(expected_action_command or bound_cmd, expected_action_params)
                        if computed_h != bound_params_hash:
                            conn.execute(
                                """
                                INSERT INTO playbook_audit_trail
                                (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"aud-{uuid.uuid4().hex[:10]}",
                                    now_iso,
                                    "EXECUTION_REJECTED",
                                    cap_id,
                                    playbook_id,
                                    step_id,
                                    operator,
                                    bound_cmd,
                                    "REJECTED_PARAMS_HASH_MISMATCH",
                                    "Action parameters payload does not match approved capability hash.",
                                ),
                            )
                            return False, "Execution rejected: Action parameters do not match approved capability hash.", None

                    # 9. Atomically consume via CAS
                    cur_upd = conn.execute(
                        "UPDATE playbook_approval_capabilities SET consumed = 1, consumed_at = ? WHERE capability_id = ? AND consumed = 0",
                        (now_iso, cap_id),
                    )
                    if cur_upd.rowcount != 1:
                        conn.execute(
                            """
                            INSERT INTO playbook_audit_trail
                            (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"aud-{uuid.uuid4().hex[:10]}",
                                now_iso,
                                "REPLAY_ATTEMPT_BLOCKED",
                                cap_id,
                                playbook_id,
                                step_id,
                                operator,
                                bound_cmd,
                                "REJECTED_CONCURRENT_CONSUMPTION",
                                "Capability token was concurrently consumed by another execution.",
                            ),
                        )
                        return False, "Execution rejected: Capability token concurrently consumed. Replay attempt blocked.", None

                    conn.execute(
                        """
                        INSERT INTO playbook_audit_trail
                        (event_id, timestamp, event_type, capability_id, playbook_id, step_id, actor, action_command, status, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"aud-{uuid.uuid4().hex[:10]}",
                            now_iso,
                            "STEP_EXECUTED",
                            cap_id,
                            playbook_id,
                            step_id,
                            operator,
                            bound_cmd,
                            "EXECUTED",
                            f"Capability token atomically consumed by {operator}.",
                        ),
                    )

                    cap_info = {
                        "capability_id": cap_id,
                        "playbook_id": bound_pb,
                        "step_id": bound_step,
                        "provider_id": bound_provider,
                        "action_name": bound_action,
                        "resource_id": bound_resource,
                        "case_id": bound_case,
                        "action_command": bound_cmd,
                        "approver": row["approver"],
                        "consumed_at": now_iso,
                    }
                    return True, "Authorized capability validated and consumed.", cap_info
            finally:
                conn.close()

    def reset(self) -> None:
        """Wipes capabilities table for test isolation."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM playbook_approval_capabilities")
                    conn.execute("DELETE FROM playbook_audit_trail")
            finally:
                conn.close()


@dataclass
class PlaybookStep:
    step_id: str
    stage: int
    name: str
    description: str
    decision_point: str
    recommended_action: str
    action_command: str | None = None
    requires_approval: bool = True
    approval_status: PlaybookStepStatus = PlaybookStepStatus.PENDING
    approver: str | None = None
    approval_timestamp: str | None = None
    execution_result: str | None = None
    containment_flag: bool = False
    capability_id: str | None = None
    capability_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["approval_status"] = self.approval_status.value if hasattr(self.approval_status, "value") else str(self.approval_status)
        return d


@dataclass
class ResponsePlaybook:
    playbook_id: str
    title: str
    category: str
    trigger_conditions: list[str]
    required_evidence: list[str]
    steps: list[PlaybookStep]
    containment_guidance: list[str]
    recovery_steps: list[str]
    verification_steps: list[str]
    rollback_plan: str
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "title": self.title,
            "category": self.category,
            "trigger_conditions": self.trigger_conditions,
            "required_evidence": self.required_evidence,
            "steps": [s.to_dict() for s in self.steps],
            "containment_guidance": self.containment_guidance,
            "recovery_steps": self.recovery_steps,
            "verification_steps": self.verification_steps,
            "rollback_plan": self.rollback_plan,
            "audit_events": self.audit_events,
        }


class SOCPlaybookEngine:
    """Manages and executes SOC incident response playbooks with explicit human approval enforcement."""

    _PLAYBOOKS: dict[str, ResponsePlaybook] = {}

    @classmethod
    def _initialize_catalog(cls) -> None:
        if cls._PLAYBOOKS:
            return

        # 1. PB-CRED: Suspected Credential Compromise
        cls._PLAYBOOKS["PB-CRED"] = ResponsePlaybook(
            playbook_id="PB-CRED",
            title="Suspected Credential Compromise & Session Revocation",
            category="Identity & Access",
            trigger_conditions=[
                "Successful authentication following 3+ failed logins",
                "Logon from anomalous geographical location or Tor exit node",
                "Credential exposure detected in breach repository",
            ],
            required_evidence=[
                "Authentication logs (/var/log/auth.log or Event ID 4624/4625)",
                "Source IP address and User-Agent telemetry",
                "Account username and role privileges",
            ],
            steps=[
                PlaybookStep(
                    step_id="step-cred-1",
                    stage=1,
                    name="Triage & Session Verification",
                    description="Inspect authentication logs to confirm whether logon source IP is foreign or unauthorized.",
                    decision_point="Is the logon origin an authorized corporate subnet/VPN?",
                    recommended_action="If IP is anomalous, flag account for immediate containment.",
                    requires_approval=False,
                    approval_status=PlaybookStepStatus.EXECUTED,
                ),
                PlaybookStep(
                    step_id="step-cred-2",
                    stage=2,
                    name="Account Session Invalidation & Temporary Lockout",
                    description="Revoke active OAuth/Kerberos refresh tokens and temporarily disable account password.",
                    decision_point="Confirm account containment to prevent unauthorized lateral movement.",
                    recommended_action="Execute directory lockout command via administrative CLI.",
                    action_command="sudo passwd -l <username> && sudo pkill -u <username>",
                    requires_approval=True,
                    containment_flag=True,
                ),
                PlaybookStep(
                    step_id="step-cred-3",
                    stage=3,
                    name="Forced Password Reset & MFA Enrollment",
                    description="Trigger mandatory password rotation and re-verify MFA authenticator binding.",
                    decision_point="Has the user confirmed identity out-of-band?",
                    recommended_action="Issue single-use temporary password and force rotation on next logon.",
                    requires_approval=True,
                ),
            ],
            containment_guidance=[
                "Disable active user sessions across all SaaS and internal bastions.",
                "Block malicious source IP address on perimeter edge firewall.",
            ],
            recovery_steps=[
                "Verify no persistence mechanisms (SSH authorized_keys, scheduled tasks) were added during compromised session.",
                "Re-enable account upon verified user password rotation.",
            ],
            verification_steps=[
                "Confirm previous session tokens return 401 Unauthorized.",
                "Verify subsequent logon attempts from malicious IP fail.",
            ],
            rollback_plan="sudo passwd -u <username> (Unlocks account if confirmed false alarm)",
        )

        # 2. PB-BRUTE: Authentication Brute-Force Containment
        cls._PLAYBOOKS["PB-BRUTE"] = ResponsePlaybook(
            playbook_id="PB-BRUTE",
            title="Authentication Brute-Force Perimeter Containment",
            category="Network & Authentication",
            trigger_conditions=["5+ failed logins from single IP within 5 minutes"],
            required_evidence=["Firewall or SSH authentication logs", "Attacker source IP"],
            steps=[
                PlaybookStep(
                    step_id="step-brute-1",
                    stage=1,
                    name="Source Reputation & Scope Check",
                    description="Check source IP against internal subnets and WHOIS reputation.",
                    decision_point="Is the source IP an internal scanner or external attacker?",
                    recommended_action="If external and malicious, generate perimeter drop rule.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-brute-2",
                    stage=2,
                    name="Perimeter IP Firewall Blacklist",
                    description="Deploy temporary firewall drop rule restricting attacker source IP.",
                    decision_point="Approve perimeter drop rule for attacker source IP.",
                    recommended_action="Execute iptables or host firewall block.",
                    action_command="sudo iptables -I INPUT -s <source_ip> -j DROP",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Add attacker IP to Fail2ban or edge firewall blocklist for 24 hours."],
            recovery_steps=["Review SSH configuration to enforce publickey-only auth."],
            verification_steps=["Verify packets from source IP are dropped at ingress."],
            rollback_plan="sudo iptables -D INPUT -s <source_ip> -j DROP",
        )

        # 3. PB-PSHELL: Suspicious Obfuscated PowerShell Execution
        cls._PLAYBOOKS["PB-PSHELL"] = ResponsePlaybook(
            playbook_id="PB-PSHELL",
            title="Suspicious Obfuscated PowerShell & Script Containment",
            category="Endpoint & Process",
            trigger_conditions=["PowerShell launched with -enc or hidden window parameters"],
            required_evidence=["Sysmon Event ID 1", "Full CommandLine string", "Process GUID"],
            steps=[
                PlaybookStep(
                    step_id="step-ps-1",
                    stage=1,
                    name="Payload Decoding & Deobfuscation",
                    description="Decode Base64 Unicode string to reveal actual script operations.",
                    decision_point="Does decoded payload invoke network downloads (DownloadString, IEX)?",
                    recommended_action="Identify dropped files and target C2 IP addresses.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-ps-2",
                    stage=2,
                    name="Host Process Tree Termination",
                    description="Kill active malicious PowerShell process and child processes.",
                    decision_point="Approve termination of PID <process_id>.",
                    recommended_action="Execute process tree termination.",
                    action_command="Stop-Process -Id <process_id> -Force",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Isolate affected workstation from internal VLAN via switch ACL or EDR."],
            recovery_steps=["Scan host with offline AV/antimalware; inspect registry Run keys."],
            verification_steps=["Confirm process PID is no longer present in task list."],
            rollback_plan="Restart benign service if process was misidentified.",
        )

        # 4. PB-WEB: Web Application Attack (SQLi / Traversal / Web Shell)
        cls._PLAYBOOKS["PB-WEB"] = ResponsePlaybook(
            playbook_id="PB-WEB",
            title="Web Application Attack & Web Shell Neutralization",
            category="Web Application",
            trigger_conditions=["SQL injection or directory traversal attack detected in web logs"],
            required_evidence=["Nginx/Apache access log", "Request URI and POST body", "HTTP response status code"],
            steps=[
                PlaybookStep(
                    step_id="step-web-1",
                    stage=1,
                    name="HTTP Response Analysis",
                    description="Check whether target web server returned 200 OK or 403/404/500.",
                    decision_point="Did server execute payload successfully or return error?",
                    recommended_action="If 200 OK with anomalous response size, inspect web document root for created files.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-web-2",
                    stage=2,
                    name="WAF Rule Deployment or URL Path Blocking",
                    description="Inject modsecurity or Nginx location deny directive blocking malicious pattern.",
                    decision_point="Approve web server config snippet reload.",
                    recommended_action="Block URI path pattern at reverse proxy.",
                    action_command="echo 'deny <source_ip>;' >> /etc/nginx/conf.d/blocklist.conf && nginx -s reload",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Quarantine newly created files in document root created in the last 1 hour."],
            recovery_steps=["Apply software patch for vulnerable endpoint parameter."],
            verification_steps=["Re-test endpoint with harmless probe to verify 403 Forbidden."],
            rollback_plan="sed -i '/<source_ip>/d' /etc/nginx/conf.d/blocklist.conf && nginx -s reload",
        )

        # 5. PB-MALWARE: Malware Indicator Triage & Host Quarantine
        cls._PLAYBOOKS["PB-MALWARE"] = ResponsePlaybook(
            playbook_id="PB-MALWARE",
            title="Malware Indicator Triage & Endpoint Quarantine",
            category="Endpoint Threat",
            trigger_conditions=["Known malicious SHA-256 hash match"],
            required_evidence=["File path", "File hash", "Sysmon Event ID 11 or AV detection alert"],
            steps=[
                PlaybookStep(
                    step_id="step-mal-1",
                    stage=1,
                    name="Threat Intelligence Correlation",
                    description="Query VirusTotal/NVD for known malware family attribution.",
                    decision_point="Is the hash verified malicious across multiple vendors?",
                    recommended_action="If verified, immediately quarantine host and file.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-mal-2",
                    stage=2,
                    name="File Quarantine & Network Isolation",
                    description="Move file to quarantine directory and isolate host network interface.",
                    decision_point="Approve moving file to /var/quarantine and isolating network interface.",
                    recommended_action="Execute quarantine command.",
                    action_command="sudo mv <file_path> /var/quarantine/<file_hash>.bak",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Isolate endpoint to prevent worm lateral propagation."],
            recovery_steps=["Restore endpoint from clean golden image snapshot."],
            verification_steps=["Verify file is removed from original path and cannot execute."],
            rollback_plan="sudo mv /var/quarantine/<file_hash>.bak <file_path>",
        )

        # 6. PB-PHISH: Phishing Investigation
        cls._PLAYBOOKS["PB-PHISH"] = ResponsePlaybook(
            playbook_id="PB-PHISH",
            title="Phishing Investigation & Mailbox Remediation",
            category="Email Security",
            trigger_conditions=["Inbound email with failed SPF/DKIM and executable/ISO attachment"],
            required_evidence=["EML headers", "Authentication-Results", "Attachment hash", "Sender IP"],
            steps=[
                PlaybookStep(
                    step_id="step-phish-1",
                    stage=1,
                    name="Header & Attachment Analysis",
                    description="Inspect SPF/DKIM verification and scan attachment hashes.",
                    decision_point="Are sender authentication checks failed and attachments high-risk?",
                    recommended_action="Extract embedded URLs and query domain age and reputation.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-phish-2",
                    stage=2,
                    name="Mailbox Purge & Sender Domain Blacklist",
                    description="Purge phishing email from all recipient inboxes and block sender domain.",
                    decision_point="Approve enterprise-wide mailbox purge of Message-ID <msg_id>.",
                    recommended_action="Execute mailbox purge via mail gateway API.",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Block sender domain and IP at mail gateway."],
            recovery_steps=["Notify affected users who received message; check for credential submission."],
            verification_steps=["Confirm message is purged from Exchange/IMAP mailboxes."],
            rollback_plan="Restore message from mail quarantine archive.",
        )

        # 7. PB-OUTBOUND: Suspicious Outbound C2 Connection Disruption
        cls._PLAYBOOKS["PB-OUTBOUND"] = ResponsePlaybook(
            playbook_id="PB-OUTBOUND",
            title="Suspicious Outbound C2 Connection Disruption",
            category="Network Security",
            trigger_conditions=["Outbound connection to known C2 IP or DNS tunneling domain"],
            required_evidence=["Netflow or Sysmon Event ID 3", "Destination IP/Port", "Process ID"],
            steps=[
                PlaybookStep(
                    step_id="step-out-1",
                    stage=1,
                    name="Connection Triage & Socket Inspection",
                    description="Identify process ID maintaining active TCP socket to destination IP.",
                    decision_point="Is the connection benign software update or unauthorized C2?",
                    recommended_action="If unauthorized, terminate socket and block destination IP.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-out-2",
                    stage=2,
                    name="Outbound Firewall Null-Route",
                    description="Deploy null-route (blackhole) or firewall block for destination C2 IP.",
                    decision_point="Approve route nullification for <destination_ip>.",
                    recommended_action="Execute route blackhole command.",
                    action_command="sudo ip route add blackhole <destination_ip>",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Null-route C2 IP at router/firewall level."],
            recovery_steps=["Inspect internal host for installed rootkit or backdoor."],
            verification_steps=["Verify TCP SYN packets to destination IP are dropped immediately."],
            rollback_plan="sudo ip route del blackhole <destination_ip>",
        )

        # 8. PB-EXFIL: Potential Data Exfiltration Investigation
        cls._PLAYBOOKS["PB-EXFIL"] = ResponsePlaybook(
            playbook_id="PB-EXFIL",
            title="Potential Data Exfiltration & Channel Blocking",
            category="Data Protection",
            trigger_conditions=["Unusual outbound data transfer volume or cloud upload"],
            required_evidence=["Netflow byte counters", "Source host", "Destination cloud endpoint"],
            steps=[
                PlaybookStep(
                    step_id="step-ex-1",
                    stage=1,
                    name="Bandwidth & Data Volume Verification",
                    description="Verify byte count transmitted and identify local file handles.",
                    decision_point="Did data transfer exceed authorized threshold?",
                    recommended_action="Identify sensitive data accessed prior to transfer.",
                    requires_approval=False,
                ),
                PlaybookStep(
                    step_id="step-ex-2",
                    stage=2,
                    name="Egress Port / Domain Firewall Block",
                    description="Enforce egress filtering blocking file sharing or storage endpoint.",
                    decision_point="Approve blocking egress traffic to destination endpoint.",
                    recommended_action="Deploy egress firewall block rule.",
                    requires_approval=True,
                    containment_flag=True,
                ),
            ],
            containment_guidance=["Revoke user access to sensitive file shares pending forensic audit."],
            recovery_steps=["Assess regulatory disclosure requirements under GDPR/HIPAA if PII was accessed."],
            verification_steps=["Confirm transfer terminated and egress channel is inaccessible."],
            rollback_plan="Remove egress block rule once investigation completes.",
        )

    @classmethod
    def _reset_playbooks(cls) -> None:
        """Resets playbooks catalog to fresh unapproved state for testing."""
        cls._PLAYBOOKS.clear()
        cls._initialize_catalog()
        try:
            PlaybookApprovalStore.get_instance().reset()
        except Exception:
            pass

    @classmethod
    def list_playbooks(cls) -> list[dict[str, Any]]:
        cls._initialize_catalog()
        return [p.to_dict() for p in cls._PLAYBOOKS.values()]

    @classmethod
    def get_playbook(cls, playbook_id: str) -> ResponsePlaybook | None:
        cls._initialize_catalog()
        return cls._PLAYBOOKS.get(playbook_id)

    @classmethod
    def approve_step(
        cls,
        playbook_id: str,
        step_id: str,
        approver: str = "security_lead",
        approved: bool = True,
    ) -> dict[str, Any]:
        """Applies explicit human approval/rejection to a containment response step."""
        pb = cls.get_playbook(playbook_id)
        if not pb:
            return {"success": False, "error": f"Playbook '{playbook_id}' not found."}

        target_step: PlaybookStep | None = None
        for s in pb.steps:
            if s.step_id == step_id:
                target_step = s
                break

        if not target_step:
            return {"success": False, "error": f"Step '{step_id}' not found in playbook '{playbook_id}'."}

        # Replay prevention: reject duplicate approval if already approved
        if target_step.approval_status == PlaybookStepStatus.APPROVED and approved is True:
            return {
                "success": False,
                "error": f"Step '{step_id}' has already been resolved with status '{target_step.approval_status.value}'. Replay attempt rejected.",
            }
        if target_step.approval_status == PlaybookStepStatus.EXECUTED:
            return {
                "success": False,
                "error": f"Step '{step_id}' has already been executed. Cannot modify approval.",
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        target_step.approver = approver
        target_step.approval_timestamp = now_iso

        cap_token = None
        cap_id = None
        expires_at = None

        if approved:
            target_step.approval_status = PlaybookStepStatus.APPROVED
            # Issue cryptographic one-time execution capability token
            store = PlaybookApprovalStore.get_instance()
            cap, cap_token = store.issue_capability(
                playbook_id=playbook_id,
                step_id=step_id,
                action_command=target_step.action_command,
                approver=approver,
            )
            cap_id = cap.capability_id
            expires_at = cap.expires_at
            target_step.capability_id = cap_id
            target_step.capability_token = cap_token
            target_step.execution_result = (
                f"Action approved by {approver} at {now_iso}. "
                f"Cryptographic capability issued ({cap_id}). Ready for authorized execution."
            )
        else:
            target_step.approval_status = PlaybookStepStatus.REJECTED
            target_step.execution_result = f"Action explicitly rejected by {approver} at {now_iso}."

        audit_entry = {
            "timestamp": now_iso,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "approver": approver,
            "approved": approved,
            "action_command": target_step.action_command,
            "capability_id": cap_id,
        }
        pb.audit_events.append(audit_entry)

        res: dict[str, Any] = {
            "success": True,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "status": target_step.approval_status.value,
            "audit_entry": audit_entry,
        }
        if approved and cap_token:
            res["capability_id"] = cap_id
            res["capability_token"] = cap_token
            res["auth_token"] = cap_token  # Backward-compatible alias
            res["expires_at"] = expires_at

        return res

    @classmethod
    def execute_step(
        cls,
        playbook_id: str,
        step_id: str,
        auth_token: str | None = None,
        operator: str = "operator",
        action_command: Optional[str] = None,
        action_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Executes an approved containment step. Enforces human authorization and capability token verification."""
        pb = cls.get_playbook(playbook_id)
        if not pb:
            return {"success": False, "error": f"Playbook '{playbook_id}' not found."}

        target_step: PlaybookStep | None = None
        for s in pb.steps:
            if s.step_id == step_id:
                target_step = s
                break

        if not target_step:
            return {"success": False, "error": f"Step '{step_id}' not found in playbook '{playbook_id}'."}

        if target_step.approval_status == PlaybookStepStatus.EXECUTED:
            store = PlaybookApprovalStore.get_instance()
            store.validate_and_consume(playbook_id, step_id, auth_token or "", operator)
            return {
                "success": False,
                "error": "Execution rejected: Step has already been executed and capability token already consumed. Replay attempt blocked.",
            }

        # Enforce prerequisite approval
        if target_step.requires_approval and target_step.approval_status != PlaybookStepStatus.APPROVED:
            return {
                "success": False,
                "error": (
                    f"Execution rejected: Step '{step_id}' requires explicit human approval before execution. "
                    f"Current status: {target_step.approval_status.value}"
                ),
            }

        # Check authorization capability token
        if not auth_token:
            return {
                "success": False,
                "error": "Execution rejected: Missing authorization token.",
            }

        # If action_command was explicitly provided, verify it against target step
        effective_cmd = action_command if action_command is not None else target_step.action_command

        store = PlaybookApprovalStore.get_instance()
        valid, msg, cap_info = store.validate_and_consume(
            playbook_id=playbook_id,
            step_id=step_id,
            token_secret=auth_token,
            operator=operator,
            expected_action_command=effective_cmd,
            expected_action_params=action_params,
        )

        if not valid:
            return {
                "success": False,
                "error": f"Execution rejected: {msg}",
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        target_step.approval_status = PlaybookStepStatus.EXECUTED
        used_cap = cap_info["capability_id"] if cap_info else "unknown"
        target_step.execution_result = f"Action successfully executed under capability {used_cap} by {operator} at {now_iso}."

        return {
            "success": True,
            "playbook_id": playbook_id,
            "step_id": step_id,
            "capability_id": used_cap,
            "status": target_step.approval_status.value,
            "execution_result": target_step.execution_result,
        }
