"""REDLOOP Autonomous SOC Operations — Cross-Platform Detection Engineering Layer (Phase 9).

Provides:
1. Unified detection rule lifecycle & inventory (Native, Sigma, and Provider rules).
2. Rule validation, schema verification, and MITRE ATT&CK technique/tactic mapping.
3. Test harness executing positive and negative telemetry test cases.
4. Execution audit history, hit counting, and false-positive tracking.
5. ATT&CK coverage calculation (identifying covered techniques vs detection gaps).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from redloop.assessment.soc_events import UniversalSecurityEvent


class RuleSource(str, Enum):
    NATIVE = "NATIVE"
    SIGMA = "SIGMA"
    PROVIDER = "PROVIDER"


class RuleSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DetectionRuleTestCase:
    """Positive/Negative test case asserting rule detection accuracy."""
    case_id: str
    is_positive: bool  # True: must trigger alert; False: benign, must NOT trigger
    description: str
    telemetry_payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionRule:
    """Authoritative detection rule specification."""
    rule_id: str
    title: str
    description: str
    source: RuleSource
    version: str
    technique_id: str  # e.g. "T1059.001"
    tactic: str        # e.g. "Execution"
    severity: RuleSeverity
    confidence: float  # 0.0 to 1.0
    data_sources: list[str]  # e.g. ["process_creation", "powershell_logs"]
    enabled: bool = True
    author: str = "redloop_detection_eng"
    test_cases: list[DetectionRuleTestCase] = field(default_factory=list)
    hit_count: int = 0
    false_positive_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["severity"] = self.severity.value
        d["test_cases"] = [tc.to_dict() for tc in self.test_cases]
        return d


class DetectionEngineeringManager:
    """Manages the full lifecycle of cross-platform detection rules and coverage metrics."""

    _instance: Optional["DetectionEngineeringManager"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/detection_rules.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_rules()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "DetectionEngineeringManager":
        with cls._lock:
            if db_path is not None:
                p = Path(db_path)
                if cls._instance is None or cls._instance.db_path != p:
                    cls._instance = cls(db_path=p)
                    return cls._instance
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

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
                        CREATE TABLE IF NOT EXISTS detection_rules (
                            rule_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT NOT NULL,
                            source TEXT NOT NULL,
                            version TEXT NOT NULL,
                            technique_id TEXT NOT NULL,
                            tactic TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            confidence REAL NOT NULL,
                            data_sources_json TEXT NOT NULL,
                            enabled INTEGER NOT NULL DEFAULT 1,
                            author TEXT NOT NULL,
                            test_cases_json TEXT NOT NULL,
                            hit_count INTEGER NOT NULL DEFAULT 0,
                            false_positive_count INTEGER NOT NULL DEFAULT 0,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS detection_rule_executions (
                            exec_id TEXT PRIMARY KEY,
                            rule_id TEXT NOT NULL,
                            event_id TEXT NOT NULL,
                            triggered INTEGER NOT NULL,
                            matched_fields_json TEXT NOT NULL,
                            executed_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS detection_rule_audit_log (
                            audit_id TEXT PRIMARY KEY,
                            rule_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            details TEXT NOT NULL,
                            timestamp TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears rule inventory (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM detection_rules")
                    conn.execute("DELETE FROM detection_rule_executions")
                    conn.execute("DELETE FROM detection_rule_audit_log")
            finally:
                conn.close()
        self._seed_default_rules()

    def _seed_default_rules(self) -> None:
        """Seeds initial production-grade detection rules if inventory is empty."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT COUNT(*) FROM detection_rules")
                if cur.fetchone()[0] > 0:
                    return

                default_rules = [
                    DetectionRule(
                        rule_id="RL-DET-001",
                        title="Encoded PowerShell Execution via Command-Line",
                        description="Detects suspicious powershell invocation with encoded or hidden window parameters.",
                        source=RuleSource.NATIVE,
                        version="1.0.0",
                        technique_id="T1059.001",
                        tactic="Execution",
                        severity=RuleSeverity.HIGH,
                        confidence=0.85,
                        data_sources=["process_creation", "powershell_logs"],
                        test_cases=[
                            DetectionRuleTestCase(
                                case_id="tc-001-pos",
                                is_positive=True,
                                description="PowerShell encoded command execution",
                                telemetry_payload={"command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi..."},
                            ),
                            DetectionRuleTestCase(
                                case_id="tc-001-neg",
                                is_positive=False,
                                description="Normal powershell execution",
                                telemetry_payload={"command_line": "powershell.exe -NoProfile -Command Get-Process"},
                            ),
                        ],
                    ),
                    DetectionRule(
                        rule_id="RL-DET-002",
                        title="Credential Dumping via LSASS Memory Access",
                        description="Identifies unauthorized process handles opened against lsass.exe for credential exfiltration.",
                        source=RuleSource.SIGMA,
                        version="1.1.0",
                        technique_id="T1003.001",
                        tactic="Credential Access",
                        severity=RuleSeverity.CRITICAL,
                        confidence=0.92,
                        data_sources=["sysmon_event_10", "edr_memory_access"],
                        test_cases=[
                            DetectionRuleTestCase(
                                case_id="tc-002-pos",
                                is_positive=True,
                                description="Mimikatz procdump against lsass",
                                telemetry_payload={"command_line": "procdump.exe -ma lsass.exe lsass.dmp"},
                            ),
                            DetectionRuleTestCase(
                                case_id="tc-002-neg",
                                is_positive=False,
                                description="Legitimate svchost process activity",
                                telemetry_payload={"command_line": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted"},
                            ),
                        ],
                    ),
                    DetectionRule(
                        rule_id="RL-DET-003",
                        title="Remote Service Creation (PsExec Lateral Movement)",
                        description="Monitors service installation artifacts typical of lateral movement tooling.",
                        source=RuleSource.NATIVE,
                        version="1.0.0",
                        technique_id="T1543.003",
                        tactic="Privilege Escalation",
                        severity=RuleSeverity.HIGH,
                        confidence=0.88,
                        data_sources=["windows_event_7045", "security_event_4697"],
                    ),
                    DetectionRule(
                        rule_id="RL-DET-004",
                        title="DNS Tunneling and High-Entropy Exfiltration",
                        description="Flags anomaly in DNS query length and high-entropy subdomains typical of C2 beaconing.",
                        source=RuleSource.PROVIDER,
                        version="1.0.0",
                        technique_id="T1071.004",
                        tactic="Command and Control",
                        severity=RuleSeverity.MEDIUM,
                        confidence=0.80,
                        data_sources=["zeek_dns", "suricata_dns"],
                    ),
                ]

                with conn:
                    for r in default_rules:
                        self._save_rule_locked(r, conn)
            finally:
                conn.close()

    def _save_rule_locked(self, rule: DetectionRule, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO detection_rules
            (rule_id, title, description, source, version, technique_id, tactic, severity,
             confidence, data_sources_json, enabled, author, test_cases_json, hit_count,
             false_positive_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.rule_id,
                rule.title,
                rule.description,
                rule.source.value,
                rule.version,
                rule.technique_id,
                rule.tactic,
                rule.severity.value,
                rule.confidence,
                json.dumps(rule.data_sources),
                1 if rule.enabled else 0,
                rule.author,
                json.dumps([tc.to_dict() for tc in rule.test_cases]),
                rule.hit_count,
                rule.false_positive_count,
                rule.created_at,
                rule.updated_at,
            ),
        )

    def register_rule(self, rule: DetectionRule, actor: str = "detection_engineer") -> DetectionRule:
        """Validates and registers a new detection rule."""
        self.validate_rule(rule)
        with self._op_lock:
            conn = self._get_connection()
            try:
                now = datetime.now(timezone.utc).isoformat()
                rule.updated_at = now
                with conn:
                    self._save_rule_locked(rule, conn)
                    conn.execute(
                        """
                        INSERT INTO detection_rule_audit_log
                        (audit_id, rule_id, action, actor, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (f"aud-det-{uuid.uuid4().hex[:10]}", rule.rule_id, "RULE_REGISTERED", actor, f"Registered rule '{rule.title}'.", now),
                    )
            finally:
                conn.close()
        return rule

    def validate_rule(self, rule: DetectionRule) -> bool:
        """Enforces schema, confidence bounds, and ATT&CK mapping requirements."""
        if not rule.rule_id or not isinstance(rule.rule_id, str):
            raise ValueError("Rule ID must be a non-empty string.")
        if not rule.title or len(rule.title.strip()) < 5:
            raise ValueError("Rule title must contain at least 5 characters.")
        if not rule.technique_id or not rule.technique_id.startswith("T"):
            raise ValueError(f"Invalid MITRE ATT&CK technique '{rule.technique_id}'. Must start with 'T'.")
        if not (0.0 <= rule.confidence <= 1.0):
            raise ValueError(f"Confidence score {rule.confidence} must be between 0.0 and 1.0.")
        return True

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))
                r = cur.fetchone()
                if not r:
                    return None
                return self._row_to_rule(r)
            finally:
                conn.close()

    def list_rules(self, enabled_only: bool = False, technique_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                query = "SELECT * FROM detection_rules"
                clauses = []
                params = []
                if enabled_only:
                    clauses.append("enabled = 1")
                if technique_id:
                    clauses.append("technique_id = ?")
                    params.append(technique_id)
                if clauses:
                    query += " WHERE " + " AND ".join(clauses)
                query += " ORDER BY rule_id ASC"
                cur = conn.execute(query, params)
                return [self._row_to_rule(r).to_dict() for r in cur.fetchall()]
            finally:
                conn.close()

    def run_rule_test_harness(self, rule_id: str) -> dict[str, Any]:
        """Executes positive and negative test cases against a detection rule."""
        rule = self.get_rule(rule_id)
        if not rule:
            return {"error": f"Rule '{rule_id}' not found."}

        results = []
        passed_all = True

        for tc in rule.test_cases:
            payload = tc.telemetry_payload
            triggered = self._evaluate_rule_against_payload(rule, payload)

            test_passed = (triggered == tc.is_positive)
            if not test_passed:
                passed_all = False

            results.append({
                "case_id": tc.case_id,
                "description": tc.description,
                "is_positive_case": tc.is_positive,
                "triggered": triggered,
                "passed": test_passed,
            })

        return {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "all_tests_passed": passed_all,
            "cases_executed": len(results),
            "results": results,
        }

    def _evaluate_rule_against_payload(self, rule: DetectionRule, payload: dict[str, Any]) -> bool:
        """Deterministic evaluation of rule match criteria against telemetry."""
        cmd = str(payload.get("command_line", "")).lower()
        if rule.technique_id == "T1059.001":
            # Encoded powershell check
            return "-enc" in cmd or "-encodedcommand" in cmd
        elif rule.technique_id == "T1003.001":
            # LSASS dump check
            return "lsass" in cmd and ("procdump" in cmd or "mimikatz" in cmd or "comsvcs" in cmd)
        elif rule.technique_id == "T1543.003":
            return "psexec" in cmd or "sc.exe create" in cmd
        elif rule.technique_id == "T1071.004":
            return len(str(payload.get("dns_query", ""))) > 65
        return False

    def evaluate_event(self, event: UniversalSecurityEvent) -> list[dict[str, Any]]:
        """Evaluates all enabled detection rules against an ingested security event."""
        matches = []
        rules = self.list_rules(enabled_only=True)
        now = datetime.now(timezone.utc).isoformat()

        payload = {
            "command_line": event.command_line or "",
            "source_ip": event.source_ip or "",
            "dest_ip": event.dest_ip or "",
            "user": event.user or "",
            "host": event.host or "",
        }

        with self._op_lock:
            conn = self._get_connection()
            try:
                for r_dict in rules:
                    rule = self.get_rule(r_dict["rule_id"])
                    if not rule:
                        continue

                    triggered = self._evaluate_rule_against_payload(rule, payload)
                    if triggered:
                        exec_id = f"exec-{uuid.uuid4().hex[:10]}"
                        with conn:
                            conn.execute(
                                """
                                INSERT INTO detection_rule_executions
                                (exec_id, rule_id, event_id, triggered, matched_fields_json, executed_at)
                                VALUES (?, ?, ?, 1, ?, ?)
                                """,
                                (exec_id, rule.rule_id, event.event_id, json.dumps(payload), now),
                            )
                            conn.execute(
                                "UPDATE detection_rules SET hit_count = hit_count + 1 WHERE rule_id = ?",
                                (rule.rule_id,),
                            )
                        matches.append({
                            "rule_id": rule.rule_id,
                            "title": rule.title,
                            "technique_id": rule.technique_id,
                            "severity": rule.severity.value,
                            "confidence": rule.confidence,
                        })
            finally:
                conn.close()

        return matches

    def mark_false_positive(self, rule_id: str, actor: str = "analyst", reason: str = "") -> bool:
        """Records a confirmed false positive against a detection rule."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                now = datetime.now(timezone.utc).isoformat()
                with conn:
                    cur = conn.execute(
                        "UPDATE detection_rules SET false_positive_count = false_positive_count + 1 WHERE rule_id = ?",
                        (rule_id,),
                    )
                    conn.execute(
                        """
                        INSERT INTO detection_rule_audit_log
                        (audit_id, rule_id, action, actor, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (f"aud-fp-{uuid.uuid4().hex[:10]}", rule_id, "FALSE_POSITIVE_FLAGGED", actor, reason or "Flagged as benign false positive", now),
                    )
                    return cur.rowcount > 0
            finally:
                conn.close()

    def get_attack_coverage_matrix(self) -> dict[str, Any]:
        """Calculates MITRE ATT&CK technique coverage and identifies visibility gaps."""
        rules = self.list_rules(enabled_only=True)
        covered_techniques: dict[str, list[str]] = {}
        tactic_coverage: dict[str, int] = {}

        for r in rules:
            tech = r["technique_id"]
            tactic = r["tactic"]
            covered_techniques.setdefault(tech, []).append(r["rule_id"])
            tactic_coverage[tactic] = tactic_coverage.get(tactic, 0) + 1

        # Key core enterprise ATT&CK techniques monitored
        BENCHMARK_TECHNIQUES = {
            "T1059.001": "PowerShell Execution",
            "T1003.001": "LSASS Memory Dump",
            "T1543.003": "Windows Service",
            "T1071.004": "DNS C2 Tunneling",
            "T1078.002": "Domain Accounts",
            "T1190": "Exploit Public-Facing Application",
            "T1048": "Exfiltration Over Alternative Protocol",
            "T1053": "Scheduled Task",
        }

        gaps = [t for t in BENCHMARK_TECHNIQUES if t not in covered_techniques]

        coverage_ratio = round((len(covered_techniques) / len(BENCHMARK_TECHNIQUES) * 100.0), 1)

        return {
            "total_active_rules": len(rules),
            "covered_technique_count": len(covered_techniques),
            "covered_techniques_count": len(covered_techniques),
            "benchmark_technique_count": len(BENCHMARK_TECHNIQUES),
            "coverage_percentage": coverage_ratio,
            "coverage_ratio_percent": coverage_ratio,
            "covered_techniques": covered_techniques,
            "tactic_distribution": tactic_coverage,
            "identified_detection_gaps": [{"technique_id": g, "name": BENCHMARK_TECHNIQUES[g]} for g in gaps],
            "coverage_gaps": gaps,
        }

    def _row_to_rule(self, row: sqlite3.Row) -> DetectionRule:
        tc_raw = json.loads(row["test_cases_json"])
        tcs = [DetectionRuleTestCase(**tc) for tc in tc_raw]
        return DetectionRule(
            rule_id=row["rule_id"],
            title=row["title"],
            description=row["description"],
            source=RuleSource(row["source"]),
            version=row["version"],
            technique_id=row["technique_id"],
            tactic=row["tactic"],
            severity=RuleSeverity(row["severity"]),
            confidence=float(row["confidence"]),
            data_sources=json.loads(row["data_sources_json"]),
            enabled=bool(row["enabled"]),
            author=row["author"],
            test_cases=tcs,
            hit_count=row["hit_count"],
            false_positive_count=row["false_positive_count"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


DetectionEngineeringManager.get_engine = classmethod(lambda cls, db_path=None: cls.get_instance(db_path=db_path))
DetectionRuleEngine = DetectionEngineeringManager

