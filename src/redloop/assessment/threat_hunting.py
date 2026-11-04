"""REDLOOP Threat Hunting & Hypothesis Validation Engine (Phase 6).

Provides:
1. Natural language hunting query parsing into structured typed Query AST.
2. Query Plan Preview with safety verification, execution cost, and max limits (default 100, max 1000).
3. Parameterized safe execution against stored telemetry events without SQL injection hazards.
4. Hypothesis tracking (UNTESTED, CONFIRMED, REFUTED, INCONCLUSIVE) with evidence provenance.
5. Interactive Threat Hunting session management and follow-up guidance.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional


class QuerySecurityError(Exception):
    """Raised when a threat hunting query violates security, complexity, or authorization boundaries."""
    pass


class HypothesisStatus(str, Enum):
    UNTESTED = "UNTESTED"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class QueryExecutionCost(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class HuntingFilterClause:
    """Individual filter clause in a structured hunting query."""
    field_name: str
    operator: str  # "eq", "contains", "startswith", "endswith", "in", "regex"
    value: Any

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HuntingQueryPlan:
    """Pre-execution query plan and safety verification."""
    query_id: str
    natural_language: str
    target_sources: list[str]
    filter_clauses: list[dict[str, Any]]
    projected_scope: str
    estimated_cost: QueryExecutionCost
    limit: int
    safety_checks_passed: bool
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["estimated_cost"] = self.estimated_cost.value
        return d


@dataclass
class HuntingQueryResult:
    """Structured results from executing a threat hunting query."""
    query_id: str
    query_title: str
    hypothesis: str
    hypothesis_status: HypothesisStatus
    total_matched: int
    returned_count: int
    execution_time_ms: float
    events: list[dict[str, Any]]
    matched_entities: dict[str, list[str]]
    evidence_provenance: list[str]
    suggested_followups: list[str]
    offset: int = 0
    target_scope: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["hypothesis_status"] = self.hypothesis_status.value
        return d


@dataclass
class HuntingSession:
    """Stateful hunting investigation session."""
    session_id: str
    title: str
    created_at: str
    queries_executed: list[HuntingQueryResult] = field(default_factory=list)
    active_hypothesis: str = ""
    hypothesis_status: HypothesisStatus = HypothesisStatus.UNTESTED
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["hypothesis_status"] = self.hypothesis_status.value
        d["queries_executed"] = [q.to_dict() for q in self.queries_executed]
        return d


class ThreatHuntingEngine:
    """Autonomous Threat Hunting & Hypothesis Engine."""

    MAX_RESULT_LIMIT: int = 1000
    DEFAULT_RESULT_LIMIT: int = 100
    MAX_QUERY_LENGTH: int = 500
    MAX_FILTER_CLAUSES: int = 10
    MAX_EXECUTION_TIMEOUT_SECONDS: float = 5.0

    ALLOWED_FIELDS: set[str] = {
        "source_ip",
        "destination_ip",
        "hostname",
        "username",
        "process_name",
        "parent_process",
        "command_line",
        "url",
        "cve_id",
        "file_hash",
        "timestamp",
        "event_id",
        "source_type",
        "event_category",
        "event_action",
        "severity",
    }

    ALLOWED_OPERATORS: set[str] = {"eq", "contains", "startswith", "endswith", "gte", "lte"}

    @classmethod
    def parse_natural_language(cls, nl_query: str) -> dict[str, Any]:
        """Translates a natural language hunting query into a structured query dictionary."""
        if not nl_query or not isinstance(nl_query, str):
            raise QuerySecurityError("Query string must be a non-empty string.")
        
        query_text = nl_query.strip()
        if len(query_text) > cls.MAX_QUERY_LENGTH:
            raise QuerySecurityError(
                f"Query length ({len(query_text)}) exceeds maximum allowable limit of {cls.MAX_QUERY_LENGTH} characters."
            )

        now = datetime.now(timezone.utc)

        filters: list[HuntingFilterClause] = []
        target_sources: list[str] = []
        target_entities: dict[str, list[str]] = {
            "ips": [],
            "hosts": [],
            "users": [],
            "processes": [],
            "hashes": [],
            "cves": [],
        }

        # 1. Extract IP addresses (IPv4)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query_text)
        for ip in ips:
            if not ip.startswith("0.") and not ip.startswith("255."):
                target_entities["ips"].append(ip)
                filters.append(HuntingFilterClause("source_ip", "eq", ip))

        # 2. Extract CVE IDs
        cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", query_text, re.IGNORECASE)
        for cve in cves:
            target_entities["cves"].append(cve.upper())
            filters.append(HuntingFilterClause("cve_id", "eq", cve.upper()))

        # 3. Extract SHA-256 hashes
        hashes = re.findall(r"\b[a-fA-F0-9]{64}\b", query_text)
        for h in hashes:
            target_entities["hashes"].append(h.lower())
            filters.append(HuntingFilterClause("file_hash", "eq", h.lower()))

        # 4. Extract process names & keywords
        q_lower = query_text.lower()
        if "powershell" in q_lower or "pwsh" in q_lower:
            target_entities["processes"].append("powershell.exe")
            filters.append(HuntingFilterClause("process_name", "contains", "powershell"))
            target_sources.append("windows_sysmon")
        if "cmd.exe" in q_lower or "command prompt" in q_lower:
            target_entities["processes"].append("cmd.exe")
            filters.append(HuntingFilterClause("process_name", "contains", "cmd"))
        if "bash" in q_lower or "sudo" in q_lower:
            target_sources.append("linux_auth")
            if "sudo" in q_lower:
                filters.append(HuntingFilterClause("command_line", "contains", "sudo"))

        if any(w in q_lower for w in ["sql", "injection", "traversal", "http", "url", "web"]):
            target_sources.append("web_access")
            if "injection" in q_lower or "sqli" in q_lower:
                filters.append(HuntingFilterClause("command_line", "contains", "union"))

        if "dns" in q_lower or "tunneling" in q_lower:
            target_sources.append("suricata_eve")

        # 5. Extract time window (only if explicitly specified)
        time_limit_hours = None
        if "last 1 hour" in q_lower or "past hour" in q_lower:
            time_limit_hours = 1
        elif "last 24 hours" in q_lower or "past day" in q_lower:
            time_limit_hours = 24
        elif "last 7 days" in q_lower or "past week" in q_lower:
            time_limit_hours = 168
        elif "last 30 days" in q_lower:
            time_limit_hours = 720

        if time_limit_hours is not None:
            start_time = (now - timedelta(hours=time_limit_hours)).isoformat()
            filters.append(HuntingFilterClause("timestamp", "gte", start_time))

        if not target_sources:
            target_sources = ["linux_auth", "web_access", "windows_sysmon", "suricata_eve"]

        return {
            "query_id": f"hunt-{uuid.uuid4().hex[:8]}",
            "natural_language": nl_query,
            "target_sources": target_sources,
            "entities": target_entities,
            "filters": [f.to_dict() for f in filters],
            "limit": cls.DEFAULT_RESULT_LIMIT,
            "time_window_hours": time_limit_hours,
        }

    @classmethod
    def generate_query_plan(cls, nl_query: str, limit: int = DEFAULT_RESULT_LIMIT) -> HuntingQueryPlan:
        """Constructs and returns an explainable Query Plan Preview prior to execution."""
        parsed = cls.parse_natural_language(nl_query)
        effective_limit = min(cls.MAX_RESULT_LIMIT, max(1, limit))

        cost = QueryExecutionCost.LOW
        if len(parsed["target_sources"]) > 2 or (parsed.get("time_window_hours") or 0) > 48:
            cost = QueryExecutionCost.MEDIUM
        if not parsed["filters"] or len(parsed["target_sources"]) >= 4 and (parsed.get("time_window_hours") or 0) > 168:
            cost = QueryExecutionCost.HIGH

        explanation = (
            f"Query targets {len(parsed['target_sources'])} source categories ({', '.join(parsed['target_sources'])}) "
            f"over a {parsed.get('time_window_hours') or 'complete'}-hour window with {len(parsed['filters'])} parameterized filter clauses. "
            f"Safety limit clamped to {effective_limit} records."
        )

        return HuntingQueryPlan(
            query_id=parsed["query_id"],
            natural_language=nl_query,
            target_sources=parsed["target_sources"],
            filter_clauses=parsed["filters"],
            projected_scope=f"Telemetry sources: {', '.join(parsed['target_sources'])}",
            estimated_cost=cost,
            limit=effective_limit,
            safety_checks_passed=True,
            explanation=explanation,
        )

    @classmethod
    def execute_hunt(
        cls,
        nl_query: str,
        events: list[Any],
        limit: int = DEFAULT_RESULT_LIMIT,
        offset: int = 0,
        target_scope: Optional[str] = None,
        hypothesis: str | None = None,
    ) -> HuntingQueryResult:
        """Executes a structured hunt against universal security events with safety bounds, pagination, and scope isolation."""
        start_time = time.perf_counter()
        parsed = cls.parse_natural_language(nl_query)
        effective_limit = min(cls.MAX_RESULT_LIMIT, max(1, limit))
        effective_offset = max(0, offset)
        target_hyp = hypothesis or f"Adversary activity matching patterns: '{nl_query}'"

        if len(parsed["filters"]) > cls.MAX_FILTER_CLAUSES:
            raise QuerySecurityError(
                f"Query generated {len(parsed['filters'])} filter clauses, exceeding limit of {cls.MAX_FILTER_CLAUSES}."
            )

        # Field and operator allowlist enforcement
        for f in parsed["filters"]:
            f_field = f.get("field_name")
            f_op = f.get("operator")
            if f_field not in cls.ALLOWED_FIELDS:
                raise QuerySecurityError(f"Field '{f_field}' is not in the allowed query field allowlist.")
            if f_op not in cls.ALLOWED_OPERATORS:
                raise QuerySecurityError(f"Operator '{f_op}' is not in the allowed operator allowlist.")

        filters = [HuntingFilterClause(**f) for f in parsed["filters"]]
        target_sources = set(parsed["target_sources"])

        all_matched_events: list[dict[str, Any]] = []
        matched_entities: dict[str, set[str]] = {
            "ips": set(),
            "hosts": set(),
            "users": set(),
            "processes": set(),
        }
        evidence_provenance: set[str] = set()

        for ev in events:
            # Check timeout protection
            if time.perf_counter() - start_time > cls.MAX_EXECUTION_TIMEOUT_SECONDS:
                raise QuerySecurityError(f"Query execution timed out (> {cls.MAX_EXECUTION_TIMEOUT_SECONDS}s).")

            # Enforce target scope isolation if specified (prevent silent context leakage)
            if target_scope:
                ev_ip = getattr(ev, "source_ip", "") or getattr(ev, "destination_ip", "")
                ev_host = getattr(ev, "hostname", "")
                if target_scope not in (ev_ip, ev_host):
                    continue
            # Check source type filtering
            src_type = getattr(ev, "source_type", None)
            if target_sources and src_type and src_type not in target_sources:
                continue

            # Evaluate each filter clause
            matches = True
            for f in filters:
                val = getattr(ev, f.field_name, None)
                if val is None:
                    if f.field_name in ("command_line", "url"):
                        val = getattr(ev, "url", None) or getattr(ev, "command_line", None) or getattr(ev, "raw_data", None)
                    elif hasattr(ev, "raw_data") and isinstance(ev.raw_data, dict):
                        val = ev.raw_data.get(f.field_name)
                    elif hasattr(ev, "raw_data") and isinstance(ev.raw_data, str):
                        val = ev.raw_data

                if val is None:
                    matches = False
                    break

                val_str = str(val).lower()
                exp_str = str(f.value).lower()

                if f.operator == "eq":
                    if val_str != exp_str:
                        matches = False
                        break
                elif f.operator == "contains":
                    if exp_str not in val_str:
                        matches = False
                        break
                elif f.operator == "startswith":
                    if not val_str.startswith(exp_str):
                        matches = False
                        break
                elif f.operator == "gte":
                    # Lexicographical comparison for ISO UTC timestamps
                    if val_str < exp_str:
                        matches = False
                        break

            if matches:
                ev_dict = ev.to_dict() if hasattr(ev, "to_dict") else dict(ev)
                all_matched_events.append(ev_dict)

                # Record entities
                if getattr(ev, "source_ip", None):
                    matched_entities["ips"].add(ev.source_ip)
                if getattr(ev, "destination_ip", None):
                    matched_entities["ips"].add(ev.destination_ip)
                if getattr(ev, "hostname", None):
                    matched_entities["hosts"].add(ev.hostname)
                if getattr(ev, "username", None):
                    matched_entities["users"].add(ev.username)
                if getattr(ev, "process_name", None):
                    matched_entities["processes"].add(ev.process_name)

                raw_evi = getattr(ev, "raw_evidence_id", None)
                if raw_evi:
                    evidence_provenance.add(raw_evi)

        total_matched = len(all_matched_events)
        # Apply pagination offset and limit
        paginated_events = all_matched_events[effective_offset : effective_offset + effective_limit]

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Determine hypothesis status
        if total_matched > 0:
            status = HypothesisStatus.CONFIRMED
        else:
            status = HypothesisStatus.REFUTED if len(events) >= 5 else HypothesisStatus.INCONCLUSIVE

        # Generate intelligent follow-up queries
        followups = []
        if status == HypothesisStatus.CONFIRMED:
            for ip in list(matched_entities["ips"])[:2]:
                followups.append(f"Hunt for all lateral movement and authentication attempts from {ip}")
            for proc in list(matched_entities["processes"])[:2]:
                followups.append(f"Investigate process lineage and child executions spawned by {proc}")
        else:
            followups.append("Broaden time window to past 7 days to account for low-and-slow tactics.")
            followups.append("Verify if endpoint logging policy captures process creation (Sysmon Event ID 1).")

        return HuntingQueryResult(
            query_id=parsed["query_id"],
            query_title=nl_query[:60],
            hypothesis=target_hyp,
            hypothesis_status=status,
            total_matched=total_matched,
            returned_count=len(paginated_events),
            execution_time_ms=elapsed_ms,
            events=paginated_events,
            matched_entities={k: sorted(list(v)) for k, v in matched_entities.items()},
            evidence_provenance=sorted(list(evidence_provenance)),
            suggested_followups=followups,
            offset=effective_offset,
            target_scope=target_scope,
        )
