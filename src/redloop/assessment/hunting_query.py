"""REDLOOP Phase 10 — Advanced Structured Threat Hunting Query AST & Execution Engine.

Provides:
1. Typed AST for secure threat hunting queries without eval() or raw code execution.
2. Grammar supporting field comparisons (EQ, NEQ, CONTAINS, REGEX, IN, GT, LT, GTE, LTE)
   and logical expressions (AND, OR, NOT).
3. Schema-validated fields (event_type, process_name, command_line, source_ip, dest_ip, user, host, file_hash, etc.).
4. Query cost and complexity estimator (penalizing unbounded regex, wide timeframes, wildcard searches).
5. Bounded query execution engine with memory limits and pagination limits.
6. Persistent query book for saved hunting queries and auditable execution history.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from redloop.assessment.soc_events import UniversalSecurityEvent


class HuntingOperator(str, Enum):
    EQ = "EQ"
    NEQ = "NEQ"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    STARTSWITH = "STARTSWITH"
    ENDSWITH = "ENDSWITH"
    REGEX = "REGEX"
    IN = "IN"
    GT = "GT"
    LT = "LT"
    GTE = "GTE"
    LTE = "LTE"


class LogicalOperator(str, Enum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


HuntingLogicalOperator = LogicalOperator


ALLOWED_QUERY_FIELDS: set[str] = {
    "event_id",
    "timestamp",
    "source_type",
    "source_file",
    "hostname",
    "host",
    "username",
    "user",
    "source_ip",
    "dest_ip",
    "destination_ip",
    "source_port",
    "dest_port",
    "destination_port",
    "event_category",
    "event_action",
    "event_type",
    "process_name",
    "parent_process_name",
    "process_id",
    "parent_process_id",
    "command_line",
    "file_path",
    "file_hash",
    "sha256",
    "md5",
    "dns_query",
    "url",
    "severity",
    "parser_status",
}


@dataclass
class QueryFieldCriteria:
    """Individual attribute matching condition in a hunting query."""
    field_name: str
    operator: HuntingOperator
    value: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_name": self.field_name,
            "operator": self.operator.value,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "QueryFieldCriteria":
        f = d.get("field_name", "").strip().lower()
        if f not in ALLOWED_QUERY_FIELDS:
            raise ValueError(f"Unrecognized or unapproved hunting query field '{f}'. Allowed: {sorted(ALLOWED_QUERY_FIELDS)}")
        op = HuntingOperator(d.get("operator", "EQ").upper())
        val = d.get("value")
        if op == HuntingOperator.REGEX:
            try:
                re.compile(str(val))
            except re.error as re_err:
                raise ValueError(f"Invalid regular expression '{val}': {re_err}")
        return cls(field_name=f, operator=op, value=val)


@dataclass
class HuntingQueryAST:
    """Abstract Syntax Tree representing a structured threat hunting query."""
    criteria: list[QueryFieldCriteria] = field(default_factory=list)
    logical_operator: LogicalOperator = LogicalOperator.AND
    subqueries: list["HuntingQueryAST"] = field(default_factory=list)
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    limit: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "criteria": [c.to_dict() for c in self.criteria],
            "logical_operator": self.logical_operator.value,
            "subqueries": [sq.to_dict() for sq in self.subqueries],
            "time_start": self.time_start,
            "time_end": self.time_end,
            "limit": self.limit,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HuntingQueryAST":
        crit = [QueryFieldCriteria.from_dict(c) for c in d.get("criteria", [])]
        op = LogicalOperator(d.get("logical_operator", "AND").upper())
        subs = [cls.from_dict(sq) for sq in d.get("subqueries", [])]
        lim = min(max(1, int(d.get("limit", 100))), 1000)
        return cls(
            criteria=crit,
            logical_operator=op,
            subqueries=subs,
            time_start=d.get("time_start"),
            time_end=d.get("time_end"),
            limit=lim,
        )


@dataclass
class HuntingQueryResult:
    """Outcome of a structured hunting query execution."""
    query_id: str
    matched_events: list[UniversalSecurityEvent]
    total_matched: int
    execution_time_ms: float
    cost_score: int
    complexity_rating: str  # "LOW", "MEDIUM", "HIGH"
    query_ast: dict[str, Any]
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "matched_events": [e.to_dict() for e in self.matched_events],
            "total_matched": self.total_matched,
            "execution_time_ms": self.execution_time_ms,
            "cost_score": self.cost_score,
            "complexity_rating": self.complexity_rating,
            "query_ast": self.query_ast,
            "executed_at": self.executed_at,
        }


def estimate_query_cost(ast: HuntingQueryAST) -> tuple[int, str]:
    """Calculates query execution cost and complexity rating without running the query."""
    score = 10  # Base cost
    for c in ast.criteria:
        if c.operator == HuntingOperator.REGEX:
            score += 35
        elif c.operator in (HuntingOperator.CONTAINS, HuntingOperator.NOT_CONTAINS):
            score += 15
        elif c.operator == HuntingOperator.IN:
            score += 10
        else:
            score += 5

    for sq in ast.subqueries:
        sub_score, _ = estimate_query_cost(sq)
        score += sub_score

    if not ast.time_start or not ast.time_end:
        score += 20  # Unbounded timeframe penalty

    if ast.limit > 500:
        score += 15

    rating = "LOW"
    if score > 80:
        rating = "HIGH"
    elif score > 40:
        rating = "MEDIUM"

    return score, rating


class HuntingQueryEngine:
    """Executes structured AST hunting queries with resource bounds and persistence."""

    _instance: Optional["HuntingQueryEngine"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/hunting_queries.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "HuntingQueryEngine":
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
                        CREATE TABLE IF NOT EXISTS saved_hunting_queries (
                            query_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT NOT NULL,
                            query_ast_json TEXT NOT NULL,
                            mitre_techniques_json TEXT NOT NULL,
                            created_by TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS hunting_query_history (
                            history_id TEXT PRIMARY KEY,
                            query_id TEXT NOT NULL,
                            query_ast_json TEXT NOT NULL,
                            matched_count INTEGER NOT NULL,
                            execution_time_ms REAL NOT NULL,
                            cost_score INTEGER NOT NULL,
                            executed_by TEXT NOT NULL,
                            executed_at TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears all query history and saved queries (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM saved_hunting_queries")
                    conn.execute("DELETE FROM hunting_query_history")
            finally:
                conn.close()

    def parse_simple_dsl(self, query_str: str) -> HuntingQueryAST:
        """Parses a human-readable query string into a structured HuntingQueryAST.
        
        Example:
            process_name == "powershell.exe" AND command_line CONTAINS "-enc"
        """
        clean = query_str.strip()
        if not clean:
            return HuntingQueryAST()

        # Split top-level by ' AND ' or ' OR '
        is_or = " OR " in clean and " AND " not in clean
        logical_op = LogicalOperator.OR if is_or else LogicalOperator.AND
        delimiter = " OR " if is_or else " AND "
        raw_parts = clean.split(delimiter)

        criteria = []
        op_map = {
            "==": HuntingOperator.EQ,
            "!=": HuntingOperator.NEQ,
            "CONTAINS": HuntingOperator.CONTAINS,
            "NOT_CONTAINS": HuntingOperator.NOT_CONTAINS,
            "STARTSWITH": HuntingOperator.STARTSWITH,
            "ENDSWITH": HuntingOperator.ENDSWITH,
            "REGEX": HuntingOperator.REGEX,
            ">=": HuntingOperator.GTE,
            "<=": HuntingOperator.LTE,
            ">": HuntingOperator.GT,
            "<": HuntingOperator.LT,
        }

        for part in raw_parts:
            part = part.strip()
            if not part:
                continue
            matched = False
            for sym, op_enum in sorted(op_map.items(), key=lambda x: -len(x[0])):
                pattern = rf"^(\w+)\s+{re.escape(sym)}\s+(.+)$"
                m = re.match(pattern, part, re.IGNORECASE)
                if m:
                    f_name = m.group(1).lower().strip()
                    val = m.group(2).strip().strip("\"'")
                    criteria.append(QueryFieldCriteria(field_name=f_name, operator=op_enum, value=val))
                    matched = True
                    break
            if not matched:
                # Default fallback: CONTAINS on command_line or raw
                criteria.append(QueryFieldCriteria(field_name="command_line", operator=HuntingOperator.CONTAINS, value=part))

        return HuntingQueryAST(criteria=criteria, logical_operator=logical_op)

    def _matches_criteria(self, event: UniversalSecurityEvent, criteria: QueryFieldCriteria) -> bool:
        """Evaluates whether an individual security event satisfies a single criterion."""
        f_name = criteria.field_name
        # Alias normalization
        if f_name == "host":
            f_name = "hostname"
        elif f_name == "user":
            f_name = "username"
        elif f_name in ("dest_ip", "destination_ip"):
            f_name = "destination_ip"
        elif f_name == "event_type":
            f_name = "event_action"

        # Extract value from event
        actual_val = getattr(event, f_name, None)
        if actual_val is None and event.raw_data and isinstance(event.raw_data, dict):
            actual_val = event.raw_data.get(f_name)

        target_val = criteria.value
        op = criteria.operator

        if actual_val is None:
            return op == HuntingOperator.NEQ

        actual_str = str(actual_val)
        target_str = str(target_val)

        if op == HuntingOperator.EQ:
            return actual_str.lower() == target_str.lower()
        elif op == HuntingOperator.NEQ:
            return actual_str.lower() != target_str.lower()
        elif op == HuntingOperator.CONTAINS:
            return target_str.lower() in actual_str.lower()
        elif op == HuntingOperator.NOT_CONTAINS:
            return target_str.lower() not in actual_str.lower()
        elif op == HuntingOperator.STARTSWITH:
            return actual_str.lower().startswith(target_str.lower())
        elif op == HuntingOperator.ENDSWITH:
            return actual_str.lower().endswith(target_str.lower())
        elif op == HuntingOperator.REGEX:
            try:
                return bool(re.search(target_str, actual_str, re.IGNORECASE))
            except Exception:
                return False
        elif op == HuntingOperator.IN:
            if isinstance(target_val, list):
                return actual_str.lower() in [str(x).lower() for x in target_val]
            targets = [x.strip().lower() for x in target_str.split(",")]
            return actual_str.lower() in targets
        elif op in (HuntingOperator.GT, HuntingOperator.LT, HuntingOperator.GTE, HuntingOperator.LTE):
            try:
                num_actual = float(actual_val)
                num_target = float(target_val)
                if op == HuntingOperator.GT:
                    return num_actual > num_target
                elif op == HuntingOperator.LT:
                    return num_actual < num_target
                elif op == HuntingOperator.GTE:
                    return num_actual >= num_target
                elif op == HuntingOperator.LTE:
                    return num_actual <= num_target
            except (ValueError, TypeError):
                # Fallback to string comparison
                if op == HuntingOperator.GT:
                    return actual_str > target_str
                elif op == HuntingOperator.LT:
                    return actual_str < target_str
                elif op == HuntingOperator.GTE:
                    return actual_str >= target_str
                elif op == HuntingOperator.LTE:
                    return actual_str <= target_str

        return False

    def evaluate_ast(self, event: UniversalSecurityEvent, ast: HuntingQueryAST) -> bool:
        """Recursively checks if a single event matches an AST query."""
        # Time window boundary check
        if ast.time_start and event.timestamp < ast.time_start:
            return False
        if ast.time_end and event.timestamp > ast.time_end:
            return False

        if not ast.criteria and not ast.subqueries:
            return True

        crit_matches = [self._matches_criteria(event, c) for c in ast.criteria]
        sub_matches = [self.evaluate_ast(event, sq) for sq in ast.subqueries]
        all_evals = crit_matches + sub_matches

        if ast.logical_operator == LogicalOperator.AND:
            return all(all_evals) if all_evals else True
        elif ast.logical_operator == LogicalOperator.OR:
            return any(all_evals) if all_evals else True
        elif ast.logical_operator == LogicalOperator.NOT:
            return not any(all_evals)

        return False

    def execute_query(
        self,
        query: HuntingQueryAST | dict[str, Any] | str,
        events: Optional[list[UniversalSecurityEvent]] = None,
        operator: str = "analyst",
    ) -> HuntingQueryResult:
        """Executes a hunting query against provided events or ingested database telemetry."""
        start_t = time.time()
        qid = f"query-{uuid.uuid4().hex[:10]}"

        if isinstance(query, str):
            ast = self.parse_simple_dsl(query)
        elif isinstance(query, dict):
            ast = HuntingQueryAST.from_dict(query)
        else:
            ast = query

        cost, complexity = estimate_query_cost(ast)

        # Source pool of events
        pool: list[UniversalSecurityEvent] = []
        if events is not None:
            pool = events
        else:
            # Query ingested events from local database if available
            pool = self._load_ingested_events()

        matches = []
        for ev in pool:
            if self.evaluate_ast(ev, ast):
                matches.append(ev)
                if len(matches) >= ast.limit:
                    break

        elapsed = round((time.time() - start_t) * 1000.0, 2)

        res = HuntingQueryResult(
            query_id=qid,
            matched_events=matches,
            total_matched=len(matches),
            execution_time_ms=elapsed,
            cost_score=cost,
            complexity_rating=complexity,
            query_ast=ast.to_dict(),
        )

        # Record history
        self._record_history(res, executed_by=operator)
        return res

    def _load_ingested_events(self) -> list[UniversalSecurityEvent]:
        """Loads events from ingested_telemetry_events SQLite table if exists."""
        db_path = Path("data/telemetry_sync.db")
        if not db_path.exists():
            return []
        events = []
        try:
            conn = sqlite3.connect(str(db_path), timeout=5.0)
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.execute("SELECT normalized_json FROM ingested_telemetry_events ORDER BY original_timestamp DESC LIMIT 1000")
                for r in cur.fetchall():
                    try:
                        d = json.loads(r["normalized_json"])
                        events.append(UniversalSecurityEvent(**d))
                    except Exception:
                        pass
            finally:
                conn.close()
        except Exception:
            pass
        return events

    def _record_history(self, result: HuntingQueryResult, executed_by: str) -> None:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO hunting_query_history
                        (history_id, query_id, query_ast_json, matched_count, execution_time_ms, cost_score, executed_by, executed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"hist-{uuid.uuid4().hex[:10]}",
                            result.query_id,
                            json.dumps(result.query_ast),
                            result.total_matched,
                            result.execution_time_ms,
                            result.cost_score,
                            executed_by,
                            result.executed_at,
                        ),
                    )
            finally:
                conn.close()

    def save_query(
        self,
        title: str,
        query_ast: HuntingQueryAST | dict[str, Any],
        description: str = "",
        mitre_techniques: Optional[list[str]] = None,
        created_by: str = "analyst",
    ) -> dict[str, Any]:
        """Persists a saved threat hunting query in the query book."""
        qid = f"sq-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        ast_dict = query_ast.to_dict() if isinstance(query_ast, HuntingQueryAST) else query_ast
        techniques = mitre_techniques or []

        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO saved_hunting_queries
                        (query_id, title, description, query_ast_json, mitre_techniques_json, created_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (qid, title, description, json.dumps(ast_dict), json.dumps(techniques), created_by, now, now),
                    )
            finally:
                conn.close()

        return {
            "query_id": qid,
            "title": title,
            "description": description,
            "query_ast": ast_dict,
            "mitre_techniques": techniques,
            "created_by": created_by,
            "created_at": now,
        }

    def list_saved_queries(self) -> list[dict[str, Any]]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM saved_hunting_queries ORDER BY created_at DESC")
                results = []
                for r in cur.fetchall():
                    results.append({
                        "query_id": r["query_id"],
                        "title": r["title"],
                        "description": r["description"],
                        "query_ast": json.loads(r["query_ast_json"]),
                        "mitre_techniques": json.loads(r["mitre_techniques_json"]),
                        "created_by": r["created_by"],
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                    })
                return results
            finally:
                conn.close()

    def delete_saved_query(self, query_id: str) -> bool:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute("DELETE FROM saved_hunting_queries WHERE query_id = ?", (query_id,))
                    return cur.rowcount > 0
            finally:
                conn.close()
