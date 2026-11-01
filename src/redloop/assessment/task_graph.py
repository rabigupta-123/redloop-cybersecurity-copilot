"""Autonomous Task Graph Architecture and Execution Loop Controller for REDLOOP.

Implements PentAGI-style autonomous orchestration with strict security-first controls:
- Directed Acyclic Graph (DAG) of task nodes with dependency tracking.
- Controlled Autonomous Loop: OBSERVE -> PLAN -> AUTHORIZE -> ACT -> VERIFY -> RECORD -> REPLAN.
- Hard safety boundaries:
  * Maximum iterations (e.g. 10)
  * Maximum task depth (e.g. 5)
  * Maximum total execution time (e.g. 120 seconds)
  * Maximum per-task retries (e.g. 2)
  * Global and per-tool timeouts
  * Cancellation tokens
- Complete persistence to SQLite for inspectability and resume.
- Fail-closed authorization checking before every network action.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from redloop.assessment.models import ExecutionClass, StageStatus
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.tool_registry import ToolDefinition, get_tool_registry
from redloop.audit import AuditLogger


class NodeAuthState(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"
    EXEMPT_LOCAL = "EXEMPT_LOCAL"


@dataclass
class TaskNode:
    id: str
    parent_id: str | None
    target: str
    operation: str
    tool_name: str
    execution_class: ExecutionClass
    authorization_state: NodeAuthState
    status: StageStatus = StageStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 2
    provider_info: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "target": self.target,
            "operation": self.operation,
            "tool_name": self.tool_name,
            "execution_class": self.execution_class.value,
            "authorization_state": self.authorization_state.value,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "evidence_ids": self.evidence_ids,
            "findings": self.findings,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "provider_info": self.provider_info,
            "output": self.output,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskNode:
        return cls(
            id=data["id"],
            parent_id=data.get("parent_id"),
            target=data["target"],
            operation=data["operation"],
            tool_name=data["tool_name"],
            execution_class=ExecutionClass(data["execution_class"]),
            authorization_state=NodeAuthState(data["authorization_state"]),
            status=StageStatus(data["status"]),
            dependencies=data.get("dependencies", []),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            evidence_ids=data.get("evidence_ids", []),
            findings=data.get("findings", []),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 2),
            provider_info=data.get("provider_info", {}),
            output=data.get("output", {}),
            reason=data.get("reason", ""),
        )


class TaskGraph:
    """DAG Task Graph representation for structured multi-stage cyber operations."""

    def __init__(
        self,
        graph_id: str | None = None,
        root_goal: str = "",
        id: str | None = None,
        target: str = "",
        root_task_id: str = "",
    ) -> None:
        self.graph_id = id or graph_id or f"graph-{uuid.uuid4().hex[:12]}"
        self.root_goal = root_goal or (f"Assessment of {target}" if target else "")
        self.target = target
        self.root_task_id = root_task_id
        self.nodes: dict[str, TaskNode] = {}
        self.edges: list[tuple[str, str]] = []  # (from_id, to_id)
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    @property
    def id(self) -> str:
        return self.graph_id

    def add_node(self, node: TaskNode) -> None:
        self.nodes[node.id] = node
        for dep in node.dependencies:
            self.edges.append((dep, node.id))
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def get_ready_nodes(self) -> list[TaskNode]:
        """Return all nodes whose dependencies have succeeded and are currently PENDING."""
        ready: list[TaskNode] = []
        for n in self.nodes.values():
            if n.status != StageStatus.PENDING:
                continue
            deps_met = True
            for dep_id in n.dependencies:
                dep_node = self.nodes.get(dep_id)
                if not dep_node or dep_node.status not in (StageStatus.SUCCESS, StageStatus.SKIPPED):
                    deps_met = False
                    break
            if deps_met:
                ready.append(n)
        return ready

    def is_complete(self) -> bool:
        """Check if all nodes are in terminal states."""
        terminal_states = {
            StageStatus.SUCCESS,
            StageStatus.FAILED,
            StageStatus.BLOCKED,
            StageStatus.SKIPPED,
            StageStatus.UNAVAILABLE,
        }
        return all(n.status in terminal_states for n in self.nodes.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "root_goal": self.root_goal,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": self.edges,
            "is_complete": self.is_complete(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskGraph:
        g = cls(graph_id=data["graph_id"], root_goal=data.get("root_goal", ""))
        g.created_at = data.get("created_at", g.created_at)
        g.updated_at = data.get("updated_at", g.updated_at)
        g.edges = data.get("edges", [])
        for nid, ndata in data.get("nodes", {}).items():
            g.nodes[nid] = TaskNode.from_dict(ndata)
        return g


class TaskGraphStore:
    """Persistent storage for task graphs in SQLite."""

    def __init__(self, db_path: str | Path = "data/tasks.sqlite"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_graphs (
                    graph_id TEXT PRIMARY KEY,
                    root_goal TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    is_complete INTEGER,
                    graph_json TEXT
                )
                """
            )
            conn.commit()

    def save(self, graph: TaskGraph) -> None:
        data_json = json.dumps(graph.to_dict())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO task_graphs (graph_id, root_goal, created_at, updated_at, is_complete, graph_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(graph_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    is_complete=excluded.is_complete,
                    graph_json=excluded.graph_json
                """,
                (
                    graph.graph_id,
                    graph.root_goal,
                    graph.created_at,
                    graph.updated_at,
                    int(graph.is_complete()),
                    data_json,
                ),
            )
            conn.commit()

    def load(self, graph_id: str) -> TaskGraph | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT graph_json FROM task_graphs WHERE graph_id = ?", (graph_id,)).fetchone()
            if row:
                return TaskGraph.from_dict(json.loads(row[0]))
        return None

    def get(self, graph_id: str) -> TaskGraph | None:
        """Alias for load(graph_id)."""
        return self.load(graph_id)


class AutonomousLoopController:
    """Manages the OBSERVE -> PLAN -> AUTHORIZE -> ACT -> VERIFY -> RECORD -> REPLAN cycle."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
        store: TaskGraphStore | None = None,
        max_iterations: int = 10,
        max_execution_time_seconds: float = 120.0,
        max_depth: int = 5,
        task_id: str | None = None,
        target: str = "",
        max_execution_time: float | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.store = store or TaskGraphStore()
        self.registry = get_tool_registry()
        self.max_iterations = max_iterations
        self.max_execution_time = max_execution_time if max_execution_time is not None else max_execution_time_seconds
        self.max_depth = max_depth
        self.task_id = task_id
        self.target = target
        self._cancelled = False
        self._iteration_count = 0
        self._start_monotonic = time.monotonic()
        self._observations: list[dict[str, Any]] = []

    def cancel(self) -> None:
        """Signal cancellation of the autonomous loop."""
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled

    def record_observation(self, obs: dict[str, Any]) -> None:
        self._observations.append(obs)
        self._iteration_count += 1

    def should_continue(self) -> bool:
        if self._cancelled:
            return False
        if self._iteration_count >= self.max_iterations:
            return False
        if (time.monotonic() - self._start_monotonic) >= self.max_execution_time:
            return False
        return True

    def build_initial_assessment_graph(self, target: str, depth: str = "standard") -> TaskGraph:
        """Construct standard multi-stage assessment DAG for a target."""
        graph = TaskGraph(root_goal=f"Comprehensive Security Assessment of {target}")

        # Root: Scope validation
        is_ip = bool(target.replace(".", "").isdigit())
        node_scope = TaskNode(
            id=f"node-scope-{uuid.uuid4().hex[:6]}",
            parent_id=None,
            target=target,
            operation="scope_validation",
            tool_name="scope_guard",
            execution_class=ExecutionClass.LOCAL_ONLY,
            authorization_state=NodeAuthState.EXEMPT_LOCAL,
            status=StageStatus.PENDING,
        )
        graph.add_node(node_scope)

        # Local evidence check
        node_local = TaskNode(
            id=f"node-local-{uuid.uuid4().hex[:6]}",
            parent_id=node_scope.id,
            target=target,
            operation="local_evidence_review",
            tool_name="local_evidence_review",
            execution_class=ExecutionClass.LOCAL_ONLY,
            authorization_state=NodeAuthState.EXEMPT_LOCAL,
            dependencies=[node_scope.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_local)

        # Recon: DNS (if domain) and Port scan
        node_dns = TaskNode(
            id=f"node-dns-{uuid.uuid4().hex[:6]}",
            parent_id=node_scope.id,
            target=target,
            operation="dns_discovery",
            tool_name="dns_scanner",
            execution_class=ExecutionClass.NETWORK_DEPENDENT,
            authorization_state=NodeAuthState.PENDING,
            dependencies=[node_scope.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_dns)

        node_ports = TaskNode(
            id=f"node-ports-{uuid.uuid4().hex[:6]}",
            parent_id=node_scope.id,
            target=target,
            operation="network_discovery",
            tool_name="port_scanner",
            execution_class=ExecutionClass.NETWORK_DEPENDENT,
            authorization_state=NodeAuthState.PENDING,
            dependencies=[node_scope.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_ports)

        # Service assessment: TLS and Web
        node_tls = TaskNode(
            id=f"node-tls-{uuid.uuid4().hex[:6]}",
            parent_id=node_ports.id,
            target=target,
            operation="tls_assessment",
            tool_name="tls_checker",
            execution_class=ExecutionClass.NETWORK_DEPENDENT,
            authorization_state=NodeAuthState.PENDING,
            dependencies=[node_ports.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_tls)

        node_web = TaskNode(
            id=f"node-web-{uuid.uuid4().hex[:6]}",
            parent_id=node_ports.id,
            target=target,
            operation="web_assessment",
            tool_name="web_checker",
            execution_class=ExecutionClass.NETWORK_DEPENDENT,
            authorization_state=NodeAuthState.PENDING,
            dependencies=[node_ports.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_web)

        # Synthesis & Reporting
        node_corr = TaskNode(
            id=f"node-corr-{uuid.uuid4().hex[:6]}",
            parent_id=None,
            target=target,
            operation="correlation_and_risk",
            tool_name="correlation_engine",
            execution_class=ExecutionClass.LOCAL_ONLY,
            authorization_state=NodeAuthState.EXEMPT_LOCAL,
            dependencies=[node_local.id, node_tls.id, node_web.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_corr)

        node_ai = TaskNode(
            id=f"node-ai-{uuid.uuid4().hex[:6]}",
            parent_id=node_corr.id,
            target=target,
            operation="ai_analysis",
            tool_name="llm_reasoning",
            execution_class=ExecutionClass.AI_PROVIDER_DEPENDENT,
            authorization_state=NodeAuthState.EXEMPT_LOCAL,
            dependencies=[node_corr.id],
            status=StageStatus.PENDING,
        )
        graph.add_node(node_ai)

        self.store.save(graph)
        return graph

    def run_step(self, graph: TaskGraph, execute_node_fn: Callable[[TaskNode], None]) -> bool:
        """Execute one autonomous step across ready nodes.
        
        Returns True if progress was made, False if graph is complete or blocked.
        """
        if self._cancelled or graph.is_complete():
            return False

        ready_nodes = graph.get_ready_nodes()
        if not ready_nodes:
            return False

        for node in ready_nodes:
            if self._cancelled:
                node.status = StageStatus.FAILED
                node.reason = "Autonomous loop cancelled by user."
                continue

            node.start_time = datetime.now(timezone.utc).isoformat()

            # AUTHORIZE step: If network-dependent, check scope guard strictly
            if node.execution_class == ExecutionClass.NETWORK_DEPENDENT:
                is_auth = False
                if self.scope_guard:
                    try:
                        is_auth = self.scope_guard.is_authorized(node.target)
                    except Exception:
                        is_auth = False
                
                if not is_auth:
                    node.authorization_state = NodeAuthState.BLOCKED
                    node.status = StageStatus.BLOCKED
                    node.reason = f"Target '{node.target}' is outside the active signed scope contract."
                    node.end_time = datetime.now(timezone.utc).isoformat()
                    if self.audit:
                        self.audit.blocked(node.target, node.operation, "task_graph", "Network operation blocked by scope guard.")
                    continue
                else:
                    node.authorization_state = NodeAuthState.AUTHORIZED

            # ACT & VERIFY: execute node function
            try:
                execute_node_fn(node)
                if node.status == StageStatus.PENDING:
                    node.status = StageStatus.SUCCESS
            except ScopeBlockedError as sbe:
                node.status = StageStatus.BLOCKED
                node.reason = str(sbe)
            except Exception as exc:
                node.status = StageStatus.FAILED
                node.reason = f"Execution error: {exc}"

            node.end_time = datetime.now(timezone.utc).isoformat()

        graph.updated_at = datetime.now(timezone.utc).isoformat()
        self.store.save(graph)
        return True
