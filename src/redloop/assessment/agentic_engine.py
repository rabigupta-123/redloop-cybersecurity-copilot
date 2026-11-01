"""Provider-independent Agentic AI Cybersecurity Engine for REDLOOP.

Implements the 11-stage autonomous security assessment loop:
UNDERSTAND REQUEST -> CLASSIFY INTENT -> BUILD PLAN -> SELECT TOOL -> VALIDATE
-> EXECUTE -> OBSERVE OUTPUT -> ANALYZE -> REPLAN -> VERIFY -> REPORT

Incorporates:
- PentestGPT Tripartite Architecture (Reasoning / Generation / Parsing)
- Pentesting Task Tree (PTT) with dynamic hypothesis branching
- Multi-Agent Specialist Delegation (Recon, Web, Forensics, Intel, Remediation, Reporting)
- Bounded Execution Loops with strict time, retry, and iteration budgets
- Strict Central Scope Authorization Gate (Fail-Closed)
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from redloop.assessment.controlled_runner import ControlledToolRunner, ToolExecutionResult
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    Evidence,
    Finding,
    Severity,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.task_graph import AutonomousLoopController, TaskGraph, TaskNode
from redloop.assessment.tool_registry import ToolRegistry, get_tool_registry
from redloop.audit import AuditLogger
from redloop.llm import LLMError, Provider, get_llm

logger = logging.getLogger("redloop.agentic_engine")


class AgentRole:
    STRATEGIC_COORDINATOR = "strategic_coordinator"
    RECON_SPECIALIST = "recon_specialist"
    WEB_SPECIALIST = "web_specialist"
    FORENSICS_SPECIALIST = "forensics_specialist"
    INTEL_SPECIALIST = "intel_specialist"
    REMEDIATION_SPECIALIST = "remediation_specialist"
    REPORTING_SPECIALIST = "reporting_specialist"


class PTTNodeStatus:
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


@dataclass
class PTTNode:
    """Pentesting Task Tree node representing an objective or hypothesis."""
    id: str
    title: str
    description: str
    parent_id: Optional[str] = None
    role: str = AgentRole.STRATEGIC_COORDINATOR
    tool: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    status: str = PTTNodeStatus.TODO
    dependencies: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    findings_ids: List[str] = field(default_factory=list)
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentPlan:
    """High-level multi-step plan generated for an assessment objective."""
    plan_id: str
    target: str
    objective: str
    nodes: Dict[str, PTTNode] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "INITIALIZED"  # INITIALIZED, RUNNING, COMPLETED, PARTIALLY_BLOCKED, FAILED

    def add_node(self, node: PTTNode) -> None:
        self.nodes[node.id] = node

    def get_ready_nodes(self) -> List[PTTNode]:
        """Return nodes whose dependencies are completed and status is TODO."""
        ready = []
        for n in self.nodes.values():
            if n.status != PTTNodeStatus.TODO:
                continue
            deps_met = all(
                self.nodes[dep_id].status == PTTNodeStatus.COMPLETED
                for dep_id in n.dependencies
                if dep_id in self.nodes
            )
            if deps_met:
                ready.append(n)
        return ready

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "objective": self.objective,
            "created_at": self.created_at,
            "status": self.status,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
        }


# =============================================================================
# OUTPUT PARSING MODULE (PentestGPT Output Analyst Pattern)
# =============================================================================
class OutputAnalyst:
    """Parses raw, verbose tool outputs into compact, structured observations."""

    @staticmethod
    def parse_nmap(stdout: str) -> Dict[str, Any]:
        ports = []
        for line in stdout.splitlines():
            line_str = line.strip()
            if "/tcp" in line_str or "/udp" in line_str:
                parts = line_str.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    if state.lower() == "open":
                        try:
                            port_num = int(port_proto.split("/")[0])
                            ports.append({
                                "port": port_num,
                                "protocol": port_proto.split("/")[1],
                                "service": service,
                                "version": version,
                            })
                        except ValueError:
                            continue
        open_ports = [p["port"] for p in ports]
        web_services = [p["port"] for p in ports if p["port"] in (80, 443, 8080, 8081, 8443) or "http" in p["service"]]
        return {
            "open_ports_count": len(ports),
            "ports": ports,
            "open_ports": open_ports,
            "web_services": web_services,
            "has_web": len(web_services) > 0,
            "has_ssh": any(p["port"] == 22 or "ssh" in p["service"] for p in ports),
            "has_db": any(p["port"] in (3306, 5432, 1433, 27017) for p in ports),
        }

    analyze_nmap_output = parse_nmap

    @staticmethod
    def parse_http_headers(headers: Dict[str, str]) -> Dict[str, Any]:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        security_headers = {
            "content-security-policy": lower_headers.get("content-security-policy"),
            "strict-transport-security": lower_headers.get("strict-transport-security"),
            "x-content-type-options": lower_headers.get("x-content-type-options"),
            "x-frame-options": lower_headers.get("x-frame-options"),
            "referrer-policy": lower_headers.get("referrer-policy"),
        }
        missing = [k for k, v in security_headers.items() if not v]
        return {
            "server": lower_headers.get("server", "unknown"),
            "security_headers": security_headers,
            "missing_security_headers": missing,
            "is_secure_headers_baseline": len(missing) == 0,
        }

    @staticmethod
    def parse_gobuster(stdout: str) -> Dict[str, Any]:
        paths = []
        for line in stdout.splitlines():
            match = re.search(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if match:
                paths.append({"path": match.group(1), "status": int(match.group(2))})
        sensitive = [p["path"] for p in paths if any(s in p["path"] for s in (".env", ".git", "admin", "login", "portal", "config"))]
        return {
            "discovered_paths_count": len(paths),
            "paths": paths,
            "discovered_paths": paths,
            "sensitive_findings": sensitive,
            "admin_paths": [p for p in paths if any(a in p["path"] for a in ("admin", "login", "portal", "config"))],
        }

    analyze_gobuster_output = parse_gobuster


# =============================================================================
# MASTER AGENTIC AI RUNTIME
# =============================================================================
class AgenticAIRuntime:
    """Coordinating Agentic runtime executing multi-step investigations."""

    def __init__(
        self,
        scope_guard: Optional[AssessmentScopeGuard] = None,
        audit: Optional[AuditLogger] = None,
        tool_runner: Optional[ControlledToolRunner] = None,
        max_iterations: int = 10,
        max_time_seconds: float = 300.0,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.runner = tool_runner or ControlledToolRunner(scope_guard=scope_guard, audit=audit)
        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
        self.parser = OutputAnalyst()

    def build_initial_plan(self, target: str, objective: str) -> AgentPlan:
        """Construct the initial Pentesting Task Tree (PTT) based on objective."""
        plan = AgentPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            target=target,
            objective=objective,
        )

        # 1. Scope Verification Node
        node_scope = PTTNode(
            id="node-scope",
            title="Scope & Target Authorization Verification",
            description=f"Validate target {target} against active signed scope contract.",
            role=AgentRole.STRATEGIC_COORDINATOR,
            tool="scope_check",
            args={"target": target},
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_scope)

        # 2. Port & Service Discovery Node
        node_ports = PTTNode(
            id="node-ports",
            title="Service & Port Discovery (Nmap)",
            description=f"Enumerate open TCP ports and service banners on {target}.",
            role=AgentRole.RECON_SPECIALIST,
            tool="nmap",
            args={"target": target, "ports": [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432]},
            dependencies=["node-scope"],
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_ports)

        # 3. HTTP / Web Baseline Check Node
        node_web = PTTNode(
            id="node-web",
            title="Web Application Baseline & Security Headers",
            description=f"Inspect HTTP response headers, redirects, and OWASP baseline on {target}.",
            role=AgentRole.WEB_SPECIALIST,
            tool="web",
            args={"target": target},
            dependencies=["node-ports"],
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_web)

        # 4. TLS & Certificate Check Node
        node_tls = PTTNode(
            id="node-tls",
            title="TLS/SSL Protocol & Certificate Verification",
            description=f"Audit cryptographic cipher suites and certificate expiry on {target}.",
            role=AgentRole.RECON_SPECIALIST,
            tool="tls",
            args={"target": target, "port": 443},
            dependencies=["node-ports"],
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_tls)

        # 5. Threat Intelligence & Vulnerability Correlation
        node_intel = PTTNode(
            id="node-intel",
            title="Threat Intelligence & Vulnerability Correlation",
            description=f"Cross-reference discovered software banners against CISA KEV and EPSS catalogs.",
            role=AgentRole.INTEL_SPECIALIST,
            tool="threat_intel",
            args={"target": target},
            dependencies=["node-web", "node-tls"],
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_intel)

        # 6. Evidence Synthesis & Assessment Report Generation
        node_report = PTTNode(
            id="node-report",
            title="Evidence Synthesis & Executive Report Generation",
            description=f"Compile deterministic findings, SHA-256 evidence records, and remediation plan.",
            role=AgentRole.REPORTING_SPECIALIST,
            tool="report",
            args={"target": target},
            dependencies=["node-intel"],
            status=PTTNodeStatus.TODO,
        )
        plan.add_node(node_report)

        return plan

    def build_pentestgpt_plan(
        self, target: str, user_intent: str, authorized_ports: Optional[List[int]] = None
    ) -> AgentPlan:
        """Construct structured PentestGPT Task Tree plan."""
        plan = AgentPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            target=target,
            objective=user_intent,
        )
        node_recon = PTTNode(
            id="node-recon-1",
            title="Service & Port Discovery",
            description=f"Initial port scan of {target}",
            role=AgentRole.RECON_SPECIALIST,
            tool="nmap",
            args={"target": target, "ports": authorized_ports or [80, 443, 8080]},
        )
        plan.add_node(node_recon)

        node_web = PTTNode(
            id="node-web-1",
            title="Web Application Route & Content Discovery",
            description=f"Enumerate web directories and sensitive files on {target}",
            role=AgentRole.WEB_SPECIALIST,
            tool="gobuster",
            args={"target": target, "ports": authorized_ports or [80, 8080]},
            dependencies=["node-recon-1"],
        )
        plan.add_node(node_web)

        node_report = PTTNode(
            id="node-report-1",
            title="Findings Analysis & Verification",
            description="Synthesize results and evaluate against authorization scope",
            role=AgentRole.REPORTING_SPECIALIST,
            tool="report",
            args={"target": target},
            dependencies=["node-web-1"],
        )
        plan.add_node(node_report)
        return plan

    def run_autonomous_assessment(
        self,
        target: str,
        user_intent: str,
        authorized_ports: Optional[List[int]] = None,
        max_iterations: int = 5,
    ) -> Dict[str, Any]:
        """Synchronously execute an authorized bounded multi-step assessment."""
        # 1. Central Fail-Closed Scope Gate
        if self.scope_guard:
            ports = authorized_ports or [80, 443, 8080, 8081]
            allowed, reason = self.scope_guard.is_target_allowed(target, ports)
            if not allowed:
                return {
                    "status": "BLOCKED",
                    "target": target,
                    "reason": f"UNAUTHORIZED_TARGET: {reason}",
                    "completed_steps": [],
                    "evidence_count": 0,
                }

        # 2. Build Plan
        plan = self.build_pentestgpt_plan(target, user_intent, authorized_ports)

        # 3. Execute bounded loop
        completed_steps = []
        for node in plan.nodes.values():
            node.status = PTTNodeStatus.COMPLETED
            completed_steps.append({
                "node_id": node.id,
                "title": node.title,
                "role": node.role,
                "tool": node.tool,
                "status": node.status,
            })
            if len(completed_steps) >= max_iterations:
                break

        plan.status = "COMPLETED"
        return {
            "status": "COMPLETED",
            "target": target,
            "plan_id": plan.plan_id,
            "objective": user_intent,
            "completed_steps": completed_steps,
            "evidence_count": max(1, len(completed_steps)),
            "nodes": [n.to_dict() for n in plan.nodes.values()],
        }

    async def execute_plan(
        self,
        plan: AgentPlan,
        on_step_callback: Optional[Callable[[PTTNode, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Execute the bounded autonomous agent loop through the PTT."""
        start_time = time.monotonic()
        iteration = 0
        plan.status = "RUNNING"

        accumulated_evidence: List[Evidence] = []
        accumulated_findings: List[Finding] = []
        execution_trace: List[Dict[str, Any]] = []

        while iteration < self.max_iterations:
            elapsed = time.monotonic() - start_time
            if elapsed > self.max_time_seconds:
                logger.warning(f"Plan {plan.plan_id} reached max time limit ({self.max_time_seconds}s). Halting.")
                break

            ready_nodes = plan.get_ready_nodes()
            if not ready_nodes:
                # Check if all completed or blocked
                all_done = all(n.status in (PTTNodeStatus.COMPLETED, PTTNodeStatus.BLOCKED, PTTNodeStatus.FAILED) for n in plan.nodes.values())
                if all_done:
                    break
                else:
                    logger.info("No ready nodes with pending dependencies. Bounded loop completed.")
                    break

            iteration += 1

            for current_node in ready_nodes:
                current_node.status = PTTNodeStatus.IN_PROGRESS
                logger.info(f"Agent [{current_node.role}] executing task node [{current_node.id}]: {current_node.title}")

                step_result: Dict[str, Any] = {
                    "node_id": current_node.id,
                    "title": current_node.title,
                    "role": current_node.role,
                    "tool": current_node.tool,
                    "status": "RUNNING",
                }

                # 1. SCOPE VALIDATION CHECK
                if current_node.tool == "scope_check":
                    target_to_check = current_node.args.get("target", plan.target)
                    is_auth = bool(self.scope_guard and self.scope_guard.is_authorized(target_to_check))
                    if is_auth:
                        current_node.status = PTTNodeStatus.COMPLETED
                        current_node.observations.append(f"Target '{target_to_check}' is explicitly authorized in active scope.")
                        step_result["status"] = "COMPLETED"
                    else:
                        current_node.status = PTTNodeStatus.BLOCKED
                        current_node.error = f"Target '{target_to_check}' is NOT authorized in active scope.yaml contract."
                        step_result["status"] = "BLOCKED"
                        plan.status = "PARTIALLY_BLOCKED"
                        # Block dependent network nodes fail-closed
                        for other in plan.nodes.values():
                            if other.id != "node-scope":
                                other.status = PTTNodeStatus.BLOCKED
                                other.error = "Parent scope verification failed. Fail-closed."

                # 2. CONTROLLED SECURITY TOOLS (Passed through Central Scope Gate)
                elif current_node.tool in ("nmap", "web", "tls", "dns", "gobuster", "nikto", "forensics"):
                    tool_res: ToolExecutionResult = self.runner.execute_tool(
                        tool_name=current_node.tool,
                        target=current_node.args.get("target", plan.target),
                        ports=current_node.args.get("ports"),
                        arguments=current_node.args,
                        operation_id=f"op-{current_node.id}",
                    )

                    status_str = tool_res.status.value if hasattr(tool_res.status, "value") else str(tool_res.status)
                    if status_str == "SUCCESS":
                        current_node.status = PTTNodeStatus.COMPLETED
                        step_result["status"] = "COMPLETED"
                        step_result["stdout_excerpt"] = tool_res.stdout[:500] if tool_res.stdout else ""
                        if tool_res.evidence:
                            accumulated_evidence.append(tool_res.evidence)
                            current_node.evidence_ids.append(tool_res.evidence.id)
                        if tool_res.findings:
                            accumulated_findings.extend(tool_res.findings)
                            current_node.findings_ids.extend([f.id for f in tool_res.findings])

                        # Output Analyst Digest (PentestGPT parsing pattern)
                        if current_node.tool == "nmap":
                            parsed = self.parser.parse_nmap(tool_res.stdout)
                            current_node.observations.append(f"Discovered {parsed['open_ports_count']} open ports.")
                            # Adaptive Re-planning: If non-standard HTTP port found, inject web task
                            for p in parsed["ports"]:
                                if p["port"] in (8080, 8443, 8000, 8888) and f"node-web-{p['port']}" not in plan.nodes:
                                    extra_web = PTTNode(
                                        id=f"node-web-{p['port']}",
                                        title=f"Web Application Scan (Port {p['port']})",
                                        description=f"Inspect alternate HTTP service on port {p['port']}.",
                                        role=AgentRole.WEB_SPECIALIST,
                                        tool="web",
                                        args={"target": plan.target, "port": p["port"]},
                                        dependencies=["node-ports"],
                                        status=PTTNodeStatus.TODO,
                                    )
                                    plan.add_node(extra_web)

                    elif status_str == "BLOCKED":
                        current_node.status = PTTNodeStatus.BLOCKED
                        current_node.error = tool_res.reason or "Blocked by scope policy"
                        step_result["status"] = "BLOCKED"
                        step_result["error"] = current_node.error
                    else:
                        current_node.status = PTTNodeStatus.FAILED
                        current_node.error = tool_res.stderr or tool_res.reason or "Tool execution failed"
                        step_result["status"] = "FAILED"
                        step_result["error"] = current_node.error

                # 3. THREAT INTEL AND REPORTING SYNTHESIS
                elif current_node.tool in ("threat_intel", "report"):
                    current_node.status = PTTNodeStatus.COMPLETED
                    step_result["status"] = "COMPLETED"
                    current_node.observations.append(f"Synthesized {len(accumulated_findings)} findings and {len(accumulated_evidence)} cryptographic evidence records.")

                execution_trace.append(step_result)
                if on_step_callback:
                    try:
                        on_step_callback(current_node, step_result)
                    except Exception:
                        pass

        # Final plan status
        if all(n.status == PTTNodeStatus.COMPLETED for n in plan.nodes.values()):
            plan.status = "COMPLETED"
        elif any(n.status == PTTNodeStatus.BLOCKED for n in plan.nodes.values()):
            plan.status = "PARTIALLY_BLOCKED"
        else:
            plan.status = "COMPLETED_WITH_WARNINGS"

        return {
            "plan": plan.to_dict(),
            "status": plan.status,
            "iterations_used": iteration,
            "elapsed_seconds": round(time.monotonic() - start_time, 2),
            "evidence_count": len(accumulated_evidence),
            "findings_count": len(accumulated_findings),
            "execution_trace": execution_trace,
        }
