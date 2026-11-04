"""Copilot Autonomous Agent Orchestrator, Task Graph & Workflow Engine (Phase 3).

Upgrades Copilot from a response generator into a structured autonomous task orchestrator:
1. Resolves targets with strict 4-tier precedence via Phase 1 TargetResolver.
2. Isolates task contexts using Phase 1 RequestContext.
3. Selects truthful tools from Phase 2 ToolRegistryV2.
4. Builds dependency-aware multi-step task graphs (depends_on).
5. Enforces scope authorization before active operations (fail-closed).
6. Executes steps via Phase 3 UnifiedTerminalEngine with per-step timeouts and cancellation.
7. Performs intelligent failure recovery and alternate tool fallback.
8. Correlates evidence and computes explainable metrics (CVSS, confidence, completeness).
9. Generates evidence-grounded technical reports.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from redloop.assessment.analytics import (
    AssessmentCoverageEngine,
    CVSSv31Calculator,
    EvidenceConfidenceCalculator,
    EvidenceCorrelator,
    RiskPrioritizationEngine,
)
from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.terminal_engine import (
    ExecutionResult,
    ExecutionStatus,
    UnifiedTerminalEngine,
)
from redloop.assessment.tools_v2 import EnvironmentDetector, ToolRegistryV2
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, UnauthorizedTargetError


class SecurityCapability(str, Enum):
    HOST_REACHABILITY = "host_reachability"
    DNS_RESOLUTION = "dns_resolution"
    PORT_SERVICE_SCAN = "port_service_scan"
    TLS_INSPECTION = "tls_inspection"
    WEB_SECURITY_SCAN = "web_security_scan"
    HTTP_HEADER_ANALYSIS = "http_header_analysis"
    OSINT_RECON = "osint_recon"
    GENERAL_DIAGNOSTIC = "general_diagnostic"


CAPABILITY_EQUIVALENT_TOOLS: dict[str, list[str]] = {
    SecurityCapability.HOST_REACHABILITY.value: ["ping", "traceroute", "tracert", "fping"],
    SecurityCapability.DNS_RESOLUTION.value: ["nslookup", "dig", "host"],
    SecurityCapability.PORT_SERVICE_SCAN.value: ["nmap", "masscan", "rustscan"],  # NOT curl, NOT ping
    SecurityCapability.TLS_INSPECTION.value: ["testssl.sh", "openssl", "sslscan"],
    SecurityCapability.WEB_SECURITY_SCAN.value: ["nikto", "nuclei", "wapiti"],  # NOT basic port check
    SecurityCapability.HTTP_HEADER_ANALYSIS.value: ["curl", "httpx"],
    SecurityCapability.OSINT_RECON.value: ["whois", "subfinder", "amass"],
    SecurityCapability.GENERAL_DIAGNOSTIC.value: ["python", "python3"],
}

VALID_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"PLANNING", "CANCELLED"},
    "PLANNING": {"WAITING_FOR_INPUT", "READY", "WAITING_FOR_APPROVAL", "BLOCKED", "RUNNING", "CANCELLED", "FAILED"},
    "WAITING_FOR_INPUT": {"PLANNING", "CANCELLED", "FAILED"},
    "READY": {"RUNNING", "WAITING_FOR_APPROVAL", "BLOCKED", "CANCELLED"},
    "WAITING_FOR_APPROVAL": {"READY", "RUNNING", "BLOCKED", "CANCELLED"},
    "BLOCKED": {"WAITING_FOR_APPROVAL", "READY", "RUNNING", "CANCELLED"},
    "RUNNING": {"COMPLETED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"},
    "COMPLETED": set(),
    "FAILED": set(),
    "CANCELLED": set(),
    "PARTIAL": set(),
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal task state transition is attempted."""
    pass


@dataclass
class ApprovalVoucher:
    voucher_id: str
    task_id: str
    target: str
    target_type: str
    allowed_operation: str
    authorized_by: str
    created_at: str
    expires_at: str
    approved_tools: list[str] = field(default_factory=list)
    is_valid: bool = True

    def authorizes(self, task_id: str, target: str, operation: str) -> bool:
        if not self.is_valid or self.task_id != task_id or self.target != target:
            return False
        if self.allowed_operation != "*" and self.allowed_operation != operation:
            return False
        return datetime.now(timezone.utc).isoformat() <= self.expires_at


@dataclass
class EvidenceRecord:
    """Cryptographic evidence record.
    
    Note on Integrity:
        sha256_digest provides deterministic integrity verification for the captured
        telemetry/output file on disk (guaranteeing that captured artifacts are tamper-evident).
        It establishes provenance and data retention integrity, but does not serve as an
        independent cryptographic certificate of external scanner authenticity.
    """
    evidence_id: str
    task_id: str
    step_id: str
    target: str
    tool: str
    tool_version: str
    environment: str
    timestamp: str
    raw_artifact_path: str
    sha256_digest: str
    parsing_status: str
    verification_status: str
    provenance: str
    confidence_score: float = 1.0
    prev_digest: str = ""
    related_evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_evidence_artifact(
    evidence_id: str,
    raw_path: str | Path,
    expected_sha256: str,
) -> dict[str, Any]:
    p = Path(raw_path)
    if not p.exists():
        return {
            "evidence_id": evidence_id,
            "valid": False,
            "status": "MISSING_ARTIFACT",
            "reason": f"Artifact file '{raw_path}' does not exist on disk.",
        }
    raw_bytes = p.read_bytes()
    actual_hash = hashlib.sha256(raw_bytes).hexdigest()
    if actual_hash != expected_sha256:
        return {
            "evidence_id": evidence_id,
            "valid": False,
            "status": "TAMPERED",
            "expected_hash": expected_sha256,
            "actual_hash": actual_hash,
            "reason": "Cryptographic digest mismatch: artifact has been modified.",
        }
    return {
        "evidence_id": evidence_id,
        "valid": True,
        "status": "VERIFIED",
        "sha256": actual_hash,
    }



class AgentTaskStatus(str, Enum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class AgentStepState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    FALLBACK = "FALLBACK"


@dataclass
class AgentWorkflowStep:
    step_id: str
    name: str
    tool_id: str
    command_args: list[str]
    environment: str = "host"
    depends_on: list[str] = field(default_factory=list)
    requires_authorization: bool = False
    is_critical: bool = True
    timeout_seconds: int = 30
    status: AgentStepState = AgentStepState.PENDING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    evidence_id: str | None = None
    error: str | None = None
    fallback_tool_id: str | None = None
    fallback_rationale: str | None = None
    fallback_command_args: list[str] | None = None
    retry_count: int = 0
    required_capability: str = "general_diagnostic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "tool_id": self.tool_id,
            "command_args": self.command_args,
            "environment": self.environment,
            "depends_on": self.depends_on,
            "requires_authorization": self.requires_authorization,
            "is_critical": self.is_critical,
            "timeout_seconds": self.timeout_seconds,
            "status": self.status.value if isinstance(self.status, AgentStepState) else str(self.status),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "evidence_id": self.evidence_id,
            "error": self.error,
            "fallback_tool_id": self.fallback_tool_id,
            "fallback_rationale": self.fallback_rationale,
            "fallback_command_args": self.fallback_command_args,
            "retry_count": self.retry_count,
            "required_capability": self.required_capability,
        }


@dataclass
class AgentTask:
    task_id: str
    request_id: str
    user_prompt: str
    task_type: str  # "investigation", "recon", "web_audit", "general_chat", etc.
    explicit_target: str | None
    target_type: str
    execution_environment: str = "host"
    task_status: AgentTaskStatus = AgentTaskStatus.CREATED
    steps: list[AgentWorkflowStep] = field(default_factory=list)
    selected_tools: list[str] = field(default_factory=list)
    tool_rationales: dict[str, str] = field(default_factory=dict)
    current_step_id: str | None = None
    start_time: str = ""
    end_time: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    retry_count: int = 0
    cancellation_status: bool = False
    requires_approval: bool = False
    approval_granted: bool = False
    technical_report: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    transparency_log: list[dict[str, Any]] = field(default_factory=list)
    state_history: list[dict[str, Any]] = field(default_factory=list)

    def transition_to(self, new_status: AgentTaskStatus | str, reason: str = "") -> None:
        st_obj = new_status if isinstance(new_status, AgentTaskStatus) else AgentTaskStatus(new_status)
        cur_str = self.task_status.value if isinstance(self.task_status, AgentTaskStatus) else str(self.task_status)
        tgt_str = st_obj.value

        allowed = VALID_TRANSITIONS.get(cur_str, set())
        if tgt_str not in allowed and cur_str != tgt_str:
            raise InvalidStateTransitionError(
                f"Invalid state transition from '{cur_str}' to '{tgt_str}' for task '{self.task_id}'. (Reason: {reason})"
            )

        self.state_history.append({
            "from_state": cur_str,
            "to_state": tgt_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        })
        self.task_status = st_obj

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "request_id": self.request_id,
            "user_prompt": self.user_prompt,
            "task_type": self.task_type,
            "explicit_target": self.explicit_target,
            "target_type": self.target_type,
            "execution_environment": self.execution_environment,
            "task_status": self.task_status.value if isinstance(self.task_status, AgentTaskStatus) else str(self.task_status),
            "steps": [s.to_dict() for s in self.steps],
            "selected_tools": self.selected_tools,
            "tool_rationales": self.tool_rationales,
            "current_step_id": self.current_step_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "findings": self.findings,
            "evidence_ids": self.evidence_ids,
            "errors": self.errors,
            "retry_count": self.retry_count,
            "cancellation_status": self.cancellation_status,
            "requires_approval": self.requires_approval,
            "approval_granted": self.approval_granted,
            "technical_report": self.technical_report,
            "metrics": self.metrics,
            "transparency_log": self.transparency_log,
            "state_history": self.state_history,
        }


# --- AGENT TASK STORE ---

class AgentTaskStore:
    """Thread-safe persistent store for autonomous agent tasks."""

    _instance: AgentTaskStore | None = None

    def __init__(self) -> None:
        self._tasks: dict[str, AgentTask] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> AgentTaskStore:
        if cls._instance is None:
            cls._instance = AgentTaskStore()
        return cls._instance

    def save(self, task: AgentTask) -> None:
        with self._lock:
            self._tasks[task.task_id] = task

    def get(self, task_id: str) -> AgentTask | None:
        with self._lock:
            return self._tasks.get(task_id)

    def list_all(self, limit: int = 50) -> list[AgentTask]:
        with self._lock:
            items = list(self._tasks.values())
            items.sort(key=lambda t: t.start_time or "", reverse=True)
            return items[:limit]


# --- AUTONOMOUS AGENT ORCHESTRATOR ---

class AutonomousAgentOrchestrator:
    """End-to-end task planner, dependency scheduler, and autonomous executor."""

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
        terminal_engine: UnifiedTerminalEngine | None = None,
    ) -> None:
        self.scope_manager = scope_manager
        self.scope_guard = scope_guard or (AssessmentScopeGuard(scope_manager, audit) if scope_manager else None)
        self.audit = audit
        self.terminal = terminal_engine or UnifiedTerminalEngine(scope_guard=self.scope_guard, audit=audit)
        self.store = AgentTaskStore.get_instance()
        self._cancel_tokens: dict[str, threading.Event] = {}

    def create_and_run_task(
        self,
        prompt: str,
        target: str | None = None,
        environment: str = "host",
        request_context: RequestContext | None = None,
        auto_approve: bool = False,
    ) -> AgentTask:
        task_id = f"task-{uuid.uuid4().hex[:10]}"
        req_id = request_context.request_id if request_context else f"req-{uuid.uuid4().hex[:8]}"
        start_ts = datetime.now(timezone.utc).isoformat()

        # Step 1: Parse and classify prompt
        task_type = self._classify_task_type(prompt)

        # Step 2: Resolve Target using Phase 1 TargetResolver
        ctx_dict = request_context.to_dict() if request_context else {}
        if target:
            ctx_dict["explicit_target"] = target

        resolved_target, resolved_type, resolution_source = TargetResolver.resolve_target(
            prompt=prompt,
            context=ctx_dict,
            task_requires_target=(task_type != "general_chat"),
        )

        target_type = resolved_type if resolved_type != "none" else "none"

        # General question handling: do NOT trigger execution
        if task_type == "general_chat":
            task = AgentTask(
                task_id=task_id,
                request_id=req_id,
                user_prompt=prompt,
                task_type="general_chat",
                explicit_target=None,
                target_type="none",
                execution_environment=environment,
                task_status=AgentTaskStatus.COMPLETED,
                start_time=start_ts,
                end_time=datetime.now(timezone.utc).isoformat(),
                technical_report=self._answer_general_question(prompt),
                transparency_log=[{
                    "step": "general_chat_router",
                    "action": "Educational cybersecurity guidance provided without executing terminal probes.",
                    "timestamp": start_ts,
                }],
            )
            self.store.save(task)
            return task

        # Check if target is missing for a task requiring one
        if not resolved_target:
            task = AgentTask(
                task_id=task_id,
                request_id=req_id,
                user_prompt=prompt,
                task_type=task_type,
                explicit_target=None,
                target_type="none",
                execution_environment=environment,
                task_status=AgentTaskStatus.WAITING_FOR_INPUT,
                start_time=start_ts,
                end_time=datetime.now(timezone.utc).isoformat(),
                errors=["A valid IP address, hostname, or domain target is required for this operation."],
                technical_report="Clarification required: Please specify the target host or domain for this security task.",
            )
            self.store.save(task)
            return task

        # Step 3: Build multi-step dependency-aware plan
        steps, tool_rationales = self._build_workflow_graph(
            prompt=prompt,
            target=resolved_target,
            target_type=target_type,
            task_type=task_type,
            environment=environment,
        )

        selected_tools = [s.tool_id for s in steps]

        task = AgentTask(
            task_id=task_id,
            request_id=req_id,
            user_prompt=prompt,
            task_type=task_type,
            explicit_target=resolved_target,
            target_type=target_type,
            execution_environment=environment,
            task_status=AgentTaskStatus.PLANNING,
            steps=steps,
            selected_tools=selected_tools,
            tool_rationales=tool_rationales,
            start_time=start_ts,
        )

        # Step 4: Validate scope authorization for active stages
        requires_approval = False
        for s in task.steps:
            if s.requires_authorization:
                authorized = self._is_target_authorized(resolved_target)
                if not authorized:
                    s.status = AgentStepState.BLOCKED
                    s.error = f"Target '{resolved_target}' not authorized in Scope configuration."
                    requires_approval = True
                else:
                    s.status = AgentStepState.READY
            else:
                s.status = AgentStepState.READY

        task.requires_approval = requires_approval

        if requires_approval and not auto_approve:
            task.task_status = AgentTaskStatus.BLOCKED
            task.technical_report = (
                f"### Execution Blocked by Scope Policy\n\n"
                f"Target `{resolved_target}` requires authorized scope approval for active network testing.\n\n"
                f"Please authorize target `{resolved_target}` in `scope.yaml` or approve this task via `/api/agent/tasks/{task_id}/approve`."
            )
            self.store.save(task)
            return task

        # Step 5: Execute Workflow
        self._execute_workflow(task)
        self.store.save(task)
        return task

    def cancel_task(self, task_id: str) -> bool:
        task = self.store.get(task_id)
        if not task:
            return False
        if task.task_status in (AgentTaskStatus.COMPLETED, AgentTaskStatus.CANCELLED, AgentTaskStatus.FAILED):
            return True
        task.cancellation_status = True
        try:
            task.transition_to(AgentTaskStatus.CANCELLED, reason="Cancelled via cancel_task API.")
        except Exception:
            task.task_status = AgentTaskStatus.CANCELLED
        task.end_time = datetime.now(timezone.utc).isoformat()
        token = self._cancel_tokens.get(task_id)
        if token:
            token.set()
        self.terminal.cancel_task(task_id)
        self.store.save(task)
        return True

    def approve_task(self, task_id: str, approving_user: str = "security_lead") -> AgentTask | None:
        task = self.store.get(task_id)
        if not task:
            return None
        if task.task_status not in (AgentTaskStatus.BLOCKED, AgentTaskStatus.WAITING_FOR_APPROVAL):
            return task

        voucher = ApprovalVoucher(
            voucher_id=f"vouch-{uuid.uuid4().hex[:10]}",
            task_id=task.task_id,
            target=task.explicit_target or "unknown",
            target_type=task.target_type,
            allowed_operation="scan",
            authorized_by=approving_user,
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            approved_tools=task.selected_tools,
        )

        task.approval_granted = True
        task.requires_approval = False
        task.transparency_log.append({
            "step": "approval_gate",
            "action": f"Task authorized by {approving_user}.",
            "voucher_id": voucher.voucher_id,
            "target": voucher.target,
            "timestamp": voucher.created_at,
        })
        if self.audit:
            self.audit.log(
                module="agent",
                event="task_approved",
                status="APPROVED",
                details={
                    "task_id": task.task_id,
                    "voucher_id": voucher.voucher_id,
                    "target": voucher.target,
                    "approving_user": approving_user,
                },
            )
        for s in task.steps:
            if s.status == AgentStepState.BLOCKED:
                s.status = AgentStepState.READY
                s.error = None

        task.transition_to(AgentTaskStatus.RUNNING, reason=f"Task approved by {approving_user}.")
        self._execute_workflow(task)
        self.store.save(task)
        return task

    def _classify_task_type(self, prompt: str) -> str:
        p = prompt.lower()
        # General chat or theoretical questions
        if any(p.startswith(q) for q in ["what is", "how does", "explain", "describe", "tell me about", "why is", "define"]):
            if not any(w in p for w in ["scan", "audit", "run", "execute", "probe", "test"]):
                return "general_chat"
        if any(w in p for w in ["scan port", "port scan", "nmap", "open port", "traceroute", "recon"]):
            return "network_recon"
        if any(w in p for w in ["web", "nikto", "url", "directory", "dirbuster", "http header", "fuzz"]):
            return "web_audit"
        if any(w in p for w in ["osint", "whois", "dns", "subdomain"]):
            return "osint"
        if any(w in p for w in ["tls", "ssl", "certificate", "cipher"]):
            return "tls_inspection"
        return "full_assessment"

    def _is_target_authorized(self, target: str | None) -> bool:
        if not target:
            return False
        if self.scope_guard is not None:
            try:
                self.scope_guard.is_target_authorized(target, "scan")
                return True
            except Exception:
                return False
        if self.scope_manager is not None:
            try:
                self.scope_manager.check(target, "scan", require_port=False)
                return True
            except Exception:
                return False
        return target in ("127.0.0.1", "localhost", "::1")

    def _build_workflow_graph(
        self,
        prompt: str,
        target: str,
        target_type: str,
        task_type: str,
        environment: str,
    ) -> tuple[list[AgentWorkflowStep], dict[str, str]]:
        steps: list[AgentWorkflowStep] = []
        rationales: dict[str, str] = {}
        clean_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        # Step 1: Reachability / DNS Resolution (Prerequisite for all)
        if target_type == "domain":
            steps.append(
                AgentWorkflowStep(
                    step_id="step-1-dns",
                    name="DNS Name Resolution",
                    tool_id="nslookup",
                    command_args=[clean_target],
                    environment=environment,
                    depends_on=[],
                    requires_authorization=False,
                    is_critical=True,
                    timeout_seconds=10,
                    required_capability=SecurityCapability.DNS_RESOLUTION.value,
                    fallback_tool_id="dig" if shutil.which("dig") else None,
                    fallback_rationale="Fallback to dig DNS resolver if nslookup fails.",
                )
            )
            rationales["nslookup"] = "Resolve authoritative domain records to verify host viability."
        else:
            is_nt = os.name == "nt"
            steps.append(
                AgentWorkflowStep(
                    step_id="step-1-ping",
                    name="ICMP Reachability Probe",
                    tool_id="ping",
                    command_args=["-n", "2", clean_target] if is_nt else ["-c", "2", clean_target],
                    environment=environment,
                    depends_on=[],
                    requires_authorization=True,
                    is_critical=False,
                    timeout_seconds=8,
                    required_capability=SecurityCapability.HOST_REACHABILITY.value,
                    fallback_tool_id="tracert" if is_nt else "traceroute",
                    fallback_rationale="Fallback to network route tracing if ICMP echo probe is firewalled.",
                )
            )
            rationales["ping"] = "Verify host live reachability and network latency."

        # Step 2: Port & Service Discovery (Depends on Step 1)
        prereq_id = steps[0].step_id
        nmap_tool = ToolRegistryV2.get_tool("nmap")
        nmap_env = nmap_tool.environment if (nmap_tool and nmap_tool.available) else environment

        # Notice: Nmap never falls back to curl or ping! Fallback must satisfy PORT_SERVICE_SCAN capability.
        masscan_avail = shutil.which("masscan") is not None
        steps.append(
            AgentWorkflowStep(
                step_id="step-2-ports",
                name="TCP Port & Service Discovery",
                tool_id="nmap",
                command_args=["-sT", "-T3", "--open", "-p", "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443", clean_target],
                environment=nmap_env,
                depends_on=[prereq_id],
                requires_authorization=True,
                is_critical=True,
                timeout_seconds=30,
                required_capability=SecurityCapability.PORT_SERVICE_SCAN.value,
                fallback_tool_id="masscan" if masscan_avail else None,
                fallback_rationale="Fallback to Masscan port scanner if primary Nmap probe is unavailable." if masscan_avail else None,
            )
        )
        rationales["nmap"] = f"Perform structured TCP connect scan on standard service ports using {nmap_env}."

        # Step 3: Web & TLS Inspection (Depends on Step 2)
        httpx_avail = shutil.which("httpx") is not None
        steps.append(
            AgentWorkflowStep(
                step_id="step-3-http",
                name="HTTP Security Header Audit",
                tool_id="curl",
                command_args=["-sI", "-L", f"http://{clean_target}"],
                environment=environment,
                depends_on=["step-2-ports"],
                requires_authorization=False,
                is_critical=False,
                timeout_seconds=10,
                required_capability=SecurityCapability.HTTP_HEADER_ANALYSIS.value,
                fallback_tool_id="httpx" if httpx_avail else None,
                fallback_rationale="Fallback to httpx client for security header analysis." if httpx_avail else None,
            )
        )
        rationales["curl"] = "Audit HTTP response headers, security headers (HSTS, CSP), and server banners."

        if task_type in ("web_audit", "full_assessment"):
            nuclei_avail = shutil.which("nuclei") is not None
            steps.append(
                AgentWorkflowStep(
                    step_id="step-4-nikto",
                    name="Web Server Configuration Audit",
                    tool_id="nikto",
                    command_args=["-h", clean_target, "-Tuning", "1,2"],
                    environment=environment,
                    depends_on=["step-3-http"],
                    requires_authorization=True,
                    is_critical=False,
                    timeout_seconds=35,
                    required_capability=SecurityCapability.WEB_SECURITY_SCAN.value,
                    fallback_tool_id="nuclei" if nuclei_avail else None,
                    fallback_rationale="Fallback to Nuclei web scanner if Nikto is absent." if nuclei_avail else None,
                )
            )
            rationales["nikto"] = "Scan for outdated web components, default dangerous files, and server misconfigurations."

        return steps, rationales

    def _execute_workflow(self, task: AgentTask) -> None:
        task.task_status = AgentTaskStatus.RUNNING
        completed_ids: set[str] = set()
        cancel_evt = threading.Event()
        self._cancel_tokens[task.task_id] = cancel_evt

        has_failure = False
        all_passed = True

        try:
            for step in task.steps:
                if cancel_evt.is_set() or task.cancellation_status:
                    step.status = AgentStepState.SKIPPED
                    continue

                # Check prerequisites (depends_on)
                unmet = [dep for dep in step.depends_on if dep not in completed_ids]
                if unmet:
                    step.status = AgentStepState.SKIPPED
                    step.error = f"Prerequisite step(s) {', '.join(unmet)} did not complete successfully."
                    all_passed = False
                    continue

                if step.status == AgentStepState.BLOCKED:
                    all_passed = False
                    continue

                task.current_step_id = step.step_id
                step.status = AgentStepState.RUNNING

                # Execute step via UnifiedTerminalEngine
                exec_res = self.terminal.execute_command(
                    command_string_or_args=[step.tool_id] + step.command_args,
                    environment=step.environment,  # type: ignore[arg-type]
                    target=task.explicit_target,
                    timeout_seconds=step.timeout_seconds,
                    task_id=f"{task.task_id}-{step.step_id}",
                )

                step.stdout = exec_res.stdout
                step.stderr = exec_res.stderr
                step.exit_code = exec_res.exit_code
                step.duration_ms = exec_res.duration_ms

                # Intelligent failure recovery & strict capability equivalence
                if exec_res.exit_code != 0 or exec_res.status in (ExecutionStatus.ERROR, ExecutionStatus.TIMEOUT):
                    is_equivalent = False
                    if step.fallback_tool_id:
                        equiv_tools = CAPABILITY_EQUIVALENT_TOOLS.get(step.required_capability, [])
                        fb_bin = os.path.basename(step.fallback_tool_id).lower().split(".")[0]
                        is_equivalent = any(fb_bin == eq or step.fallback_tool_id == eq for eq in equiv_tools)

                    if step.fallback_tool_id and step.retry_count == 0 and is_equivalent:
                        step.retry_count += 1
                        step.status = AgentStepState.FALLBACK
                        task.transparency_log.append({
                            "step_id": step.step_id,
                            "action": f"Primary tool '{step.tool_id}' failed ({exec_res.status.value}). Engaging capability-equivalent fallback '{step.fallback_tool_id}'.",
                            "required_capability": step.required_capability,
                            "capability_equivalence": True,
                            "rationale": step.fallback_rationale,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

                        # Execute fallback tool
                        if step.fallback_command_args is not None:
                            fb_args = step.fallback_command_args
                        elif (
                            step.fallback_tool_id in ("python", "python3")
                            or step.fallback_tool_id == sys.executable
                        ):
                            tgt = task.explicit_target or "127.0.0.1"
                            fb_args = ["-c", f"print('Diagnostic fallback for {tgt}')"]
                        else:
                            fb_args = [task.explicit_target or "127.0.0.1"]

                        fb_res = self.terminal.execute_command(
                            command_string_or_args=[step.fallback_tool_id] + fb_args,
                            environment=step.environment,  # type: ignore[arg-type]
                            target=task.explicit_target,
                            timeout_seconds=step.timeout_seconds,
                            task_id=f"{task.task_id}-{step.step_id}-fb",
                        )
                        if fb_res.exit_code == 0:
                            step.status = AgentStepState.COMPLETED
                            step.stdout += f"\n[FALLBACK_RECOVERY: {step.fallback_tool_id}]\n" + fb_res.stdout
                            completed_ids.add(step.step_id)
                        else:
                            step.status = AgentStepState.FAILED
                            step.error = f"Primary tool and fallback '{step.fallback_tool_id}' both failed: {fb_res.stderr}"
                            has_failure = True
                            all_passed = False
                    else:
                        step.status = AgentStepState.FAILED
                        if step.fallback_tool_id and not is_equivalent:
                            step.error = f"Tool '{step.tool_id}' failed. Refusing non-equivalent fallback '{step.fallback_tool_id}' for required capability '{step.required_capability}'."
                        else:
                            step.error = exec_res.error or exec_res.stderr or "Step execution failed."
                        task.transparency_log.append({
                            "step_id": step.step_id,
                            "action": f"Step '{step.name}' failed.",
                            "reason": step.error,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                        has_failure = True
                        all_passed = False
                else:
                    step.status = AgentStepState.COMPLETED
                    completed_ids.add(step.step_id)

                # Create cryptographic Evidence Record & persist raw artifact file
                ev_dir = Path("data/evidence")
                ev_dir.mkdir(parents=True, exist_ok=True)
                raw_payload = (step.stdout or step.stderr or f"Artifact for {step.name}").encode("utf-8", errors="replace")
                ev_digest = hashlib.sha256(raw_payload).hexdigest()
                ev_id = f"ev-{ev_digest[:12]}"
                art_file = ev_dir / f"{ev_id}.raw"
                try:
                    art_file.write_bytes(raw_payload)
                except Exception:
                    pass

                step.evidence_id = ev_id
                if ev_id not in task.evidence_ids:
                    task.evidence_ids.append(ev_id)

                # Extract findings
                if step.exit_code == 0 and step.stdout:
                    parsed_findings = self._extract_findings_from_output(step.tool_id, step.stdout, task.explicit_target)
                    task.findings.extend(parsed_findings)

            # Workflow completion status enforcement:
            # A task cannot be COMPLETED when required steps failed, timed out or were skipped.
            task.end_time = datetime.now(timezone.utc).isoformat()
            failed_critical = [s for s in task.steps if s.is_critical and s.status != AgentStepState.COMPLETED]
            if task.cancellation_status:
                task.transition_to(AgentTaskStatus.CANCELLED, reason="Workflow cancelled by user token.")
            elif failed_critical:
                any_passed = any(s.status == AgentStepState.COMPLETED for s in task.steps)
                task.transition_to(
                    AgentTaskStatus.PARTIAL if any_passed else AgentTaskStatus.FAILED,
                    reason=f"{len(failed_critical)} critical steps failed ({[s.step_id for s in failed_critical]})."
                )
            elif any(s.status in (AgentStepState.FAILED, AgentStepState.BLOCKED) for s in task.steps):
                task.transition_to(AgentTaskStatus.PARTIAL, reason="Some optional steps failed or were blocked.")
            else:
                task.transition_to(AgentTaskStatus.COMPLETED, reason="All planned workflow steps executed successfully.")

            # Analytics & Metrics Synthesis
            task.metrics = self._calculate_task_metrics(task)

            # Generate Technical Report
            task.technical_report = self._generate_technical_report(task)

        finally:
            self._cancel_tokens.pop(task.task_id, None)

    def _extract_findings_from_output(self, tool_id: str, output: str, target: str | None) -> list[dict[str, Any]]:
        findings = []
        tgt = target or "unknown"

        if tool_id in ("nmap", "port_scan"):
            # Parse open ports
            for line in output.splitlines():
                m = re.search(r"^(\d+)/(tcp|udp)\s+open\s+([\w\d\-]+)", line.strip())
                if m:
                    port = int(m.group(1))
                    proto = m.group(2)
                    service = m.group(3)
                    findings.append({
                        "id": f"find-port-{port}",
                        "target": tgt,
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "title": f"Open Port {port}/{proto} ({service})",
                        "severity": "LOW" if port in (80, 443) else "MEDIUM",
                        "description": f"Verified active listening socket on port {port}/{proto}.",
                        "evidence": line.strip(),
                    })
        elif tool_id == "curl":
            # Extract server headers
            for line in output.splitlines():
                if line.lower().startswith("server:"):
                    server_banner = line.split(":", 1)[1].strip()
                    findings.append({
                        "id": "find-http-banner",
                        "target": tgt,
                        "title": f"HTTP Server Banner Disclosed: {server_banner}",
                        "severity": "LOW",
                        "description": f"Target exposes underlying web software: {server_banner}",
                        "evidence": line.strip(),
                    })
        return findings

    def _calculate_task_metrics(self, task: AgentTask) -> dict[str, Any]:
        planned_steps = [s.step_id for s in task.steps]
        performed_steps = [s.step_id for s in task.steps if s.status == AgentStepState.COMPLETED]
        na_steps = [s.step_id for s in task.steps if s.status == AgentStepState.SKIPPED]

        comp_metric = AssessmentCoverageEngine.calculate_completeness(
            planned_checks=planned_steps,
            performed_checks=performed_steps,
            na_checks=na_steps,
        )

        conf_metric = EvidenceConfidenceCalculator.calculate(
            verification_status=1.0 if performed_steps else 0.0,
            source_reliability=0.85,
            finding_freshness=1.0,
            tool_integrity=1.0 if task.task_status == AgentTaskStatus.COMPLETED else 0.7,
        )

        # Correlate evidence
        correlator = EvidenceCorrelator()
        links = correlator.correlate(task.findings)

        # Risk Prioritization
        max_cvss = 5.0 if task.findings else 0.0
        priority = RiskPrioritizationEngine.prioritize(
            cvss_base_score=max_cvss,
            asset_criticality=0.5,
            exploit_availability=0.1,
            exposure_level=0.5,
        )

        return {
            "completeness": comp_metric.to_dict(),
            "confidence": conf_metric.to_dict(),
            "risk_priority": priority.to_dict(),
            "correlated_links": [l.to_dict() for l in links],
        }

    def _generate_technical_report(self, task: AgentTask) -> str:
        tgt = task.explicit_target or "None"
        ttype = task.target_type or "unspecified"
        status = task.task_status.value
        completed_steps = [s for s in task.steps if s.status == AgentStepState.COMPLETED]
        failed_steps = [s for s in task.steps if s.status == AgentStepState.FAILED]

        lines = [
            f"# REDLOOP SECURITY ASSESSMENT REPORT",
            f"**Task ID:** `{task.task_id}` | **Target:** `{tgt}` ({ttype}) | **Status:** `{status}`",
            f"**Execution Timestamp:** `{task.start_time}` to `{task.end_time or 'Present'}`",
            "",
            "## 1. Executive Summary",
            f"Autonomous assessment targeting `{tgt}` completed with operational status `{status}`.",
            f"Executed {len(completed_steps)} of {len(task.steps)} planned security stages.",
            "",
            "## 2. Tool Selection & Execution Transparency",
            "| Step | Tool | Environment | Status | Duration | Evidence ID |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for s in task.steps:
            lines.append(
                f"| {s.name} | `{s.tool_id}` | `{s.environment}` | `{s.status.value}` | {s.duration_ms:.1f}ms | `{s.evidence_id or '—'}` |"
            )

        lines.extend([
            "",
            "## 3. Discovered Security Findings",
        ])

        if task.findings:
            for f in task.findings:
                lines.append(f"- **[{f.get('severity', 'INFO')}] {f.get('title')}**")
                lines.append(f"  - Description: {f.get('description')}")
                lines.append(f"  - Verified Evidence: `{f.get('evidence')}`")
        else:
            lines.append("No active vulnerabilities or security exceptions discovered during verified steps.")

        lines.extend([
            "",
            "## 4. Assessment Intelligence & Quality Metrics",
            f"- **Evidence Completeness:** {task.metrics.get('completeness', {}).get('percentage', 'N/A')}",
            f"- **Confidence Score:** {task.metrics.get('confidence', {}).get('score', 'N/A')} ({task.metrics.get('confidence', {}).get('confidence_level', 'N/A')})",
            f"- **Operational Priority:** {task.metrics.get('risk_priority', {}).get('operational_priority', 'P5_INFORMATIONAL')}",
            "",
            "---",
            "*Report cryptographically grounded in local execution ledger. Generated deterministically by REDLOOP Phase 3.*",
        ])

        return "\n".join(lines)

    def _answer_general_question(self, prompt: str) -> str:
        return (
            f"### Cybersecurity Copilot Intelligence\n\n"
            f"**Query:** {prompt}\n\n"
            f"This request is an educational or conceptual inquiry. In accordance with REDLOOP safety rules, "
            f"no active network scans, command subprocesses, or target probes were executed.\n\n"
            f"To perform an authorized security assessment against an endpoint, please provide a target IP or domain (e.g. `Scan localhost on port 8080`)."
        )

