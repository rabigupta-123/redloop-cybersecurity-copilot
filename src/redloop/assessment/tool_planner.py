"""Autonomous Tool Selection Engine & Planning Layer (Phase 2).

Provides goal-oriented, autonomous tool planning:
- Interprets user cybersecurity intent from natural language prompts
- Resolves targets via Phase 1 TargetResolver with strict precedence & validation
- Discovers capabilities via ToolRegistryV2 and EnvironmentDetector
- Checks scope authorization before scheduling active probes
- Validates argument safety (shell=False)
- Tracks stage states: PLANNED, READY, RUNNING, COMPLETED, PARTIAL, FAILED, BLOCKED, CANCELLED
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.tools_v2 import (
    ToolCapabilityInfo,
    ToolCategory,
    ToolHealthStatus,
    ToolRegistryV2,
)
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, UnauthorizedTargetError


class PlanStageState(str, Enum):
    PLANNED = "PLANNED"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class ToolPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=4096)
    target: str | None = Field(default=None, max_length=253)
    target_type: str | None = Field(default=None, max_length=64)
    task_intent: str | None = Field(default=None, max_length=64)
    intensity: Literal["passive", "normal", "aggressive"] = "normal"
    allowed_tools: list[str] | None = None
    investigation_id: str | None = None
    conversation_id: str | None = None


@dataclass
class ToolPlanStage:
    stage_id: str
    tool_id: str
    tool_name: str
    category: str
    command_args: list[str]
    environment: str
    risk_level: str
    requires_authorization: bool
    timeout_seconds: int
    rationale: str
    status: PlanStageState = PlanStageState.PLANNED
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float = 0.0
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "category": self.category,
            "command_args": self.command_args,
            "environment": self.environment,
            "risk_level": self.risk_level,
            "requires_authorization": self.requires_authorization,
            "timeout_seconds": self.timeout_seconds,
            "rationale": self.rationale,
            "status": self.status.value if isinstance(self.status, PlanStageState) else str(self.status),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "evidence_id": self.evidence_id,
        }


@dataclass
class ToolPlan:
    plan_id: str
    prompt: str
    target: str | None
    target_type: str | None
    task_intent: str
    stages: list[ToolPlanStage]
    rationale: str
    requires_scope_approval: bool
    status: PlanStageState = PlanStageState.PLANNED
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "prompt": self.prompt,
            "target": self.target,
            "target_type": self.target_type,
            "task_intent": self.task_intent,
            "stages": [s.to_dict() for s in self.stages],
            "rationale": self.rationale,
            "requires_scope_approval": self.requires_scope_approval,
            "status": self.status.value if isinstance(self.status, PlanStageState) else str(self.status),
            "created_at": self.created_at or datetime.now(timezone.utc).isoformat(),
        }


class ToolPlanner:
    """Autonomous security tool planner."""

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.scope_manager = scope_manager
        self.scope_guard = scope_guard
        self.audit = audit

    def create_plan(
        self,
        request: ToolPlanRequest,
        request_context: RequestContext | None = None,
    ) -> ToolPlan:
        plan_id = f"plan-{uuid.uuid4().hex[:8]}"
        prompt = request.prompt.strip()

        # Step 1: Target Resolution via Phase 1 TargetResolver
        if request_context is None:
            request_context = RequestContext(
                request_id=f"req-{uuid.uuid4().hex[:8]}",
                explicit_target=request.target,
                active_investigation_id=request.investigation_id,
                user_message=prompt,
            )

        ctx_dict = request_context.to_dict()
        if request.target:
            ctx_dict["explicit_target"] = request.target

        resolved_target, resolved_type, resolution_source = TargetResolver.resolve_target(
            prompt=prompt,
            context=ctx_dict,
        )

        target_type = request.target_type or (resolved_type if resolved_type != "none" else None)
        if not target_type and resolved_target:
            t_type, _ = TargetResolver.classify_target(resolved_target)
            target_type = t_type if t_type != "unknown" else None

        # Step 2: Determine Task Intent
        intent = request.task_intent or self._detect_intent(prompt)

        # Step 3: Tool Candidate Selection & Prioritization
        stages: list[ToolPlanStage] = []
        requires_scope_approval = False

        if intent in ("network_recon", "port_scan"):
            stages.extend(self._plan_network_recon(resolved_target, target_type, request.intensity))
        elif intent in ("web_security", "web_audit"):
            stages.extend(self._plan_web_audit(resolved_target, target_type, request.intensity))
        elif intent in ("osint", "domain_recon"):
            stages.extend(self._plan_osint(resolved_target, target_type, request.intensity))
        elif intent in ("tls_check", "cert_audit"):
            stages.extend(self._plan_tls(resolved_target, target_type))
        elif intent in ("forensics", "file_analysis"):
            stages.extend(self._plan_forensics(resolved_target))
        else:
            # General diagnostic or terminal query
            stages.extend(self._plan_diagnostic(resolved_target, prompt))

        # Filter by allowed_tools if specified
        if request.allowed_tools:
            allowed_set = {t.lower() for t in request.allowed_tools}
            stages = [s for s in stages if s.tool_id.lower() in allowed_set]

        # Step 4: Validate Scope for each stage
        for idx, stage in enumerate(stages):
            if stage.requires_authorization:
                authorized = self._is_target_authorized(resolved_target)
                if not authorized:
                    stage.status = PlanStageState.BLOCKED
                    stage.rationale += f" [BLOCKED: Target '{resolved_target}' not authorized in Scope]"
                    requires_scope_approval = True
                else:
                    stage.status = PlanStageState.READY
            else:
                stage.status = PlanStageState.READY

        plan_status = PlanStageState.BLOCKED if requires_scope_approval else (PlanStageState.READY if stages else PlanStageState.PLANNED)

        rationale = (
            f"Autonomous plan for intent '{intent}' targeting '{resolved_target or 'None'}' "
            f"({target_type or 'unspecified'}). Selected {len(stages)} stage(s). "
            f"{'Scope authorization required before active execution.' if requires_scope_approval else 'All stages ready.'}"
        )

        return ToolPlan(
            plan_id=plan_id,
            prompt=prompt,
            target=resolved_target,
            target_type=target_type,
            task_intent=intent,
            stages=stages,
            rationale=rationale,
            requires_scope_approval=requires_scope_approval,
            status=plan_status,
        )

    def _detect_intent(self, prompt: str) -> str:
        p = prompt.lower()
        if any(w in p for w in ["whois", "dns", "subdomain", "shodan", "virustotal", "harvester", "osint"]):
            return "osint"
        if any(w in p for w in ["web", "nikto", "gobuster", "url", "directory", "dirbuster", "http header", "fuzz", "sqlmap"]):
            return "web_security"
        if any(w in p for w in ["tls", "ssl", "certificate", "cipher", "testssl", "sslyze", "heartbleed"]):
            return "tls_check"
        if any(w in p for w in ["pcap", "forensic", "exif", "yara", "strings", "malware", "metadata"]):
            return "forensics"
        if any(w in p for w in ["scan port", "port scan", "nmap", "open port", "traceroute", "ping host", "network recon", "port sweep"]):
            return "network_recon"
        return "network_recon" if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", p) else "diagnostic"

    def _is_target_authorized(self, target: str | None) -> bool:
        if not target:
            return False
        # If no scope manager configured, check if localhost
        if self.scope_manager is None and self.scope_guard is None:
            return target in ("127.0.0.1", "localhost", "::1")
        if self.scope_guard is not None:
            return self.scope_guard.is_target_authorized(target, "scan")
        if self.scope_manager is not None:
            try:
                self.scope_manager.check(target, "scan")
                return True
            except Exception:
                return False
        return False

    def _plan_network_recon(self, target: str | None, target_type: str | None, intensity: str) -> list[ToolPlanStage]:
        stages: list[ToolPlanStage] = []
        tgt = target or "127.0.0.1"

        # 1. ICMP Reachability / Ping
        ping_tool = ToolRegistryV2.get_tool("ping")
        stages.append(
            ToolPlanStage(
                stage_id="stage-1-ping",
                tool_id="ping",
                tool_name="ICMP Ping",
                category=ToolCategory.NETWORK_RECON.value,
                command_args=["-n", "3", tgt] if ping_tool and ping_tool.environment == "host" and subprocess.os.name == "nt" else ["-c", "3", tgt],
                environment="host",
                risk_level="ACTIVE_PROBE",
                requires_authorization=True,
                timeout_seconds=10,
                rationale="Confirm host reachability and round-trip latency.",
            )
        )

        # 2. Port Scanning / Nmap
        nmap_tool = ToolRegistryV2.get_tool("nmap")
        is_nmap_avail = nmap_tool and nmap_tool.available
        env = nmap_tool.environment if nmap_tool else "host"

        args = ["-sT", "-T3", "--open"]
        if intensity == "aggressive":
            args.extend(["-p", "1-10000", "-A"])
        elif intensity == "passive":
            args.extend(["-p", "80,443,8080"])
        else:
            args.extend(["-p", "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443"])
        args.append(tgt)

        stages.append(
            ToolPlanStage(
                stage_id="stage-2-nmap",
                tool_id="nmap",
                tool_name="Nmap Network Scanner",
                category=ToolCategory.NETWORK_RECON.value,
                command_args=args,
                environment=env,
                risk_level="ACTIVE_PROBE",
                requires_authorization=True,
                timeout_seconds=30,
                rationale=f"Execute TCP connect scan across standard ports using {env} environment.",
            )
        )
        return stages

    def _plan_web_audit(self, target: str | None, target_type: str | None, intensity: str) -> list[ToolPlanStage]:
        stages: list[ToolPlanStage] = []
        tgt = target or "127.0.0.1"
        clean_host = re.sub(r"^https?://", "", tgt).split("/")[0]

        # 1. HTTP header inspection with curl (passive/local)
        curl_tool = ToolRegistryV2.get_tool("curl")
        stages.append(
            ToolPlanStage(
                stage_id="stage-1-curl",
                tool_id="curl",
                tool_name="cURL HTTP Prober",
                category=ToolCategory.WEB_SECURITY.value,
                command_args=["-sI", "-L", f"http://{clean_host}"],
                environment=curl_tool.environment if curl_tool else "host",
                risk_level="SAFE_READONLY",
                requires_authorization=False,
                timeout_seconds=10,
                rationale="Retrieve HTTP response headers, server banner, and redirect chains.",
            )
        )

        # 2. Web misconfiguration scan with Nikto
        nikto_tool = ToolRegistryV2.get_tool("nikto")
        stages.append(
            ToolPlanStage(
                stage_id="stage-2-nikto",
                tool_id="nikto",
                tool_name="Nikto Web Scanner",
                category=ToolCategory.WEB_SECURITY.value,
                command_args=["-h", clean_host, "-Tuning", "1,2,3"],
                environment=nikto_tool.environment if nikto_tool else "host",
                risk_level="ACTIVE_PROBE",
                requires_authorization=True,
                timeout_seconds=45,
                rationale="Audit server headers, outdated software components, and default dangerous files.",
            )
        )
        return stages

    def _plan_osint(self, target: str | None, target_type: str | None, intensity: str) -> list[ToolPlanStage]:
        stages: list[ToolPlanStage] = []
        tgt = target or "example.com"
        clean_domain = re.sub(r"^https?://", "", tgt).split("/")[0].split(":")[0]

        # 1. DNS Resolution via nslookup
        stages.append(
            ToolPlanStage(
                stage_id="stage-1-dns",
                tool_id="nslookup",
                tool_name="NSLookup DNS Resolver",
                category=ToolCategory.OSINT.value,
                command_args=[clean_domain],
                environment="host",
                risk_level="SAFE_READONLY",
                requires_authorization=False,
                timeout_seconds=10,
                rationale="Resolve authoritative DNS records (A, AAAA, MX).",
            )
        )

        # 2. WHOIS Lookup
        whois_tool = ToolRegistryV2.get_tool("whois")
        stages.append(
            ToolPlanStage(
                stage_id="stage-2-whois",
                tool_id="whois",
                tool_name="WHOIS Client",
                category=ToolCategory.OSINT.value,
                command_args=[clean_domain],
                environment=whois_tool.environment if whois_tool else "host",
                risk_level="SAFE_READONLY",
                requires_authorization=False,
                timeout_seconds=15,
                rationale="Retrieve registrar, registration dates, and nameservers.",
            )
        )
        return stages

    def _plan_tls(self, target: str | None, target_type: str | None) -> list[ToolPlanStage]:
        tgt = target or "127.0.0.1"
        clean_host = re.sub(r"^https?://", "", tgt).split("/")[0].split(":")[0]

        openssl_tool = ToolRegistryV2.get_tool("openssl")
        return [
            ToolPlanStage(
                stage_id="stage-1-openssl",
                tool_id="openssl",
                tool_name="OpenSSL Certificate Inspector",
                category=ToolCategory.TLS_CERTS.value,
                command_args=["s_client", "-connect", f"{clean_host}:443", "-servername", clean_host],
                environment=openssl_tool.environment if openssl_tool else "host",
                risk_level="SAFE_READONLY",
                requires_authorization=False,
                timeout_seconds=15,
                rationale="Inspect SSL/TLS certificate chain, expiration, and cipher negotiation.",
            )
        ]

    def _plan_forensics(self, target: str | None) -> list[ToolPlanStage]:
        file_path = target or "artifact.bin"
        strings_tool = ToolRegistryV2.get_tool("strings")
        return [
            ToolPlanStage(
                stage_id="stage-1-strings",
                tool_id="strings",
                tool_name="Strings Binary Extraction",
                category=ToolCategory.FORENSICS.value,
                command_args=["-n", "8", file_path],
                environment=strings_tool.environment if strings_tool else "host",
                risk_level="INSPECTION",
                requires_authorization=False,
                timeout_seconds=10,
                rationale="Extract printable ASCII and UTF-8 strings from target artifact.",
            )
        ]

    def _plan_diagnostic(self, target: str | None, prompt: str) -> list[ToolPlanStage]:
        return [
            ToolPlanStage(
                stage_id="stage-1-netstat",
                tool_id="netstat",
                tool_name="Netstat Local Socket Audit",
                category=ToolCategory.LOCAL_TERMINAL.value,
                command_args=["-an"],
                environment="host",
                risk_level="SAFE_READONLY",
                requires_authorization=False,
                timeout_seconds=10,
                rationale="Audit local active listening ports and established sockets.",
            )
        ]
