"""Central Tool Registry for REDLOOP Security Platform.

Every executable security tool in REDLOOP must be registered here with:
- Name and Description
- Execution Class: LOCAL_ONLY, NETWORK_DEPENDENT, AI_PROVIDER_DEPENDENT
- Required Authorization: Boolean flag enforcing scope check before execution
- Allowed Actions: Scope action identifiers matching scope.yaml contracts
- Input and Output Schemas
- Timeout and Retry Policies
- Produced Evidence type and Audit Event module
- Risk Level: SAFE_READONLY, ACTIVE_PROBE, INSPECTION, SIMULATION

Any network-dependent tool strictly FAILS CLOSED if scope authorization is absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from redloop.assessment.models import ExecutionClass, StageStatus
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError


class ToolRiskLevel(str, Enum):
    SAFE_READONLY = "SAFE_READONLY"
    INSPECTION = "INSPECTION"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    SIMULATION = "SIMULATION"


@dataclass
class ToolDefinition:
    name: str
    description: str
    execution_class: ExecutionClass
    authorization_required: bool
    allowed_actions: list[str]
    risk_level: ToolRiskLevel
    timeout_seconds: float = 15.0
    max_retries: int = 1
    evidence_produced: str = "generic_evidence"
    audit_module: str = "tool"
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)

    def validate_authorization(
        self,
        scope_guard: AssessmentScopeGuard | None,
        target: str,
        action: str | None = None,
        port: int | None = None,
    ) -> bool:
        """Enforce backend scope validation before tool invocation.
        
        Returns True if authorized or if the tool is strictly local/exempt.
        Fails closed (raises ScopeBlockedError) if network authorization is missing.
        """
        if not self.authorization_required or self.execution_class == ExecutionClass.LOCAL_ONLY:
            return True

        if scope_guard is None:
            raise ScopeBlockedError(target, action or self.allowed_actions[0] if self.allowed_actions else "scan", "Scope guard not configured.")

        act = action or (self.allowed_actions[0] if self.allowed_actions else "scan")
        return scope_guard.is_target_authorized(target, act, port=port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "execution_class": self.execution_class.value,
            "authorization_required": self.authorization_required,
            "allowed_actions": self.allowed_actions,
            "risk_level": self.risk_level.value,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "evidence_produced": self.evidence_produced,
            "audit_module": self.audit_module,
        }


class ToolRegistry:
    """Central registry of all security tools available within REDLOOP."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def _register_default_tools(self) -> None:
        # 1. DNS Reconnaissance
        self.register(
            ToolDefinition(
                name="dns_scanner",
                description="Authoritative DNS record enumeration, SPF/DMARC hygiene, and DNSSEC validation.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["dns_check", "recon", "scan", "assess"],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=10.0,
                evidence_produced="dns_records",
                audit_module="dns_engine",
            )
        )

        # 2. Port & Service Discovery
        self.register(
            ToolDefinition(
                name="port_scanner",
                description="TCP socket connection ladder and banner grabbing across candidate service ports.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["scan", "recon", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=15.0,
                evidence_produced="port_scan_results",
                audit_module="network_engine",
            )
        )

        # 3. Cryptographic TLS Inspection
        self.register(
            ToolDefinition(
                name="tls_checker",
                description="TLS 1.2/1.3 cipher suite evaluation, certificate chain verification, and SAN extraction.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["tls_check", "scan", "assess"],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=12.0,
                evidence_produced="tls_certificate_and_ciphers",
                audit_module="tls_engine",
            )
        )

        # 4. Web Application Security Prober
        self.register(
            ToolDefinition(
                name="web_checker",
                description="HTTP security header audit (HSTS, CSP, XFO), safe endpoint crawl, and OWASP triage.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["web_check", "scan", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=15.0,
                evidence_produced="web_security_headers",
                audit_module="web_engine",
            )
        )

        # 5. API Schema & Endpoint Analyzer
        self.register(
            ToolDefinition(
                name="api_prober",
                description="OpenAPI/Swagger schema discovery and REST security boundary testing.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["api_check", "scan", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=15.0,
                evidence_produced="api_endpoint_tree",
                audit_module="api_engine",
            )
        )

        # 6. Shodan Threat Intelligence
        self.register(
            ToolDefinition(
                name="shodan_query",
                description="Passive OSINT query to Shodan API for open services and known vulnerabilities.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["recon", "scan", "assess"],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=8.0,
                evidence_produced="shodan_host_summary",
                audit_module="shodan_engine",
            )
        )

        # 7. Offline Synthetic Exploit Simulator
        self.register(
            ToolDefinition(
                name="exploit_simulator",
                description="Offline synthetic exploit simulation; strictly offline without live target weaponization.",
                execution_class=ExecutionClass.LOCAL_ONLY,
                authorization_required=True,
                allowed_actions=["exploit_simulation", "scan", "assess"],
                risk_level=ToolRiskLevel.SIMULATION,
                timeout_seconds=5.0,
                evidence_produced="simulated_exploit_trace",
                audit_module="exploit",
            )
        )

        # 8. Forensics Artifact Triage
        self.register(
            ToolDefinition(
                name="forensics_triage",
                description="Local binary artifact triage, file entropy, hashes (MD5, SHA-1, SHA-256), and strings analysis.",
                execution_class=ExecutionClass.LOCAL_ONLY,
                authorization_required=False,
                allowed_actions=[],
                risk_level=ToolRiskLevel.INSPECTION,
                timeout_seconds=10.0,
                evidence_produced="forensic_file_report",
                audit_module="forensics",
            )
        )

        # 9. CTF Codec & Cryptographic Toolkit
        self.register(
            ToolDefinition(
                name="ctf_codec",
                description="Multi-format encode/decode transformations (Base64, Hex, URL, Rot13, Binary, XOR).",
                execution_class=ExecutionClass.LOCAL_ONLY,
                authorization_required=False,
                allowed_actions=[],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=2.0,
                evidence_produced="transformed_payload",
                audit_module="ctf_codec",
            )
        )

        # 10. Local Evidence Review (Historical Intelligence)
        self.register(
            ToolDefinition(
                name="local_evidence_review",
                description="Inspect REDLOOP-owned persistent store for historical findings and evidence from prior authorized operations.",
                execution_class=ExecutionClass.LOCAL_ONLY,
                authorization_required=False,
                allowed_actions=[],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=3.0,
                evidence_produced="historical_evidence_audit",
                audit_module="orchestrator",
            )
        )

        # 11. Kali Command Advisor & Safe Runner
        self.register(
            ToolDefinition(
                name="kali_advisor",
                description="Kali Linux terminal command analysis, error debugging, syntax guidance, and mitigation playbooks.",
                execution_class=ExecutionClass.AI_PROVIDER_DEPENDENT,
                authorization_required=False,
                allowed_actions=[],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=10.0,
                evidence_produced="kali_guidance",
                audit_module="kali_copilot",
            )
        )

        # 12. AI Reasoning & Report Synthesis
        self.register(
            ToolDefinition(
                name="llm_reasoning",
                description="Multi-tier LLM reasoning engine synthesizing technical findings and remediation strategies.",
                execution_class=ExecutionClass.AI_PROVIDER_DEPENDENT,
                authorization_required=False,
                allowed_actions=[],
                risk_level=ToolRiskLevel.SAFE_READONLY,
                timeout_seconds=12.0,
                evidence_produced="analytical_synthesis",
                audit_module="llm",
            )
        )

        # 13. Nmap Network Scanner (Direct Tool Alias)
        self.register(
            ToolDefinition(
                name="nmap",
                description="Nmap Security Scanner for TCP/UDP port enumeration, service version detection, and host discovery.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["scan", "recon", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=30.0,
                evidence_produced="nmap_scan_output",
                audit_module="nmap",
            )
        )

        # 14. Nikto Web Scanner
        self.register(
            ToolDefinition(
                name="nikto",
                description="Nikto Web Server Scanner for dangerous files, outdated server software, and HTTP misconfigurations.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["web_check", "scan", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=30.0,
                evidence_produced="nikto_vulnerability_report",
                audit_module="nikto",
            )
        )

        # 15. Gobuster Directory Enumerator
        self.register(
            ToolDefinition(
                name="gobuster",
                description="Gobuster directory and file brute-forcer for web application reconnaissance.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["web_check", "scan", "assess"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=20.0,
                evidence_produced="gobuster_directory_list",
                audit_module="gobuster",
            )
        )

        # 16. Kali Command Runner
        self.register(
            ToolDefinition(
                name="kali_runner",
                description="Controlled execution of whitelisted Kali Linux terminal commands behind central scope authorization.",
                execution_class=ExecutionClass.NETWORK_DEPENDENT,
                authorization_required=True,
                allowed_actions=["scan", "recon", "assess", "kali_execute"],
                risk_level=ToolRiskLevel.ACTIVE_PROBE,
                timeout_seconds=20.0,
                evidence_produced="kali_command_evidence",
                audit_module="kali_runner",
            )
        )

    def execute(
        self,
        tool_name: str,
        target: str,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: Any | None = None,
        ports: list[int] | None = None,
        arguments: Any | None = None,
        operation_id: str = "op-default",
    ) -> Any:
        from redloop.assessment.controlled_runner import ControlledToolRunner
        runner = ControlledToolRunner(scope_guard=scope_guard, audit=audit)
        return runner.execute_tool(
            tool_name=tool_name,
            target=target,
            ports=ports,
            arguments=arguments,
            operation_id=operation_id,
        )


_DEFAULT_REGISTRY: ToolRegistry | None = None


def get_tool_registry() -> ToolRegistry:
    """Return the singleton instance of the ToolRegistry."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = ToolRegistry()
    return _DEFAULT_REGISTRY
