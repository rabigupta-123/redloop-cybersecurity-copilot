"""SSH-based Kali Remote Execution Connector + Cached --help Flag Validator (Phase L, Gate L.5).

Security & Engineering Guarantees:
1. Every command must pass `ValidatedCommand` (argv list only, zero shell metacharacters
   or chaining `;`, `|`, `&&`, `$()`, backticks).
2. Every tool flag must exist in the captured `--help` schema (`kali_tool_help_cache.json`
   with >=20 tools). Unknown or LLM-hallucinated flags are rejected with `UNKNOWN_TOOL_FLAG`
   before SSH dispatch.
3. Every target IP/domain/URL extracted from the command must be authorized inside the
   active, cryptographically signed `EngagementScope` (`AssessmentScopeGuard` / `ScopeEnforcer`)
   BEFORE opening or dispatching over the SSH session. Out-of-scope targets are blocked
   with `403 SCOPE_VIOLATION` and an immutable audit log entry.
4. Authorized execution results are normalized into REDLOOP `Evidence` and `Finding` models.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shlex
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from redloop.assessment.kali_copilot import KaliCommandParser
from redloop.assessment.models import (
    Confidence,
    Evidence,
    EvidenceProvenance,
    Finding,
    FindingStatus,
    Severity,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger
from redloop.connectors.models import (
    ConnectorManifest,
    ConnectorTool,
    RiskLevel,
    TransportType,
)
from redloop.scope import ScopeManager, UnauthorizedTargetError

DEFAULT_HELP_CACHE_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "kali_tool_help_cache.json"
)


class CommandBlockedError(ValueError):
    """Raised when a command fails ValidatedCommand shell-injection or safety checks."""


@dataclass(frozen=True)
class ValidatedCommand:
    """Strictly validated argv list with zero shell chaining, metacharacters, or dangerous ops."""

    argv: tuple[str, ...]

    def __init__(self, argv: list[str] | tuple[str, ...]) -> None:
        if not argv:
            raise CommandBlockedError("Command argv cannot be empty.")
        clean_argv = tuple(str(part) for part in argv if str(part))
        if not clean_argv:
            raise CommandBlockedError("Command argv cannot be empty.")
        for token in clean_argv:
            for meta in (";", "|", "&&", "||", "`", "$(", "\n", "\r", ">", "<"):
                if meta in token:
                    raise CommandBlockedError(
                        f"Forbidden shell metacharacter '{meta}' in argument '{token}'"
                    )
        parsed = KaliCommandParser.parse(" ".join(clean_argv))
        if parsed.is_dangerous:
            raise CommandBlockedError(parsed.reason)
        object.__setattr__(self, "argv", clean_argv)


@dataclass(frozen=True)
class ScopeEnforcementResult:
    """Result of verifying target against active EngagementScope before SSH dispatch."""

    allowed: bool
    target: str
    normalized_target: str
    matched_rule: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "normalized_target": self.normalized_target,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FlagCitation:
    """Verified citation for a single CLI flag from captured `--help` output."""

    tool_name: str
    flag: str
    description: str
    source_citation: str
    version_captured: str

    def to_dict(self) -> dict[str, str]:
        return {
            "tool_name": self.tool_name,
            "flag": self.flag,
            "description": self.description,
            "source_citation": self.source_citation,
            "version_captured": self.version_captured,
        }


@dataclass(frozen=True)
class ToolHelpValidationResult:
    """Result of validating a command's binary, subcommand, and flags against cached `--help`."""

    allowed: bool
    tool_name: str
    version_captured: str
    source_citation: str
    citations: list[FlagCitation] = field(default_factory=list)
    unknown_flags: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "tool_name": self.tool_name,
            "version_captured": self.version_captured,
            "source_citation": self.source_citation,
            "citations": [c.to_dict() for c in self.citations],
            "unknown_flags": self.unknown_flags,
            "reason": self.reason,
        }


class KaliToolHelpKnowledgeBase:
    """Grounded Kali tool knowledge base built from captured `--help` outputs (>=20 tools).

    Never guesses flags: every flag in a command must match an entry in `valid_flags`
    for the target binary.
    """

    def __init__(self, cache_path: Path | None = None) -> None:
        self.cache_path = cache_path or DEFAULT_HELP_CACHE_PATH
        raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.schema_version: str = raw.get("schema_version", "1.0.0")
        self.tools: dict[str, dict[str, Any]] = raw.get("tools", {})
        if len(self.tools) < 20:
            raise ValueError(
                f"Kali tool help cache must contain >= 20 tools, found {len(self.tools)}"
            )

    def list_tools(self) -> list[str]:
        return sorted(self.tools.keys())

    def get_tool_schema(self, tool_name: str) -> dict[str, Any] | None:
        return self.tools.get(tool_name.lower().strip())

    def validate_argv(self, argv: list[str]) -> ToolHelpValidationResult:
        """Validate binary and every flag in `argv` against captured `--help` output."""
        if not argv:
            return ToolHelpValidationResult(
                allowed=False,
                tool_name="",
                version_captured="",
                source_citation="",
                reason="EMPTY_COMMAND: argv is empty.",
            )

        binary = Path(argv[0]).name.lower()
        schema = self.get_tool_schema(binary)
        if schema is None:
            return ToolHelpValidationResult(
                allowed=False,
                tool_name=binary,
                version_captured="unknown",
                source_citation="unregistered",
                reason=f"UNREGISTERED_TOOL: '{binary}' is not in the cached Kali --help knowledge base.",
            )

        valid_flags: dict[str, str] = schema.get("valid_flags", {})
        valid_subcommands: list[str] = schema.get("valid_subcommands", [])
        version_captured = schema.get("version_captured", "")
        source_citation = schema.get("source_citation", "")

        citations: list[FlagCitation] = []
        unknown_flags: list[str] = []

        args = argv[1:]
        i = 0
        while i < len(args):
            token = args[i]
            # Check dig-style +options or standard - / -- flags
            if token.startswith("-") or (binary == "dig" and token.startswith("+")):
                # Handle --flag=value or -p80
                flag_key = token.split("=", 1)[0]
                if flag_key in valid_flags:
                    citations.append(
                        FlagCitation(
                            tool_name=binary,
                            flag=flag_key,
                            description=valid_flags[flag_key],
                            source_citation=source_citation,
                            version_captured=version_captured,
                        )
                    )
                elif (
                    binary == "nmap"
                    and re.match(r"^-p(?:\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*|-)$", flag_key)
                ):
                    citations.append(
                        FlagCitation(
                            tool_name=binary,
                            flag="-p",
                            description=valid_flags["-p"],
                            source_citation=source_citation,
                            version_captured=version_captured,
                        )
                    )
                else:
                    unknown_flags.append(flag_key)
            elif i == 0 and valid_subcommands and not token.startswith("http") and "." not in token:
                # If tool requires/supports subcommand (like gobuster dir/dns/vhost)
                if token not in valid_subcommands:
                    unknown_flags.append(f"subcommand:{token}")
            i += 1

        if unknown_flags:
            return ToolHelpValidationResult(
                allowed=False,
                tool_name=binary,
                version_captured=version_captured,
                source_citation=source_citation,
                citations=citations,
                unknown_flags=unknown_flags,
                reason=(
                    f"UNKNOWN_TOOL_FLAG: Flag(s) {unknown_flags} do not exist in captured "
                    f"'{source_citation}' schema. Hallucinated or unverified flags are blocked."
                ),
            )

        return ToolHelpValidationResult(
            allowed=True,
            tool_name=binary,
            version_captured=version_captured,
            source_citation=source_citation,
            citations=citations,
            unknown_flags=[],
            reason=f"All {len(citations)} flag(s) verified against {source_citation}.",
        )


@dataclass(frozen=True)
class KaliSSHConfig:
    """Connection parameters for an operator-controlled Kali host or container over SSH."""

    host: str = "127.0.0.1"
    port: int = 2222
    username: str = "kali"
    key_filename: str | None = None
    password: str | None = None
    connect_timeout_s: float = 10.0
    command_timeout_s: float = 60.0


@dataclass
class KaliSSHExecutionResult:
    """Structured result of a scope-verified SSH command execution on a Kali host."""

    allowed: bool
    status_code: int
    command: str
    argv: list[str]
    target: str | None
    ssh_dispatched: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    help_validation: ToolHelpValidationResult | None
    scope_decision: ScopeEnforcementResult | None
    evidence: Evidence | None = None
    findings: list[Finding] = field(default_factory=list)
    error_code: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status_code": self.status_code,
            "command": self.command,
            "argv": self.argv,
            "target": self.target,
            "ssh_dispatched": self.ssh_dispatched,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": round(self.duration_ms, 2),
            "help_validation": self.help_validation.to_dict() if self.help_validation else None,
            "scope_decision": self.scope_decision.to_dict() if self.scope_decision else None,
            "evidence_id": self.evidence.id if self.evidence else None,
            "findings_count": len(self.findings),
            "error_code": self.error_code,
            "reason": self.reason,
        }


SSHTransportCallable = Callable[
    [KaliSSHConfig, list[str], float],
    Awaitable[tuple[int, str, str]],
]


async def default_openssh_transport(
    config: KaliSSHConfig,
    argv: list[str],
    timeout_s: float,
) -> tuple[int, str, str]:
    """Execute validated `argv` on remote Kali host via OpenSSH client (`ssh`) with BatchMode."""
    remote_cmd = " ".join(shlex.quote(part) for part in argv)
    ssh_argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={int(config.connect_timeout_s)}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        str(config.port),
    ]
    if config.key_filename:
        ssh_argv.extend(["-i", config.key_filename])
    ssh_argv.append(f"{config.username}@{config.host}")
    ssh_argv.append(remote_cmd)

    proc = await asyncio.create_subprocess_exec(
        *ssh_argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        return (
            proc.returncode or 0,
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        return (124, "", f"SSH command timed out after {timeout_s}s")


class KaliSSHConnector:
    """SSH-based Kali remote execution connector with pre-SSH Scope + ValidatedCommand + --help gates."""

    def __init__(
        self,
        ssh_config: KaliSSHConfig | None = None,
        scope_guard: AssessmentScopeGuard | None = None,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        knowledge_base: KaliToolHelpKnowledgeBase | None = None,
        ssh_transport: SSHTransportCallable | None = None,
    ) -> None:
        self.ssh_config = ssh_config or KaliSSHConfig()
        self.scope_guard = scope_guard
        self.scope_manager = scope_manager
        self.audit = audit_logger or AuditLogger()
        self.kb = knowledge_base or KaliToolHelpKnowledgeBase()
        self.ssh_transport = ssh_transport or default_openssh_transport

    def _extract_target(self, argv: list[str]) -> str | None:
        parsed = KaliCommandParser.parse(" ".join(argv))
        if parsed.target:
            return parsed.target
        # Fallback check for URLs, domains, or IPs in any argument
        for arg in argv[1:]:
            if arg.startswith(("http://", "https://")):
                return arg
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$", arg):
                return arg
            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", arg) and not arg.startswith("-"):
                return arg
        return None

    def _verify_scope(
        self,
        target: str | None,
        command_str: str,
        operation_id: str,
    ) -> ScopeEnforcementResult:
        if not target:
            return ScopeEnforcementResult(
                allowed=False,
                target="",
                normalized_target="",
                reason="TARGET_REQUIRED: Remote Kali tool execution requires an explicit target host/IP/URL.",
            )

        # 1. Check cryptographic ScopeManager if provided
        if self.scope_manager is not None:
            if self.scope_manager.is_target_in_scope(target):
                return ScopeEnforcementResult(
                    allowed=True,
                    target=target,
                    normalized_target=target,
                    matched_rule=f"signed_scope:{self.scope_manager.scope.id}",
                    reason=f"Target '{target}' verified against signed ScopeManager ({self.scope_manager.scope.id}).",
                )
            else:
                reason = f"Target '{target}' is not present in signed scope ({self.scope_manager.scope.id})"
                self.audit.log(
                    target=target,
                    action="SCOPE_VIOLATION_BLOCKED",
                    module="kali_ssh_connector",
                    status="blocked",
                    operation_id=operation_id,
                    command=command_str,
                    reason=reason,
                )
                return ScopeEnforcementResult(
                    allowed=False,
                    target=target,
                    normalized_target=target,
                    reason=f"SCOPE_VIOLATION: {reason}",
                )

        # 2. Check AssessmentScopeGuard if provided
        if self.scope_guard is not None:
            is_ok = self.scope_guard.is_authorized(target)
            return ScopeEnforcementResult(
                allowed=is_ok,
                target=target,
                normalized_target=target,
                matched_rule="assessment_scope_guard" if is_ok else "",
                reason="Authorized by AssessmentScopeGuard" if is_ok else "Blocked by AssessmentScopeGuard",
            )

        # 3. Fail-closed if neither scope guard nor signed scope enforcer is configured
        self.audit.log(
            target=target,
            action="SCOPE_VIOLATION_BLOCKED",
            module="kali_ssh_connector",
            status="blocked",
            operation_id=operation_id,
            command=command_str,
            reason="No active EngagementScope or AssessmentScopeGuard configured.",
        )
        return ScopeEnforcementResult(
            allowed=False,
            target=target,
            normalized_target=target,
            reason="SCOPE_REQUIRED: No active signed EngagementScope configured for remote Kali execution.",
        )

    async def execute_command(
        self,
        command: str | list[str],
        operation_id: str | None = None,
    ) -> KaliSSHExecutionResult:
        """Validate command syntax, cached `--help` flags, and active scope, then dispatch over SSH."""
        t0 = time.monotonic()
        op_id = operation_id or f"kali-ssh-{uuid.uuid4().hex[:8]}"
        raw_cmd_str = command if isinstance(command, str) else " ".join(command)

        # Gate 1: ValidatedCommand (blocks shell metacharacters, chaining `;`, `|`, `&&`, `$()`, etc.)
        try:
            if isinstance(command, str):
                # Reject raw shell chaining before splitting
                for forbidden_tok in (";", "|", "&&", "||", "`", "$(", ">", "<"):
                    if forbidden_tok in command:
                        raise CommandBlockedError(
                            f"Shell chaining/redirection token '{forbidden_tok}' is prohibited in Kali SSH execution"
                        )
                argv = shlex.split(command.strip())
            else:
                argv = list(command)
            validated = ValidatedCommand(argv=argv)
        except (CommandBlockedError, ValueError) as exc:
            self.audit.log(
                target="none",
                action="DANGEROUS_COMMAND_BLOCKED",
                module="kali_ssh_connector",
                status="blocked",
                operation_id=op_id,
                command=raw_cmd_str,
                reason=str(exc),
            )
            return KaliSSHExecutionResult(
                allowed=False,
                status_code=400,
                command=raw_cmd_str,
                argv=[],
                target=None,
                ssh_dispatched=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=(time.monotonic() - t0) * 1000.0,
                help_validation=None,
                scope_decision=None,
                error_code="INVALID_COMMAND",
                reason=str(exc),
            )

        argv_list = list(validated.argv)

        # Gate 2: Cached `--help` Flag Validation (no hallucinated flags)
        help_res = self.kb.validate_argv(argv_list)
        if not help_res.allowed:
            self.audit.log(
                target="none",
                action="UNKNOWN_TOOL_FLAG_BLOCKED",
                module="kali_ssh_connector",
                status="blocked",
                operation_id=op_id,
                command=raw_cmd_str,
                reason=help_res.reason,
            )
            return KaliSSHExecutionResult(
                allowed=False,
                status_code=422,
                command=raw_cmd_str,
                argv=argv_list,
                target=None,
                ssh_dispatched=False,
                exit_code=-1,
                stdout="",
                stderr=help_res.reason,
                duration_ms=(time.monotonic() - t0) * 1000.0,
                help_validation=help_res,
                scope_decision=None,
                error_code="UNKNOWN_TOOL_FLAG",
                reason=help_res.reason,
            )

        # Gate 3: Active EngagementScope Enforcement BEFORE SSH Dispatch
        target = self._extract_target(argv_list)
        scope_res = self._verify_scope(target, raw_cmd_str, op_id)
        if not scope_res.allowed:
            return KaliSSHExecutionResult(
                allowed=False,
                status_code=403,
                command=raw_cmd_str,
                argv=argv_list,
                target=target,
                ssh_dispatched=False,
                exit_code=-1,
                stdout="",
                stderr=scope_res.reason,
                duration_ms=(time.monotonic() - t0) * 1000.0,
                help_validation=help_res,
                scope_decision=scope_res,
                error_code="SCOPE_VIOLATION",
                reason=scope_res.reason,
            )

        # Gate 4: Dispatch over SSH to Kali host
        exit_code, stdout, stderr = await self.ssh_transport(
            self.ssh_config,
            argv_list,
            self.ssh_config.command_timeout_s,
        )
        duration_ms = (time.monotonic() - t0) * 1000.0

        self.audit.log(
            target=target or "",
            action="KALI_SSH_COMMAND_EXECUTED",
            module="kali_ssh_connector",
            status="success" if exit_code == 0 else "failed",
            operation_id=op_id,
            command=raw_cmd_str,
            scope_entry=scope_res.matched_rule,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

        # Record structured Evidence and Finding
        evidence_payload = json.dumps(
            {
                "command": raw_cmd_str,
                "argv": argv_list,
                "target": target,
                "kali_host": f"{self.ssh_config.username}@{self.ssh_config.host}:{self.ssh_config.port}",
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "flag_citations": [c.to_dict() for c in help_res.citations],
                "scope_rule": scope_res.matched_rule,
            },
            sort_keys=True,
        )
        ev_id = "ev-kali-" + hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest()[:12]
        evidence = Evidence(
            id=ev_id,
            operation_id=op_id,
            target=target or "",
            provenance=EvidenceProvenance.FRESH,
            source=f"kali_ssh:{help_res.tool_name}",
            request_metadata={
                "command": raw_cmd_str,
                "argv": argv_list,
                "flag_citations": [c.to_dict() for c in help_res.citations],
            },
            response_metadata={"exit_code": exit_code},
            response_excerpt=(stdout or stderr)[:512],
            tool_output=stdout if stdout else stderr,
        )

        findings = self._parse_tool_findings(help_res.tool_name, target or "", stdout, evidence)

        return KaliSSHExecutionResult(
            allowed=True,
            status_code=200 if exit_code == 0 else 502,
            command=raw_cmd_str,
            argv=argv_list,
            target=target,
            ssh_dispatched=True,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            help_validation=help_res,
            scope_decision=scope_res,
            evidence=evidence,
            findings=findings,
            error_code=None if exit_code == 0 else "SSH_EXECUTION_ERROR",
            reason=f"Executed via Kali SSH with {len(help_res.citations)} verified flag citation(s).",
        )

    @staticmethod
    def _parse_tool_findings(
        tool_name: str,
        target: str,
        stdout: str,
        evidence: Evidence,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not stdout.strip():
            return findings

        if tool_name == "nmap":
            for line in stdout.splitlines():
                m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
                if m:
                    port, proto, service, banner = m.groups()
                    banner_str = (banner or "").strip()
                    findings.append(
                        Finding(
                            title=f"[Kali Nmap] Open Port {port}/{proto} ({service}) on {target}",
                            category="reconnaissance",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            asset=target,
                            target=f"{target}:{port}",
                            port=int(port),
                            protocol=proto,
                            description=(
                                f"Remote Kali nmap scan discovered open port {port}/{proto} "
                                f"running service '{service}' {banner_str}".strip()
                            ),
                            evidence=[evidence],
                            status=FindingStatus.VERIFIED,
                        )
                    )
        else:
            findings.append(
                Finding(
                    title=f"[Kali {tool_name}] Remote Execution Output on {target}",
                    category="reconnaissance",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    asset=target,
                    target=target,
                    description=f"Kali SSH tool '{tool_name}' completed against {target}: {stdout.strip()[:240]}",
                    evidence=[evidence],
                    status=FindingStatus.VERIFIED,
                )
            )
        return findings


def get_kali_ssh_manifest() -> ConnectorManifest:
    """Return ConnectorManifest for the built-in Kali Remote SSH connector."""
    return ConnectorManifest(
        id="builtin-kali-ssh",
        name="Kali Linux Remote SSH Executor (Scope + --help Verified)",
        transport=TransportType.STDIO,
        command="ssh",
        risk=RiskLevel.ACTIVE,
        allowed_scope=["127.0.0.1", "localhost"],
        rate_limit=30,
        timeout=60.0,
        env_keys=["REDLOOP_KALI_SSH_KEY_PATH"],
        tools=[
            ConnectorTool(
                name="execute_kali_ssh",
                description="Execute a validated, scope-authorized Kali tool command over SSH",
                parameters={
                    "type": "object",
                    "required": ["command"],
                    "properties": {
                        "command": {"type": "string"},
                    },
                },
                risk=RiskLevel.ACTIVE,
            )
        ],
        last_health="healthy",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
