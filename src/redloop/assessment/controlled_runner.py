"""Controlled, scope-enforced tool execution layer for REDLOOP.

Enforces:
1. Central Authorization Gate (Scope contract checked before ANY network subprocess or probe).
2. Fail-closed security: Unauthorized targets receive NO subprocess execution and NO network traffic.
3. Truthful, categorized operational errors (never disguised as AI refusals).
4. Deterministic structured output, cryptographic SHA-256 evidence, and audit logs.
"""

from __future__ import annotations

import hashlib
import httpx
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from redloop.assessment.capability import get_capabilities
from redloop.assessment.models import (
    Confidence,
    Evidence,
    EvidenceProvenance,
    ExecutionClass,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.tool_registry import ToolDefinition, ToolRiskLevel, get_tool_registry
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, UnauthorizedTargetError


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]


@dataclass
class ToolExecutionResult:
    tool_name: str
    status: StageStatus
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    target: str = ""
    command_executed: list[str] = field(default_factory=list)
    structured_output: dict[str, Any] = field(default_factory=dict)
    evidence: Evidence | None = None
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    error_code: str | None = None  # AUTHORIZATION_BLOCKED, TOOL_NOT_INSTALLED, TOOL_EXECUTION_FAILED, TIMEOUT, etc.
    audit_event: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "target": self.target,
            "command_executed": self.command_executed,
            "structured_output": self.structured_output,
            "evidence_id": self.evidence.id if self.evidence else None,
            "findings_count": len(self.findings),
            "reason": self.reason,
            "error_code": self.error_code,
            "error_category": self.error_code,
        }


class ControlledToolRunner:
    """Master controller executing authorized security tools behind central scope enforcement."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.capabilities = get_capabilities()

    def get_tool_diagnostics(self) -> dict[str, Any]:
        """Return diagnostic health check for all supported tools without leaking secrets."""
        nmap_path = shutil.which("nmap")
        if not nmap_path and os.name == "nt":
            for candidate in [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]:
                if os.path.exists(candidate):
                    nmap_path = candidate
                    break

        nmap_version = None
        if nmap_path:
            try:
                proc = subprocess.run(
                    [nmap_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                )
                if proc.returncode == 0:
                    first_line = proc.stdout.splitlines()[0] if proc.stdout else ""
                    v_match = re.search(r"Nmap version (\d+\.\d+)", first_line)
                    nmap_version = v_match.group(1) if v_match else first_line
            except Exception:
                nmap_version = "installed"

        nikto_path = shutil.which("nikto") or shutil.which("nikto.pl")
        gobuster_path = shutil.which("gobuster")
        curl_path = shutil.which("curl")
        openssl_path = shutil.which("openssl")
        dig_path = shutil.which("dig") or shutil.which("nslookup")

        auth_ready = bool(
            self.scope_guard
            and self.scope_guard.scope_manager
            and self.scope_guard.scope_manager.is_within_window()
        )

        docker_available = bool(shutil.which("docker"))
        wsl_available = bool(shutil.which("wsl"))

        return {
            "nmap": {
                "installed": bool(nmap_path),
                "executable_path": nmap_path,
                "version": nmap_version,
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "network",
                "risk_class": "ACTIVE_PROBE",
                "installation_guide": {
                    "windows": "Download Nmap installer from https://nmap.org/download.html or choco install nmap",
                    "kali_debian": "sudo apt-get update && sudo apt-get install -y nmap",
                    "docker": "docker run --rm -it instrumentisto/nmap -sT <target>",
                },
                "docker_available": docker_available,
                "wsl_available": wsl_available,
            },
            "nikto": {
                "installed": bool(nikto_path),
                "executable_path": nikto_path,
                "version": "installed" if nikto_path else None,
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "web",
                "risk_class": "ACTIVE_PROBE",
                "installation_guide": {
                    "windows": "choco install nikto  OR  scoop install nikto",
                    "kali_debian": "sudo apt-get update && sudo apt-get install -y nikto",
                    "docker": "docker run --rm -it secsi/nikto -h <target>",
                },
                "docker_available": docker_available,
                "wsl_available": wsl_available,
            },
            "gobuster": {
                "installed": bool(gobuster_path),
                "executable_path": gobuster_path,
                "version": "installed" if gobuster_path else None,
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "web",
                "risk_class": "ACTIVE_PROBE",
                "installation_guide": {
                    "windows": "go install github.com/OJ/gobuster/v3@latest",
                    "kali_debian": "sudo apt-get update && sudo apt-get install -y gobuster",
                    "docker": "docker run --rm -it oj/gobuster dir -u http://<target> -w <wordlist>",
                },
                "docker_available": docker_available,
                "wsl_available": wsl_available,
            },
            "tls_engine": {
                "installed": True,
                "executable_path": openssl_path or "built-in python ssl",
                "version": ssl.OPENSSL_VERSION,
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "tls",
                "risk_class": "SAFE_READONLY",
            },
            "dns_engine": {
                "installed": True,
                "executable_path": dig_path or "built-in socket resolver",
                "version": "built-in",
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "dns",
                "risk_class": "SAFE_READONLY",
            },
            "http_engine": {
                "installed": True,
                "executable_path": curl_path or "built-in http client",
                "version": "built-in",
                "execution_backend_available": True,
                "authorization_system_available": auth_ready,
                "category": "web",
                "risk_class": "ACTIVE_PROBE",
            },
            "forensics_triage": {
                "installed": True,
                "executable_path": "built-in hashlib/math",
                "version": "built-in",
                "execution_backend_available": True,
                "authorization_system_available": True,
                "category": "forensics",
                "risk_class": "INSPECTION",
            },
        }

    def _normalize_target(self, target: str) -> str:
        t = target.strip()
        t = re.sub(r"^https?://", "", t, flags=re.IGNORECASE)
        t = t.split("/")[0]
        t = t.split(":")[0]
        return t

    def execute_tool(
        self,
        tool_name: str,
        target: str,
        ports: list[int] | None = None,
        arguments: list[str] | dict[str, Any] | None = None,
        operation_id: str = "op-default",
        timeout_seconds: float = 25.0,
    ) -> ToolExecutionResult:
        """Central entrypoint executing an authorized tool behind the scope gate."""
        norm_tool = tool_name.lower().strip()
        norm_target = self._normalize_target(target)

        if norm_tool in ("nmap", "nmap_scanner", "port_scan", "tool_ports"):
            return self.run_nmap(norm_target, ports=ports, timeout_seconds=timeout_seconds, operation_id=operation_id)
        elif norm_tool in ("nikto", "web_vulnerability_scan"):
            return self.run_nikto(norm_target, timeout_seconds=timeout_seconds, operation_id=operation_id)
        elif norm_tool in ("gobuster", "dir_buster", "dir_fuzzer", "web_directory_fuzzer"):
            res = self.run_gobuster(norm_target, timeout_seconds=timeout_seconds, operation_id=operation_id)
            if res.error_code == "TOOL_NOT_INSTALLED":
                return self.run_web_directory_fuzz(norm_target, timeout_seconds=timeout_seconds, operation_id=operation_id)
            return res
        elif norm_tool in ("dns", "dns_scanner", "tool_dns"):
            return self.run_dns(norm_target, timeout_seconds=timeout_seconds, operation_id=operation_id)
        elif norm_tool in ("tls", "tls_checker", "tool_tls"):
            return self.run_tls(norm_target, port=ports[0] if ports else 443, timeout_seconds=timeout_seconds, operation_id=operation_id)
        elif norm_tool in ("web", "web_checker", "tool_web"):
            return self.run_http(norm_target, timeout_seconds=timeout_seconds, operation_id=operation_id)
        elif norm_tool in ("forensics", "forensics_triage"):
            file_path = str(arguments.get("file_path", "")) if isinstance(arguments, dict) else (arguments[0] if arguments else "")
            return self.run_forensics(file_path, operation_id=operation_id)
        else:
            return ToolExecutionResult(
                tool_name=tool_name,
                status=StageStatus.FAILED,
                exit_code=-1,
                reason=f"Unknown tool '{tool_name}'",
                error_code="TOOL_UNKNOWN",
            )

    # =========================================================================
    def _port_authorized(self, target: str, action: str, port: int) -> bool:
        if not self.scope_guard:
            return False
        try:
            self.scope_guard.is_target_authorized(target, action, port=port)
            return True
        except Exception:
            return False

    def _web_port_authorized(self, target: str, port: int = 80) -> bool:
        return self._port_authorized(target, "web_check", port)

    # 1. NMAP EXECUTION WITH CENTRAL AUTHORIZATION GATE
    # =========================================================================

    def run_nmap(
        self,
        target: str,
        ports: list[int] | None = None,
        timeout_seconds: float = 30.0,
        operation_id: str = "op-nmap",
    ) -> ToolExecutionResult:
        """Execute Nmap strictly through central scope authorization."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        # 1. Central Authorization Gate (enumerate only scope-authorized ports)
        if not self.scope_guard:
            scope_entry = None
        else:
            try:
                scope_entry = self.scope_guard.is_target_authorized(
                    target, "scan", require_port=False
                )
            except Exception:
                scope_entry = None
        if scope_entry is None:
            if self.audit:
                self.audit.blocked(
                    target,
                    "scan",
                    "nmap",
                    f"Target '{target}' is not authorized by the active signed scope policy.",
                )
            return ToolExecutionResult(
                tool_name="nmap",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                stderr=f"Target '{target}' is not authorized by the active signed scope policy.",
                reason="Target unauthorized. Nmap execution blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        # 2. Check if Nmap binary is physically available
        nmap_path = shutil.which("nmap")
        if not nmap_path and os.name == "nt":
            for candidate in [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]:
                if os.path.exists(candidate):
                    nmap_path = candidate
                    break

        if not nmap_path:
            return ToolExecutionResult(
                tool_name="nmap",
                status=StageStatus.UNAVAILABLE,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Nmap execution unavailable: executable not found.",
                error_code="TOOL_NOT_INSTALLED",
            )

        # 3. Determine authorized ports; never scan a port outside scope.
        requested_ports = ports or list(scope_entry.ports or [80, 443, 8080])
        target_ports = [
            p for p in requested_ports
            if scope_entry.ports is None or p in scope_entry.ports
        ]
        if not target_ports:
            return ToolExecutionResult(
                tool_name="nmap",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="None of the requested ports are authorized by the signed scope.",
                error_code="AUTHORIZATION_BLOCKED",
            )
        port_spec = ",".join(str(p) for p in target_ports[:32])

        # 4. Construct strict argument list (NO shell=True)
        # Using TCP connect scan (-sT), skip host discovery (-Pn), version detection (-sV)
        cmd = [nmap_path, "-sT", "-Pn", "-sV", "-p", port_spec, target]

        if self.audit:
            self.audit.log(
                target,
                "scan",
                "nmap",
                "started",
                {"command": " ".join(cmd), "ports": target_ports[:32]},
            )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
            duration = round(time.monotonic() - t0, 2)
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name="nmap",
                status=StageStatus.TIMEOUT,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                command_executed=cmd,
                reason=f"Nmap execution timed out after {timeout_seconds}s.",
                error_code="TIMEOUT",
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name="nmap",
                status=StageStatus.FAILED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                command_executed=cmd,
                stderr=str(exc),
                reason=f"Nmap execution failed: {exc}",
                error_code="TOOL_EXECUTION_FAILED",
            )

        # 5. Parse output into structured results
        discovered_ports = []
        for line in stdout.splitlines():
            line = line.strip()
            # Matching lines like: 80/tcp open http Apache httpd 2.4.41
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)?\s*(.*)$", line)
            if m:
                p_num = int(m.group(1))
                p_proto = m.group(2)
                p_state = m.group(3)
                p_svc = m.group(4) or "unknown"
                p_ver = m.group(5).strip() or None
                if p_state.lower() == "open":
                    discovered_ports.append({
                        "port": p_num,
                        "protocol": p_proto,
                        "state": p_state,
                        "service": p_svc,
                        "version": p_ver,
                    })

        # 6. Create cryptographic Evidence
        evidence = Evidence(
            operation_id=operation_id,
            target=target,
            source="nmap",
            provenance=EvidenceProvenance.FRESH,
            request_metadata={"command": cmd, "target_ports": target_ports[:32]},
            response_metadata={"exit_code": exit_code, "open_ports_count": len(discovered_ports)},
            response_excerpt=stdout[:1000],
            tool_output=stdout,
            parser_result={"open_ports": discovered_ports},
        )

        # 7. Create Findings for risky or unencrypted services
        findings: list[Finding] = []
        for dp in discovered_ports:
            p = dp["port"]
            svc = dp["service"].lower()
            if p in (21, 23) or "telnet" in svc or "ftp" in svc:
                findings.append(
                    Finding(
                        title=f"Unencrypted Service Detected ({dp['service'].upper()}:{p})",
                        category="Network Security",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        asset=target,
                        target=target,
                        port=p,
                        protocol=dp["protocol"],
                        description=f"Service '{dp['service']}' running on port {p} transmits credentials and telemetry in cleartext without TLS encapsulation.",
                        remediation="Migrate service to encrypted alternative (e.g. SFTP/SSH over port 22 or TLS encapsulation).",
                        evidence=[evidence],
                        detection_method="nmap_version_detection",
                        risk_score=7.5,
                    )
                )

        if self.audit:
            self.audit.log(
                target,
                "scan",
                "nmap",
                "success" if exit_code == 0 else "failed",
                {
                    "open_ports_count": len(discovered_ports),
                    "open_ports": [dp["port"] for dp in discovered_ports],
                    "duration_seconds": duration,
                    "evidence_id": evidence.id,
                },
            )

        status = StageStatus.SUCCESS if exit_code == 0 else StageStatus.FAILED
        reason = (
            f"Nmap discovered {len(discovered_ports)} open TCP port(s) on {target} in {duration}s."
            if discovered_ports
            else f"Nmap completed scan on {target}; 0 target ports were open."
        )

        return ToolExecutionResult(
            tool_name="nmap",
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            target=target,
            command_executed=cmd,
            structured_output={"open_ports": discovered_ports},
            evidence=evidence,
            findings=findings,
            reason=reason,
        )

    # =========================================================================
    # 2. NIKTO WEB VULNERABILITY SCANNER
    # =========================================================================

    def run_nikto(
        self,
        target: str,
        timeout_seconds: float = 30.0,
        operation_id: str = "op-nikto",
    ) -> ToolExecutionResult:
        """Execute Nikto web scanner with scope authorization gate."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self._web_port_authorized(target):
            return ToolExecutionResult(
                tool_name="nikto",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. Nikto execution blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        nikto_path = shutil.which("nikto") or shutil.which("nikto.pl")
        if not nikto_path:
            return ToolExecutionResult(
                tool_name="nikto",
                status=StageStatus.UNAVAILABLE,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Nikto execution unavailable: executable not found in PATH.",
                error_code="TOOL_NOT_INSTALLED",
            )

        cmd = [nikto_path, "-h", target, "-Tuning", "123b", "-timeout", "5"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            duration = round(time.monotonic() - t0, 2)
            evidence = Evidence(
                operation_id=operation_id,
                target=target,
                source="nikto",
                tool_output=proc.stdout,
                response_excerpt=proc.stdout[:1000],
            )
            return ToolExecutionResult(
                tool_name="nikto",
                status=StageStatus.SUCCESS if proc.returncode == 0 else StageStatus.FAILED,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=duration,
                target=target,
                command_executed=cmd,
                evidence=evidence,
                reason=f"Nikto web check completed on {target} in {duration}s.",
            )
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name="nikto",
                status=StageStatus.TIMEOUT,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                reason="Nikto scan timed out.",
                error_code="TIMEOUT",
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name="nikto",
                status=StageStatus.FAILED,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                stderr=str(exc),
                reason=f"Nikto execution failed: {exc}",
                error_code="TOOL_EXECUTION_FAILED",
            )

    # =========================================================================
    # 3. GOBUSTER DIRECTORY/FILE ENUMERATOR
    # =========================================================================

    def run_gobuster(
        self,
        target: str,
        timeout_seconds: float = 20.0,
        operation_id: str = "op-gobuster",
    ) -> ToolExecutionResult:
        """Execute Gobuster directory prober with scope authorization gate."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self._web_port_authorized(target):
            return ToolExecutionResult(
                tool_name="gobuster",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. Gobuster execution blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        gobuster_path = shutil.which("gobuster")
        if not gobuster_path:
            return ToolExecutionResult(
                tool_name="gobuster",
                status=StageStatus.UNAVAILABLE,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Gobuster execution unavailable: executable not found in PATH.",
                error_code="TOOL_NOT_INSTALLED",
            )

        # Wordlist check
        wordlist = "common.txt"
        cmd = [gobuster_path, "dir", "-u", f"http://{target}", "-w", wordlist, "-q"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            duration = round(time.monotonic() - t0, 2)
            evidence = Evidence(
                operation_id=operation_id,
                target=target,
                source="gobuster",
                tool_output=proc.stdout,
                response_excerpt=proc.stdout[:1000],
            )
            return ToolExecutionResult(
                tool_name="gobuster",
                status=StageStatus.SUCCESS if proc.returncode == 0 else StageStatus.FAILED,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=duration,
                target=target,
                command_executed=cmd,
                evidence=evidence,
                reason=f"Gobuster directory scan completed on {target} in {duration}s.",
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name="gobuster",
                status=StageStatus.FAILED,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                stderr=str(exc),
                reason=f"Gobuster execution failed: {exc}",
                error_code="TOOL_EXECUTION_FAILED",
            )

    def test_tool_installation(self, tool_name: str) -> dict[str, Any]:
        """Execute a safe --version or -help check to verify installation readiness."""
        diag = self.get_tool_diagnostics().get(tool_name.lower().strip(), {})
        if not diag.get("installed"):
            return {
                "tool": tool_name,
                "installed": False,
                "status": "NOT_INSTALLED",
                "installation_guide": diag.get("installation_guide", {}),
            }
        path = diag.get("executable_path")
        flag = "-Version" if "nikto" in tool_name.lower() else "--version"
        try:
            p = subprocess.run([path, flag], capture_output=True, text=True, timeout=5.0)
            return {
                "tool": tool_name,
                "installed": True,
                "status": "OPERATIONAL" if p.returncode == 0 else "WARNING",
                "exit_code": p.returncode,
                "output": (p.stdout or p.stderr)[:300],
            }
        except Exception as exc:
            return {
                "tool": tool_name,
                "installed": True,
                "status": "EXECUTION_ERROR",
                "error": str(exc),
            }

    def run_web_directory_fuzz(
        self,
        target: str,
        paths: list[str] | None = None,
        timeout_seconds: float = 15.0,
        operation_id: str = "op-fuzz",
    ) -> ToolExecutionResult:
        """Controlled Python directory and file prober behind the scope gate."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self._web_port_authorized(target):
            return ToolExecutionResult(
                tool_name="web_directory_fuzzer",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. Directory fuzzing blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        fuzz_paths = paths or [
            "/robots.txt", "/admin", "/login", "/api", "/config",
            "/.env", "/.git/HEAD", "/server-status", "/swagger.json",
        ]

        discovered: list[dict[str, Any]] = []
        findings: list[Finding] = []
        with httpx.Client(timeout=3.0, follow_redirects=False) as client:
            for p in fuzz_paths:
                url = f"http://{target}{p}"
                try:
                    res = client.get(url)
                    if res.status_code in (200, 301, 302, 401, 403):
                        discovered.append({"path": p, "status": res.status_code, "size": len(res.content)})
                        if p in ("/.env", "/.git/HEAD") and res.status_code == 200:
                            findings.append(
                                Finding(
                                    title=f"Sensitive File Exposed via HTTP ({p})",
                                    category="Information Disclosure",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    asset=target,
                                    target=target,
                                    description=f"Direct HTTP access to sensitive endpoint '{p}' returned HTTP 200.",
                                    remediation="Restrict access to configuration files and dotfiles at the web server.",
                                    risk_score=7.0,
                                )
                            )
                except Exception:
                    continue

        duration = round(time.monotonic() - t0, 2)
        evidence = Evidence(
            operation_id=operation_id,
            target=target,
            source="web_directory_fuzzer",
            tool_output=json.dumps(discovered, indent=2),
            response_excerpt=f"Probed {len(fuzz_paths)} paths, found {len(discovered)} active.",
            parser_result={"discovered_paths": discovered},
        )

        return ToolExecutionResult(
            tool_name="web_directory_fuzzer",
            status=StageStatus.SUCCESS,
            exit_code=0,
            stdout=json.dumps(discovered, indent=2),
            duration_seconds=duration,
            target=target,
            structured_output={"discovered_paths": discovered},
            evidence=evidence,
            findings=findings,
            reason=f"Python directory fuzzer identified {len(discovered)} endpoint(s) on {target}.",
        )

    # =========================================================================
    # 4. DNS INSPECTION
    # =========================================================================

    def run_dns(
        self,
        target: str,
        timeout_seconds: float = 10.0,
        operation_id: str = "op-dns",
    ) -> ToolExecutionResult:
        """Resolve DNS records safely behind central scope validation."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self.scope_guard or not self.scope_guard.is_authorized(target, "dns_check"):
            return ToolExecutionResult(
                tool_name="dns_engine",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. DNS lookup blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        records: dict[str, Any] = {}
        try:
            # Resolve IPv4
            ip_list = socket.gethostbyname_ex(target)[2]
            records["A"] = ip_list
            duration = round(time.monotonic() - t0, 2)
            ev = Evidence(
                operation_id=operation_id,
                target=target,
                source="dns_engine",
                request_metadata={"query": target, "type": "A"},
                response_metadata={"records": records},
                tool_output=json.dumps(records, indent=2),
                parser_result={"records": records},
            )
            return ToolExecutionResult(
                tool_name="dns_engine",
                status=StageStatus.SUCCESS,
                exit_code=0,
                stdout=json.dumps(records),
                duration_seconds=duration,
                target=target,
                structured_output={"records": records},
                evidence=ev,
                reason=f"Resolved DNS A records for {target}: {ip_list}",
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name="dns_engine",
                status=StageStatus.FAILED,
                duration_seconds=round(time.monotonic() - t0, 2),
                target=target,
                stderr=str(exc),
                reason=f"DNS resolution failed: {exc}",
                error_code="TOOL_EXECUTION_FAILED",
            )

    # =========================================================================
    # 5. TLS INSPECTION
    # =========================================================================

    def run_tls(
        self,
        target: str,
        port: int = 443,
        timeout_seconds: float = 12.0,
        operation_id: str = "op-tls",
    ) -> ToolExecutionResult:
        """Inspect TLS certificate chain and cipher suites behind scope authorization."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self.scope_guard or not self._port_authorized(target, "tls_check", port):
            return ToolExecutionResult(
                tool_name="tls_engine",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. TLS inspection blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        from redloop.assessment.tls_engine import TLSEngine
        engine = TLSEngine(self.scope_guard, self.audit)
        stage_res = engine.assess_target(target, port=port)
        duration = round(time.monotonic() - t0, 2)

        ev = stage_res.evidence[0] if stage_res.evidence else None
        return ToolExecutionResult(
            tool_name="tls_engine",
            status=stage_res.status,
            exit_code=0 if stage_res.status == StageStatus.SUCCESS else -1,
            stdout=ev.tool_output if ev else "",
            duration_seconds=duration,
            target=target,
            structured_output=ev.parser_result if ev else {},
            evidence=ev,
            findings=stage_res.findings,
            reason=stage_res.reason,
        )

    # =========================================================================
    # 6. HTTP SECURITY HEADER INSPECTION
    # =========================================================================

    def run_http(
        self,
        target: str,
        timeout_seconds: float = 12.0,
        operation_id: str = "op-http",
    ) -> ToolExecutionResult:
        """Inspect HTTP security headers behind scope authorization."""
        t0 = time.monotonic()
        target = self._normalize_target(target)

        if not self._web_port_authorized(target):
            return ToolExecutionResult(
                tool_name="web_engine",
                status=StageStatus.BLOCKED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=target,
                reason="Target unauthorized. Web inspection blocked by scope policy.",
                error_code="AUTHORIZATION_BLOCKED",
            )

        from redloop.assessment.web_engine import WebEngine
        engine = WebEngine(self.scope_guard, self.audit)
        stage_res = engine.assess_url(f"http://{target}")
        duration = round(time.monotonic() - t0, 2)

        ev = stage_res.evidence[0] if stage_res.evidence else None
        return ToolExecutionResult(
            tool_name="web_engine",
            status=stage_res.status,
            exit_code=0 if stage_res.status == StageStatus.SUCCESS else -1,
            stdout=ev.tool_output if ev else "",
            duration_seconds=duration,
            target=target,
            structured_output=ev.parser_result if ev else {},
            evidence=ev,
            findings=stage_res.findings,
            reason=stage_res.reason,
        )

    # =========================================================================
    # 7. FORENSICS ARTIFACT TRIAGE (LOCAL ONLY)
    # =========================================================================

    def run_forensics(
        self,
        file_path: str,
        operation_id: str = "op-forensics",
    ) -> ToolExecutionResult:
        """Inspect local file artifact (entropy, hashes, strings) strictly local."""
        t0 = time.monotonic()
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return ToolExecutionResult(
                tool_name="forensics_triage",
                status=StageStatus.FAILED,
                exit_code=-1,
                duration_seconds=round(time.monotonic() - t0, 3),
                target=file_path,
                reason=f"File '{file_path}' does not exist or is not a readable file.",
                error_code="FILE_NOT_FOUND",
            )

        data = p.read_bytes()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        # Simple entropy
        import math
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        for c in counts:
            if c > 0:
                prob = c / len(data)
                entropy -= prob * math.log2(prob)

        res_dict = {
            "filename": p.name,
            "size_bytes": len(data),
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "entropy": round(entropy, 4),
            "is_suspicious_entropy": entropy > 7.2,
        }

        ev = Evidence(
            operation_id=operation_id,
            target=p.name,
            source="forensics_triage",
            request_metadata={"file_path": str(p)},
            response_metadata=res_dict,
            tool_output=json.dumps(res_dict, indent=2),
            parser_result=res_dict,
        )

        return ToolExecutionResult(
            tool_name="forensics_triage",
            status=StageStatus.SUCCESS,
            exit_code=0,
            stdout=json.dumps(res_dict, indent=2),
            duration_seconds=round(time.monotonic() - t0, 3),
            target=p.name,
            structured_output=res_dict,
            evidence=ev,
            reason=f"Forensic triage analyzed {p.name} ({len(data)} bytes, entropy: {round(entropy, 2)}).",
        )
