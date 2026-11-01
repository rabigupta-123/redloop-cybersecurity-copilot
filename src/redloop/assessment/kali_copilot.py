"""Kali Linux Cybersecurity Copilot & Terminal Intelligence Module.

Provides step-by-step guidance, troubleshooting, tool output parsing, and command synthesis for Kali Linux workflows:
- Nmap, Masscan, Netcat, tcpdump, Wireshark/tshark
- Burp Suite, SQLMap, Gobuster, Nikto, Feroxbuster, FFuf
- Metasploit, Hydra, John the Ripper, Hashcat
- Linux system administration, permissions, networking (ip, ss, iptables, nftables, systemctl, journalctl)
- Python, Bash, Docker, Suricata, Yara, PCAP analysis

Strict security boundary:
- Never executes or transmits raw live attacks against unauthorized external targets.
- Clearly states authorization requirements when suggested commands target external hosts.
- Structured response architecture: COMMAND | PURPOSE | EXPECTED RESULT | WHAT TO DO IF IT FAILS.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from redloop.assessment.models import Evidence, EvidenceProvenance, StageStatus
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger


class KaliCommandState(str, Enum):
    SUGGESTED = "SUGGESTED"
    READY = "READY"
    AUTHORIZATION_REQUIRED = "AUTHORIZATION REQUIRED"
    BLOCKED = "BLOCKED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class KaliCommandRisk(str, Enum):
    SAFE_READONLY = "SAFE_READONLY"
    INSPECTION = "INSPECTION"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    DANGEROUS = "DANGEROUS"


@dataclass
class ParsedKaliCommand:
    raw_command: str
    binary: str
    args: list[str]
    risk: KaliCommandRisk
    target: str | None
    is_network: bool
    is_dangerous: bool
    state: KaliCommandState = KaliCommandState.SUGGESTED
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_command": self.raw_command,
            "binary": self.binary,
            "args": self.args,
            "risk": self.risk.value,
            "target": self.target,
            "is_network": self.is_network,
            "is_dangerous": self.is_dangerous,
            "state": self.state.value,
            "reason": self.reason,
        }


class KaliCommandParser:
    """Safely normalizes Kali Linux commands, extracts targets, and classifies operational risk."""

    DANGEROUS_PATTERNS = [
        r"\brm\s+(-[rfRF]+\s+)?(/|\*|~|/\w+)",
        r"\bmkfs\b",
        r"\bdd\s+if=",
        r">\s*/dev/sd[a-z]",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        r"\b(shutdown|reboot|init\s+0|poweroff)\b",
    ]

    NETWORK_TOOLS = {
        "nmap", "ping", "traceroute", "tracepath", "curl", "wget", "dig", "nslookup",
        "whois", "openssl", "nikto", "gobuster", "feroxbuster", "ffuf", "masscan",
        "nc", "netcat", "socat", "sqlmap", "hydra",
    }

    LOCAL_SAFE_TOOLS = {
        "uname", "id", "whoami", "uptime", "hostname", "which", "whereis", "file",
        "strings", "cat", "grep", "awk", "sed", "stat", "date", "ps", "top",
        "sha256sum", "md5sum", "sha1sum", "head", "tail", "wc", "ls", "pwd",
        "ss", "ip", "netstat", "route", "ifconfig",
    }

    @classmethod
    def parse(cls, command: str) -> ParsedKaliCommand:
        cmd_str = command.strip()
        # Remove leading sudo if present for binary extraction
        clean_cmd = re.sub(r"^\s*sudo\s+", "", cmd_str)

        # 1. Dangerous pattern check
        for pat in cls.DANGEROUS_PATTERNS:
            if re.search(pat, cmd_str, re.IGNORECASE):
                return ParsedKaliCommand(
                    raw_command=cmd_str,
                    binary="unknown",
                    args=[],
                    risk=KaliCommandRisk.DANGEROUS,
                    target=None,
                    is_network=False,
                    is_dangerous=True,
                    state=KaliCommandState.BLOCKED,
                    reason="Dangerous or destructive command pattern blocked by REDLOOP safety policy.",
                )

        try:
            tokens = shlex.split(clean_cmd)
        except Exception:
            tokens = clean_cmd.split()

        if not tokens:
            return ParsedKaliCommand(
                raw_command=cmd_str,
                binary="",
                args=[],
                risk=KaliCommandRisk.SAFE_READONLY,
                target=None,
                is_network=False,
                is_dangerous=False,
                state=KaliCommandState.FAILED,
                reason="Empty command.",
            )

        binary = tokens[0].lower()
        args = tokens[1:]

        # 2. Network tool detection & Target extraction
        is_network = binary in cls.NETWORK_TOOLS
        target = None

        if is_network:
            # Extract target from args
            for i, arg in enumerate(args):
                if arg in ("-h", "--host", "-u", "--url", "-target") and i + 1 < len(args):
                    target = args[i + 1]
                    break
                # IP address match
                if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", arg):
                    target = arg
                    break
                # Hostname / domain match
                if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", arg) and not arg.startswith("-"):
                    target = arg
                    break
                if arg.startswith("http://") or arg.startswith("https://"):
                    target = arg
                    break

            # If target not found in flags, check last positional non-flag token
            if not target:
                positional = [a for a in args if not a.startswith("-")]
                if positional:
                    target = positional[-1]

        # 3. Risk classification
        if is_network:
            risk = KaliCommandRisk.ACTIVE_PROBE
        elif binary in cls.LOCAL_SAFE_TOOLS:
            risk = KaliCommandRisk.SAFE_READONLY
        else:
            risk = KaliCommandRisk.INSPECTION

        return ParsedKaliCommand(
            raw_command=cmd_str,
            binary=binary,
            args=args,
            risk=risk,
            target=target,
            is_network=is_network,
            is_dangerous=False,
            state=KaliCommandState.READY if not is_network else KaliCommandState.AUTHORIZATION_REQUIRED,
            reason="Command parsed successfully.",
        )


class KaliCommandRunner:
    """Executes validated Kali commands behind central scope authorization."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit

    def execute(self, command: str, timeout_seconds: float = 20.0, operation_id: str = "op-kali") -> dict[str, Any]:
        """Execute command safely. Strictly verifies scope for network probes."""
        t0 = time.monotonic()
        parsed = KaliCommandParser.parse(command)

        # 1. Block dangerous commands
        if parsed.is_dangerous:
            if self.audit:
                self.audit.blocked(
                    "local",
                    "kali_execute",
                    "kali_runner",
                    f"Blocked dangerous command: {command}",
                )
            return {
                "command": command,
                "state": KaliCommandState.BLOCKED.value,
                "exit_code": -1,
                "stdout": "",
                "stderr": parsed.reason,
                "duration_seconds": round(time.monotonic() - t0, 3),
                "reason": parsed.reason,
                "target": None,
                "is_network": False,
            }

        # 2. Central scope check for network tools
        if parsed.is_network:
            target = parsed.target or "127.0.0.1"
            # Normalize target URL/hostname
            clean_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
            if not self.scope_guard or not self.scope_guard.is_authorized(clean_target):
                if self.audit:
                    self.audit.blocked(
                        clean_target,
                        "kali_execute",
                        "kali_runner",
                        f"Target '{clean_target}' outside active signed scope contract for command: {command}",
                    )
                return {
                    "command": command,
                    "state": KaliCommandState.BLOCKED.value,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Target '{clean_target}' is not authorized by the active signed scope policy.",
                    "duration_seconds": round(time.monotonic() - t0, 3),
                    "reason": f"Target unauthorized. Command execution blocked by scope policy.",
                    "target": clean_target,
                    "is_network": True,
                }

        # 3. Binary lookup
        bin_path = shutil.which(parsed.binary)
        if not bin_path and parsed.binary == "nmap" and os.name == "nt":
            for c in [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]:
                if os.path.exists(c):
                    bin_path = c
                    break

        if not bin_path:
            return {
                "command": command,
                "state": KaliCommandState.FAILED.value,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Binary '{parsed.binary}' not found in system PATH.",
                "duration_seconds": round(time.monotonic() - t0, 3),
                "reason": f"Executable unavailable: '{parsed.binary}' is not installed.",
                "target": parsed.target,
                "is_network": parsed.is_network,
            }

        # 4. Controlled Execution (NO shell=True)
        exec_args = [bin_path] + parsed.args
        if self.audit:
            self.audit.log(
                parsed.target or "localhost",
                "kali_execute",
                parsed.binary,
                "started",
                {"command": command},
            )

        try:
            proc = subprocess.run(
                exec_args,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
            duration = round(time.monotonic() - t0, 2)
            state = KaliCommandState.COMPLETED if exit_code == 0 else KaliCommandState.FAILED
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "state": KaliCommandState.FAILED.value,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout_seconds} seconds.",
                "duration_seconds": round(time.monotonic() - t0, 2),
                "reason": f"Execution timed out after {timeout_seconds}s.",
                "target": parsed.target,
                "is_network": parsed.is_network,
            }
        except Exception as exc:
            return {
                "command": command,
                "state": KaliCommandState.FAILED.value,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(exc),
                "duration_seconds": round(time.monotonic() - t0, 2),
                "reason": f"Execution failed: {exc}",
                "target": parsed.target,
                "is_network": parsed.is_network,
            }

        # 5. Create cryptographic evidence for successful commands
        ev_id = None
        if stdout:
            evidence = Evidence(
                operation_id=operation_id,
                target=parsed.target or "localhost",
                source=f"kali_{parsed.binary}",
                request_metadata={"command": command, "binary": parsed.binary},
                response_metadata={"exit_code": exit_code},
                tool_output=stdout,
                response_excerpt=stdout[:1000],
            )
            ev_id = evidence.id

        if self.audit:
            self.audit.log(
                parsed.target or "localhost",
                "kali_execute",
                parsed.binary,
                "success" if exit_code == 0 else "failed",
                {"exit_code": exit_code, "duration_seconds": duration, "evidence_id": ev_id},
            )

        return {
            "command": command,
            "state": state.value,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_seconds": duration,
            "reason": f"Command executed with exit code {exit_code}.",
            "target": parsed.target,
            "is_network": parsed.is_network,
            "evidence_id": ev_id,
        }


@dataclass
class KaliGuidance:
    command: str
    purpose: str
    expected_result: str
    failure_troubleshooting: str
    scope_notice: str | None = None
    state: KaliCommandState = KaliCommandState.SUGGESTED

    def to_markdown(self) -> str:
        lines = [
            f"#### 💻 Recommended Command (`{self.state.value}`)",
            f"```bash\n{self.command}\n```",
            f"- **🎯 Purpose:** {self.purpose}",
            f"- **📋 Expected Result:** {self.expected_result}",
            f"- **⚠️ Troubleshooting (If It Fails):** {self.failure_troubleshooting}",
        ]
        if self.scope_notice:
            lines.append(f"\n> 🛡️ **Scope Notice:** {self.scope_notice}")
        return "\n".join(lines)


class KaliCopilot:
    """Interprets Kali Linux tool execution, errors, and terminal workflows."""

    KNOWN_TOOLS = {
        "nmap": "Network exploration tool and security / port scanner",
        "gobuster": "Directory/file & DNS busting tool written in Go",
        "sqlmap": "Automatic SQL injection and database takeover tool",
        "hydra": "Parallelized network login cracker",
        "john": "John the Ripper password cracker",
        "hashcat": "Advanced password recovery utility",
        "wireshark": "Network protocol analyzer and packet capture suite",
        "tcpdump": "Command-line packet analyzer",
        "nikto": "Web server scanner for dangerous files and outdated software",
        "curl": "Command-line tool for transferring data with URLs",
        "dig": "DNS lookup utility",
        "openssl": "Cryptographic toolkit and TLS certificate inspection utility",
    }

    def __init__(self, scope_guard: AssessmentScopeGuard | None = None):
        self.scope_guard = scope_guard

    def analyze_terminal_problem(self, user_prompt: str) -> dict[str, Any]:
        """Analyze a terminal command failure or user question and produce structured guidance."""
        text = user_prompt.strip()
        lower = text.lower()

        # Check common Kali issues
        if "permission denied" in lower:
            tool_match = re.search(r"\b(nmap|tcpdump|wireshark|iptables|ss|netstat)\b", lower)
            tool = tool_match.group(1) if tool_match else "command"
            return {
                "detected_issue": "Permission Denied (Requires Elevated Privileges)",
                "tool": tool,
                "explanation": (
                    f"The tool `{tool}` requires raw socket access or administrative capabilities (CAP_NET_RAW) "
                    "which are restricted to the root user."
                ),
                "guidance": KaliGuidance(
                    command=f"sudo {tool} ...",
                    purpose=f"Run `{tool}` with superuser privileges to allow low-level network packet transmission.",
                    expected_result="Command executes without permission rejection.",
                    failure_troubleshooting="Verify your user account is in the `sudo` group with `groups`, or inspect `/etc/sudoers`.",
                ),
            }

        if "command not found" in lower:
            tool_match = re.search(r"(\w+):\s*command not found", lower) or re.search(r"\b(\w+)\s+not found", lower)
            tool = tool_match.group(1) if tool_match else "package"
            return {
                "detected_issue": f"Missing Package: {tool}",
                "tool": tool,
                "explanation": f"The `{tool}` utility is not installed in your current PATH or Kali distribution.",
                "guidance": KaliGuidance(
                    command=f"sudo apt update && sudo apt install -y {tool}",
                    purpose=f"Install `{tool}` from official Kali Linux repositories.",
                    expected_result=f"Package `{tool}` installs successfully and binary is available in `/usr/bin/{tool}`.",
                    failure_troubleshooting=f"If package is missing in apt, search with `apt-cache search {tool}` or check GitHub.",
                ),
            }

        if "connection refused" in lower:
            return {
                "detected_issue": "Connection Refused (TCP RST received)",
                "tool": "network",
                "explanation": "Target host actively reset the TCP handshake; no service is listening on the destination port, or a firewall rejected the probe.",
                "guidance": KaliGuidance(
                    command="ss -tulpn | grep -E ':(80|443|8080|22)'",
                    purpose="Check listening sockets on local system, or confirm remote port is open before probing.",
                    expected_result="List of active listening sockets and corresponding process IDs.",
                    failure_troubleshooting="Check firewall status with `sudo iptables -L -n -v` or verify target service daemon is active with `systemctl status <service>`.",
                ),
            }

        return {
            "detected_issue": "General Kali Linux Inquiry",
            "tool": "general",
            "explanation": "Interpreting terminal command context and providing operational workflow.",
            "guidance": None,
        }

    def analyze_terminal_output(self, raw_output: str, target: str | None = None) -> dict[str, Any]:
        """Ingest, parse, and analyze real terminal output from Kali security tools.

        Extracts structured findings, explains technical significance, produces cryptographic
        evidence hash, and recommends the next authorized investigation step.
        """
        output = raw_output.strip()
        evidence_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()
        evidence_id = f"ev_term_{evidence_hash[:12]}"

        # 1. Nmap Scan Detection & Parsing
        if (
            "Nmap" in output
            or "Nmap scan report for" in output
            or ("PORT" in output and ("STATE" in output or "open" in output))
            or bool(re.search(r"\b\d+/(tcp|udp)\s+(open|closed|filtered)\b", output))
        ):
            return self._parse_nmap_output(output, evidence_id, evidence_hash, target)

        # 2. Gobuster / Directory Enumeration Detection & Parsing
        if "gobuster" in output.lower() or ("Status: 200" in output or "Status: 301" in output or "Status: 403" in output):
            return self._parse_gobuster_output(output, evidence_id, evidence_hash, target)

        # 3. Nikto Web Scanner Detection & Parsing
        if "Nikto" in output or "+ Target IP:" in output or "+ Server:" in output:
            return self._parse_nikto_output(output, evidence_id, evidence_hash, target)

        # 4. HTTP Response / Headers Detection & Parsing
        if re.search(r"HTTP/[12](\.[01])?\s+\d{3}", output) or ("Content-Type:" in output and "Server:" in output):
            return self._parse_http_response_output(output, evidence_id, evidence_hash, target)

        # 5. Linux / Network Error Parsing
        if any(err in output.lower() for err in ["permission denied", "command not found", "no route to host", "connection refused", "timed out", "could not resolve host"]):
            return self._parse_terminal_error_output(output, evidence_id, evidence_hash, target)

        # Generic Output Fallback
        return {
            "tool_detected": "generic_terminal",
            "target": target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"Captured {len(output.splitlines())} lines of terminal output.",
            "findings": [{"type": "terminal_log", "lines_count": len(output.splitlines())}],
            "explanation": "Terminal log ingested. No recognized specialized security tool signature was detected.",
            "next_step": {
                "recommended_command": f"echo 'Log evidence verified: {evidence_id}'",
                "purpose": "Acknowledge and archive terminal output into investigation graph.",
                "prerequisites": "None",
                "flag_explanations": {},
                "expected_output": "Evidence receipt confirmation",
                "can_execute_via_redloop": True,
                "scope_status": "LOCAL_SAFE",
                "is_dangerous": False,
            },
        }

    def _parse_nmap_output(self, output: str, evidence_id: str, evidence_hash: str, target: str | None) -> dict[str, Any]:
        """Parse Nmap port scanning output."""
        extracted_target = target
        target_match = re.search(r"Nmap scan report for\s+([^\s\(\)]+)(?:\s+\(([^\)]+)\))?", output)
        if target_match:
            extracted_target = target_match.group(2) or target_match.group(1)

        ports: list[dict[str, Any]] = []
        port_lines = re.findall(r"(\d+)/(tcp|udp)\s+(\w+)\s+([^\r\n]+)", output)
        open_web_ports: list[int] = []
        for p_str, proto, state, svc in port_lines:
            p_int = int(p_str)
            ports.append({"port": p_int, "protocol": proto, "state": state, "service": svc.strip()})
            if state == "open" and (p_int in (80, 443, 8080, 8081, 8443) or "http" in svc.lower()):
                open_web_ports.append(p_int)

        t_display = extracted_target or "<target>"
        findings = [
            {"type": "open_port", "port": p["port"], "service": p["service"], "state": p["state"]}
            for p in ports if p["state"] == "open"
        ]

        # Determine next step
        if open_web_ports:
            web_port = open_web_ports[0]
            recommended_cmd = f"gobuster dir -u http://{t_display}:{web_port}/ -w /usr/share/wordlists/dirb/common.txt -t 20"
            purpose = f"Enumerate HTTP endpoints, hidden files, and administrative routes on open web port {web_port}."
            flags = {
                "dir": "Execute directory and file enumeration mode",
                "-u": f"Target URL (http://{t_display}:{web_port}/)",
                "-w": "Wordlist path containing common path entries",
                "-t 20": "Spawn 20 concurrent worker threads for speed",
            }
            expected = "Discovered routes returning HTTP 200, 301, 302, or 403 status codes."
        elif ports:
            open_p_list = ",".join(str(p["port"]) for p in ports if p["state"] == "open")
            recommended_cmd = f"nmap -sV -sC -p {open_p_list} {t_display}"
            purpose = f"Conduct deep service banner grabbing and default NSE script audit on open ports {open_p_list}."
            flags = {
                "-sV": "Probe open ports to determine service and version info",
                "-sC": "Execute default safe Nmap Scripting Engine (NSE) scripts",
                "-p": "Target specifically discovered open ports to minimize traffic",
            }
            expected = "Detailed version strings, OS fingerprint hints, and SSL/TLS configuration details."
        else:
            recommended_cmd = f"nmap -Pn -p 1-1000 {t_display}"
            purpose = "Retry port scan treating host as online (-Pn) in case ICMP ping was filtered."
            flags = {"-Pn": "Skip host discovery (treat all hosts as online)", "-p 1-1000": "Scan top 1000 ports"}
            expected = "Port state indications without ping failure."

        # Check scope authorization
        can_exec = False
        scope_status = "UNKNOWN_TARGET"
        if self.scope_guard and extracted_target:
            ports_to_check = [p["port"] for p in ports if p["state"] == "open"] or [80]
            allowed, reason = self.scope_guard.is_target_allowed(extracted_target, ports_to_check)
            can_exec = allowed
            scope_status = "AUTHORIZED" if allowed else f"BLOCKED: {reason}"

        return {
            "tool_detected": "nmap",
            "target": extracted_target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"Nmap scan discovered {len(findings)} open port(s) on target {t_display}.",
            "findings": findings,
            "explanation": (
                f"Identified {len(findings)} listening services on `{t_display}`. "
                + (f"Web services detected on port(s) {open_web_ports} warrant web-layer assessment. " if open_web_ports else "Target services require version enumeration.")
            ),
            "next_step": {
                "recommended_command": recommended_cmd,
                "purpose": purpose,
                "prerequisites": "Gobuster or Nmap installed on Kali / WSL / workstation",
                "flag_explanations": flags,
                "expected_output": expected,
                "can_execute_via_redloop": can_exec,
                "scope_status": scope_status,
                "is_dangerous": False,
            },
        }

    def _parse_gobuster_output(self, output: str, evidence_id: str, evidence_hash: str, target: str | None) -> dict[str, Any]:
        """Parse Gobuster directory fuzzing output."""
        findings = []
        path_matches = re.findall(r"(=>|\s|^)(/[^\s\(\)]+)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*(\d+)\])?", output)
        for _, path, status, size in path_matches:
            findings.append({"path": path, "status": int(status), "size": int(size) if size else None})

        t_display = target or "<target>"
        sensitive_found = [f for f in findings if any(s in f["path"] for s in [".env", ".git", "admin", "login", "config", "api"])]
        
        if sensitive_found:
            top_path = sensitive_found[0]["path"]
            recommended_cmd = f"curl -i -s http://{t_display}{top_path}"
            purpose = f"Inspect HTTP response headers and body content for potentially sensitive endpoint `{top_path}`."
        elif findings:
            top_path = findings[0]["path"]
            recommended_cmd = f"curl -i -s http://{t_display}{top_path}"
            purpose = f"Inspect HTTP response headers for discovered path `{top_path}`."
        else:
            recommended_cmd = f"gobuster dir -u http://{t_display}/ -w /usr/share/wordlists/dirb/big.txt -x php,html,txt"
            purpose = "Expand directory enumeration with broader wordlist and file extensions."

        return {
            "tool_detected": "gobuster",
            "target": target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"Gobuster discovered {len(findings)} reachable web path(s).",
            "findings": findings,
            "explanation": (
                f"Discovered {len(findings)} HTTP endpoints. "
                + (f"High-interest routes discovered: {[f['path'] for f in sensitive_found]}." if sensitive_found else "No obvious secret files found in common wordlist.")
            ),
            "next_step": {
                "recommended_command": recommended_cmd,
                "purpose": purpose,
                "prerequisites": "curl or python-requests",
                "flag_explanations": {"-i": "Include HTTP response headers in output", "-s": "Silent mode (suppress progress bar)"},
                "expected_output": "HTTP status code, Server header, and response payload.",
                "can_execute_via_redloop": True,
                "scope_status": "LOCAL_SAFE",
                "is_dangerous": False,
            },
        }

    def _parse_nikto_output(self, output: str, evidence_id: str, evidence_hash: str, target: str | None) -> dict[str, Any]:
        """Parse Nikto web server scanner output."""
        findings = []
        for line in output.splitlines():
            line_str = line.strip()
            if line_str.startswith("+") and not any(skip in line_str for skip in ["Target IP:", "Target Hostname:", "Target Port:", "Start Time:"]):
                findings.append({"finding": line_str.lstrip("+").strip()})

        server_match = re.search(r"\+\s+Server:\s+([^\r\n]+)", output)
        server_banner = server_match.group(1).strip() if server_match else "Unknown"

        t_display = target or "<target>"
        return {
            "tool_detected": "nikto",
            "target": target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"Nikto identified {len(findings)} web server configuration observations (Server: {server_banner}).",
            "findings": findings,
            "explanation": f"Web server identifies as `{server_banner}`. Identified {len(findings)} potential security observations or header omissions.",
            "next_step": {
                "recommended_command": f"redloop asvs evaluate http://{t_display}/",
                "purpose": "Perform systematic OWASP ASVS v4.0 verification of HTTP security headers and cookies.",
                "prerequisites": "REDLOOP ASVS Engine",
                "flag_explanations": {"evaluate": "Run ASVS checklist against target HTTP endpoint"},
                "expected_output": "Compliant vs Non-Compliant OWASP ASVS verification report.",
                "can_execute_via_redloop": True,
                "scope_status": "LOCAL_SAFE",
                "is_dangerous": False,
            },
        }

    def _parse_http_response_output(self, output: str, evidence_id: str, evidence_hash: str, target: str | None) -> dict[str, Any]:
        """Parse raw HTTP response and headers."""
        status_match = re.search(r"HTTP/[12](\.[01])?\s+(\d{3})\s+([^\r\n]*)", output)
        status_code = int(status_match.group(2)) if status_match else 200

        missing_headers = []
        for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]:
            if not re.search(rf"^{h}:", output, re.IGNORECASE | re.MULTILINE):
                missing_headers.append(h)

        findings = [
            {"type": "http_status", "status": status_code},
            {"type": "missing_security_headers", "headers": missing_headers},
        ]

        return {
            "tool_detected": "http_response",
            "target": target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"HTTP {status_code} response parsed. {len(missing_headers)} standard security headers missing.",
            "findings": findings,
            "explanation": f"Server returned HTTP {status_code}. Missing defense-in-depth headers: {', '.join(missing_headers)}.",
            "next_step": {
                "recommended_command": "redloop asvs evaluate ...",
                "purpose": "Verify endpoint against ASVS 14.4 security architecture controls.",
                "prerequisites": "Target accessibility",
                "flag_explanations": {},
                "expected_output": "Comprehensive header compliance score",
                "can_execute_via_redloop": True,
                "scope_status": "LOCAL_SAFE",
                "is_dangerous": False,
            },
        }

    def _parse_terminal_error_output(self, output: str, evidence_id: str, evidence_hash: str, target: str | None) -> dict[str, Any]:
        """Parse terminal errors and recommend precise corrections."""
        analysis = self.analyze_terminal_problem(output)
        guidance = analysis.get("guidance")
        rec_cmd = guidance.command if guidance else "dmesg | tail -n 20"
        purpose = guidance.purpose if guidance else "Inspect kernel and system messages for error context."

        return {
            "tool_detected": "terminal_error",
            "target": target,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "summary": f"Detected error: {analysis.get('detected_issue')}",
            "findings": [{"error_type": analysis.get("detected_issue"), "details": analysis.get("explanation")}],
            "explanation": analysis.get("explanation", "Terminal command encountered an error."),
            "next_step": {
                "recommended_command": rec_cmd,
                "purpose": purpose,
                "prerequisites": "None",
                "flag_explanations": {},
                "expected_output": guidance.expected_result if guidance else "Diagnostics",
                "can_execute_via_redloop": True,
                "scope_status": "LOCAL_SAFE",
                "is_dangerous": False,
            },
        }


_kali_copilot_instance: KaliCopilot | None = None


def get_kali_copilot(scope_guard: AssessmentScopeGuard | None = None) -> KaliCopilot:
    """Return singleton or configured instance of KaliCopilot."""
    global _kali_copilot_instance
    if _kali_copilot_instance is None or scope_guard is not None:
        _kali_copilot_instance = KaliCopilot(scope_guard=scope_guard)
    return _kali_copilot_instance

