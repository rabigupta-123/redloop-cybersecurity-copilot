"""Unified Terminal Engine & Multi-Environment Execution Layer (Phase 3).

Provides deterministic, resilient command execution across:
- Native Windows Host
- WSL (Windows Subsystem for Linux)
- Kali Linux (via WSL or container)
- Native Linux
- Docker container runtimes

Enforces:
- shell=False argument array execution (never arbitrary shell strings)
- Output size truncation (max 512KB to prevent memory exhaustion and UI hangs)
- Process tree termination and cancellation tokens
- Precise execution timing and exit code preservation
- Encoding resilience (UTF-8, UTF-16-LE, CP437, replacement fallback)
- Environment capability awareness (fails closed with truth if an environment is absent)
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import platform
import re
import shlex
import shutil
import signal
import socket
import sys
import subprocess
import threading
import time
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redloop.assessment.kali_copilot import (
    KaliCommandParser,
    KaliCommandRisk,
    KaliCommandState,
    detect_wsl_status,
)
from redloop.assessment.models import Evidence, EvidenceProvenance, StageStatus
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.tools_v2 import EnvironmentDetector, ToolRegistryV2
from redloop.audit import AuditLogger


MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB


class SecurityGateError(PermissionError):
    """Raised when execution violates the single choke point security gate."""
    pass


@dataclass(frozen=True)
class ValidatedCommand:
    """Cryptographically authenticated command token produced solely by the REDLOOP security gate.

    The lowest-level process spawn functions accept ONLY instances of ValidatedCommand.
    """
    binary: str
    args: tuple[str, ...]
    command_string: str
    execution_environment: str = "host"
    working_directory: str | None = None
    targets: tuple[tuple[str, int | None], ...] = ()
    is_network: bool = False
    scope_id: str = ""
    scope_snapshot_signature: str = ""
    gate_signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "args": list(self.args),
            "command_string": self.command_string,
            "execution_environment": self.execution_environment,
            "working_directory": self.working_directory,
            "targets": list(self.targets),
            "is_network": self.is_network,
            "scope_id": self.scope_id,
            "scope_snapshot_signature": self.scope_snapshot_signature,
        }


_GATE_HMAC_KEY = os.urandom(32)


def _compute_gate_signature(
    binary: str,
    args: tuple[str, ...],
    env: str,
    scope_id: str = "",
    scope_snapshot: str = "",
) -> str:
    payload = f"{binary}|{' '.join(args)}|{env}|{scope_id}|{scope_snapshot}".encode("utf-8")
    return hmac.new(_GATE_HMAC_KEY, payload, hashlib.sha256).hexdigest()


def _verify_gate_signature(cmd: Any) -> bool:
    if not isinstance(cmd, ValidatedCommand):
        return False
    if not cmd.gate_signature:
        return False
    expected = _compute_gate_signature(
        cmd.binary,
        cmd.args,
        cmd.execution_environment,
        cmd.scope_id,
        cmd.scope_snapshot_signature,
    )
    return hmac.compare_digest(cmd.gate_signature, expected)


def create_test_only_validated_command(
    binary: str,
    args: list[str] | tuple[str, ...] | None = None,
    environment: str = "host",
    working_directory: str | None = None,
    targets: list[tuple[str, int | None]] | None = None,
    is_network: bool = False,
) -> ValidatedCommand:
    """TEST ONLY factory to build a signed ValidatedCommand for adapter unit tests.

    MUST NOT be imported or referenced in production code!
    """
    clean_args = tuple(args or [])
    sig = _compute_gate_signature(binary, clean_args, environment)
    return ValidatedCommand(
        binary=binary,
        args=clean_args,
        command_string=f"{binary} {' '.join(clean_args)}".strip(),
        execution_environment=environment,
        working_directory=working_directory,
        targets=tuple(targets or []),
        is_network=is_network,
        gate_signature=sig,
    )



class ExecutionEnvironment(str, Enum):
    HOST = "host"
    WSL = "wsl"
    KALI = "kali"
    LINUX = "linux"
    DOCKER = "docker"


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"


@dataclass
class ExecutionResult:
    command: str
    args: list[str]
    execution_environment: str
    executable_path: str | None = None
    working_directory: str | None = None
    start_timestamp: str = ""
    completion_timestamp: str = ""
    duration_ms: float = 0.0
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    cancelled: bool = False
    status: ExecutionStatus = ExecutionStatus.SUCCESS
    error: str | None = None
    task_id: str | None = None
    evidence_id: str | None = None
    truncated: bool = False
    output_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        st_val = self.status.value if isinstance(self.status, ExecutionStatus) else str(self.status)
        is_success = (self.exit_code == 0 and st_val == "SUCCESS")
        state_label = "BLOCKED" if st_val == "BLOCKED" else ("COMPLETED" if is_success else "FAILED")
        return {
            "success": is_success,
            "state": state_label,
            "command": _mask_secrets(self.command),
            "args": [_mask_secrets(a) for a in self.args],
            "execution_environment": self.execution_environment,
            "executable_path": self.executable_path,
            "working_directory": self.working_directory,
            "start_timestamp": self.start_timestamp,
            "completion_timestamp": self.completion_timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "stdout": _mask_secrets(self.stdout),
            "stderr": _mask_secrets(self.stderr),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "status": st_val,
            "error": _mask_secrets(self.error) if self.error else None,
            "task_id": self.task_id,
            "evidence_id": self.evidence_id,
            "truncated": self.truncated,
            "output_hash": self.output_hash,
        }


_TRUNCATION_NOTE = "\n[TRUNCATED: Output exceeded 512KB limit]"
_TRUNCATION_NOTE_BYTES = len(_TRUNCATION_NOTE.encode("utf-8"))


def _safe_decode(raw: bytes) -> tuple[str, bool]:
    """Decodes raw bytes handling multi-encoding and limits output to MAX_OUTPUT_BYTES."""
    truncated = False
    if len(raw) > MAX_OUTPUT_BYTES:
        raw = raw[:MAX_OUTPUT_BYTES - _TRUNCATION_NOTE_BYTES]
        truncated = True

    decoded = None
    for enc in ("utf-8", "utf-16-le", "cp437", "latin-1"):
        try:
            decoded = raw.decode(enc)
            break
        except Exception:
            continue
    if decoded is None:
        decoded = raw.decode("utf-8", errors="replace")

    if truncated:
        decoded += _TRUNCATION_NOTE
    return decoded, truncated


# --- BASE EXECUTION ADAPTER ---


# --- PROCESS MANAGEMENT & SECURITY RESTRICTIONS ---

ALLOWED_EXECUTABLES = {
    # Recon & Port Scanning
    "nmap", "masscan", "rustscan", "ping", "traceroute", "tracert", "fping", "netstat", "ss", "nc", "ncat", "ssh", "telnet",
    # DNS & OSINT
    "nslookup", "dig", "host", "whois", "subfinder", "amass",
    # Web & HTTP
    "curl", "httpx", "nikto", "gobuster", "dirb", "ffuf", "nuclei", "wapiti", "wpscan", "wget", "whatweb", "tshark",
    # TLS & Cryptography
    "openssl", "testssl.sh", "sslscan",
    # Runtime & Diagnostics & Shell ops
    "python", "python3", "python.exe", "python3.exe", "echo", "uname", "pwd", "id", "whoami", "date", "printf", "dir", "cmd", "cmd.exe", "wsl", "wsl.exe", "docker", "docker.exe", "git", "git.exe",
}

METACHAIN_PATTERN = re.compile(r"[;&|`$<>]")
SENSITIVE_PATHS_PATTERN = re.compile(r"(/etc/(shadow|passwd|sudoers)|C:\\Windows\\System32\\config)", re.IGNORECASE)
SECRET_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*)[A-Za-z0-9_\-]{15,}", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*)[^\s]{4,}", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)[^\s]{6,}", re.IGNORECASE),
]

_SUBPROCESS_SEMAPHORE = threading.Semaphore(8)  # Max 8 concurrent subprocesses

ALLOWED_NETWORK_BINARIES = {
    "nmap", "curl", "wget", "nc", "ncat", "ping", "ssh", "telnet",
    "dig", "nslookup", "whatweb", "nikto", "gobuster", "nuclei", "tshark",
}

FORBIDDEN_SHELL_CHARS = re.compile(r"[;&|`$<>\n]")
FORBIDDEN_LIST_CHARS = re.compile(r"[;&|`\n]")


def _normalize_host(host_str: str) -> str:
    """Normalize and de-obfuscate target hosts (decimal/hex/octal IPv4, trailing dots, userinfo)."""
    h = host_str.strip().rstrip(".")
    if "@" in h:
        h = h.split("@")[-1]

    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]

    # Obfuscated decimal IPv4 e.g. 2130706433 -> 127.0.0.1
    if h.isdigit():
        try:
            val = int(h)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except Exception:
            pass

    # Obfuscated hex IPv4 e.g. 0x7f000001 -> 127.0.0.1
    if h.lower().startswith("0x"):
        try:
            val = int(h, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except Exception:
            pass

    # Obfuscated octal IPv4 e.g. 017700000001 or 0177.0.0.1
    if re.match(r"^0[0-7]+$", h):
        try:
            val = int(h, 8)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except Exception:
            pass

    parts = h.split(".")
    if len(parts) == 4 and any(p.startswith("0") and len(p) > 1 for p in parts):
        try:
            octets = [int(p, 8) if p.startswith("0") and not p.startswith("0x") else int(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ".".join(str(o) for o in octets)
        except Exception:
            pass

    return h


def _parse_url_or_endpoint(raw: str) -> list[tuple[str, int | None]]:
    """Extract all candidate (host, port) pairs from URL, host:port, or bare host.

    Detects and guards against URL userinfo / fragment / query host confusion.
    """
    m_v6 = re.match(r"^\[([a-fA-F0-9:]+)\]:(\d+)$", raw)
    if m_v6:
        return [(m_v6.group(1), int(m_v6.group(2)))]

    targets: list[tuple[str, int | None]] = []

    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Unparseable URL target: {raw}")
        norm_h = _normalize_host(hostname)
        port = parsed.port
        if port is None:
            if parsed.scheme == "http":
                port = 80
            elif parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "ftp":
                port = 21
            elif parsed.scheme == "ssh":
                port = 22
        targets.append((norm_h, port))

        # Anti-userinfo / fragment / query confusion: detect embedded hosts after '@' or '%40'
        unquoted = urllib.parse.unquote(raw)
        if "@" in unquoted:
            matches = re.findall(r"@([a-zA-Z0-9.\-]+(?::\d+)?)", unquoted)
            for m in matches:
                # Strip trailing path/slash/hash
                m_clean = m.split("/")[0].split("?")[0].split("#")[0]
                if ":" in m_clean and not m_clean.endswith(":"):
                    hc, pc = m_clean.split(":", 1)
                    targets.append((_normalize_host(hc), int(pc) if pc.isdigit() else (port or 80)))
                elif m_clean:
                    targets.append((_normalize_host(m_clean), port or 80))
        return list(dict.fromkeys(targets))

    if ":" in raw and not raw.startswith(":") and raw.count(":") == 1:
        h_part, p_part = raw.split(":", 1)
        if p_part.isdigit():
            p_val = int(p_part)
            if 1 <= p_val <= 65535:
                return [(_normalize_host(h_part), p_val)]

    return [(_normalize_host(raw), None)]


def extract_network_targets(command: str) -> list[tuple[str, int | None]]:
    """Strictly parse command string and extract all (target, port) pairs using shlex.

    Enforces:
    - Rejection of shell metacharacters and chaining (;&|`$( )><\\n).
    - Allowlist of permitted binaries. Unknown binary => raises ValueError.
    - Full de-obfuscation and normalization of hosts.
    - Explicit port extraction (nmap -p, URL ports, host:port, nc port, ssh -p).
    - Fail-closed: any unparseable target or port raises ValueError.
    """
    if not command or not command.strip():
        raise ValueError("Empty command string")

    if FORBIDDEN_SHELL_CHARS.search(command):
        raise ValueError(
            "Command contains forbidden shell metacharacters or chaining (;&|`$( )><\\n)."
        )

    try:
        tokens = shlex.split(command.strip(), posix=True)
    except Exception as exc:
        raise ValueError(f"Command could not be safely tokenized: {exc}") from exc

    if not tokens:
        raise ValueError("Empty command tokens")

    raw_bin = tokens[0]
    bin_name = os.path.basename(raw_bin).lower()
    if bin_name.endswith(".exe"):
        bin_name = bin_name[:-4]

    if bin_name not in ALLOWED_NETWORK_BINARIES:
        raise ValueError(f"Binary '{bin_name}' is not in trusted network allowlist.")

    args = tokens[1:]
    results: list[tuple[str, int | None]] = []

    if bin_name == "nmap":
        ports: list[int] = []
        has_p_flag = False
        targets: list[str] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-p", "--port"):
                has_p_flag = True
                if i + 1 >= len(args):
                    raise ValueError("nmap -p missing port argument")
                p_spec = args[i + 1]
                i += 2
                if p_spec == "-":
                    ports = list(range(1, 65536))
                else:
                    for chunk in p_spec.split(","):
                        chunk = chunk.strip()
                        if not chunk:
                            continue
                        if "-" in chunk:
                            start_s, end_s = chunk.split("-", 1)
                            if not start_s.isdigit() or not end_s.isdigit():
                                raise ValueError(f"Malformed nmap port range: {chunk}")
                            s_int, e_int = int(start_s), int(end_s)
                            if s_int < 1 or e_int > 65535 or s_int > e_int:
                                raise ValueError(f"Invalid nmap port range bounds: {chunk}")
                            ports.extend(range(s_int, e_int + 1))
                        elif chunk.isdigit():
                            p_int = int(chunk)
                            if not 1 <= p_int <= 65535:
                                raise ValueError(f"Invalid port: {chunk}")
                            ports.append(p_int)
                        else:
                            raise ValueError(f"Unparseable nmap port: {chunk}")
                continue
            elif arg.startswith("-p") and arg != "-p":
                has_p_flag = True
                p_spec = arg[2:]
                i += 1
                if p_spec == "-":
                    ports = list(range(1, 65536))
                else:
                    for chunk in p_spec.split(","):
                        chunk = chunk.strip()
                        if not chunk:
                            continue
                        if "-" in chunk:
                            start_s, end_s = chunk.split("-", 1)
                            if not start_s.isdigit() or not end_s.isdigit():
                                raise ValueError(f"Malformed nmap port range: {chunk}")
                            s_int, e_int = int(start_s), int(end_s)
                            ports.extend(range(s_int, e_int + 1))
                        elif chunk.isdigit():
                            ports.append(int(chunk))
                        else:
                            raise ValueError(f"Unparseable nmap port: {chunk}")
                continue
            elif arg == "--top-ports":
                has_p_flag = True
                if i + 1 >= len(args) or not args[i + 1].isdigit():
                    raise ValueError("nmap --top-ports missing count")
                top_count = int(args[i + 1])
                i += 2
                ports = list(range(1, min(top_count + 1, 65536)))
                continue
            elif arg.startswith("-"):
                if arg in ("-oN", "-oX", "-oG", "-oS", "-oA", "--script", "-e", "--source-port", "-g", "--data-length"):
                    i += 2
                else:
                    i += 1
            else:
                targets.append(arg)
                i += 1

        if not targets:
            raise ValueError("nmap command contains no target host/network")

        for tgt in targets:
            norm_tgt = _normalize_host(tgt)
            if has_p_flag and ports:
                for p in ports:
                    results.append((norm_tgt, p))
            else:
                results.append((norm_tgt, None))

    elif bin_name in ("curl", "wget"):
        opts_with_arg = {"-H", "--header", "-d", "--data", "-o", "--output", "-u", "--user", "-A", "--user-agent", "-X", "--request", "--connect-timeout", "-m", "--max-time"}
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in opts_with_arg:
                i += 2
                continue
            if arg.startswith("-"):
                i += 1
                continue
            for host, port in _parse_url_or_endpoint(arg):
                results.append((host, port or 80))
            i += 1

    elif bin_name in ("nc", "ncat"):
        positionals = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-p", "-w", "-i", "-s"):
                i += 2
                continue
            if arg.startswith("-"):
                i += 1
                continue
            positionals.append(arg)
            i += 1
        if len(positionals) < 1:
            raise ValueError("nc/ncat missing target host")
        host = _normalize_host(positionals[0])
        if len(positionals) < 2 or not positionals[1].isdigit():
            raise ValueError("nc/ncat requires explicit target port")
        port = int(positionals[1])
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid nc port: {port}")
        results.append((host, port))

    elif bin_name == "ssh":
        port = 22
        positionals = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-p":
                if i + 1 >= len(args) or not args[i + 1].isdigit():
                    raise ValueError("ssh -p missing valid port")
                port = int(args[i + 1])
                i += 2
                continue
            if arg.startswith("-"):
                i += 1
                continue
            positionals.append(arg)
            i += 1
        if not positionals:
            raise ValueError("ssh missing target host")
        host = _normalize_host(positionals[0])
        results.append((host, port))

    elif bin_name == "telnet":
        port = 23
        positionals = []
        for arg in args:
            if not arg.startswith("-"):
                positionals.append(arg)
        if not positionals:
            raise ValueError("telnet missing target host")
        host = _normalize_host(positionals[0])
        if len(positionals) >= 2 and positionals[1].isdigit():
            port = int(positionals[1])
        results.append((host, port))

    elif bin_name in ("dig", "nslookup"):
        server = None
        tgt_host = None
        for arg in args:
            if arg.startswith("@"):
                server = _normalize_host(arg[1:])
            elif not arg.startswith("-"):
                tgt_host = _normalize_host(arg)
        if server:
            results.append((server, 53))
        if tgt_host:
            results.append((tgt_host, 53))

    elif bin_name == "ping":
        tgt_host = None
        for arg in args:
            if not arg.startswith("-"):
                tgt_host = _normalize_host(arg)
                break
        if not tgt_host:
            raise ValueError("ping missing target host")
        results.append((tgt_host, None))

    elif bin_name in ("whatweb", "nikto", "gobuster", "nuclei"):
        url_target = None
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-u", "--url", "-target", "-h", "-host") and i + 1 < len(args):
                url_target = args[i + 1]
                i += 2
                continue
            if not arg.startswith("-") and url_target is None:
                url_target = arg
            i += 1
        if not url_target:
            raise ValueError(f"{bin_name} missing target URL/host")
        for host, port in _parse_url_or_endpoint(url_target):
            results.append((host, port or 80))

    elif bin_name == "tshark":
        host_target = None
        for i, arg in enumerate(args):
            if arg == "host" and i + 1 < len(args):
                host_target = _normalize_host(args[i + 1])
                break
        if host_target:
            results.append((host_target, None))

    if not results:
        raise ValueError(f"Could not extract network targets from command: {command}")

    return results


def _mask_secrets(text: str | None) -> str:
    if not text:
        return ""
    res = str(text)
    for pat in SECRET_PATTERNS:
        res = pat.sub(r"\1[REDACTED_SECRET]", res)
    return res


def _get_safe_env() -> dict[str, str]:
    """Controlled environment dictionary for subprocess execution."""
    safe_keys = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
        "TEMP", "TMP", "USERPROFILE", "HOMEPATH", "HOMEDRIVE",
        "LANG", "LC_ALL", "TERM"
    }
    return {k: v for k, v in os.environ.items() if k.upper() in safe_keys}


def validate_command_security(binary: str, args: list[str]) -> tuple[bool, str | None]:
    """Enforces application-level execution restrictions before process creation."""
    bin_name = os.path.basename(binary).lower()
    if (
        bin_name not in ALLOWED_EXECUTABLES
        and binary != sys.executable
        and not any(bin_name.startswith(x) for x in ("python", "python3"))
    ):
        return False, f"Executable '{binary}' is not permitted by REDLOOP trusted allowlist."

    for a in args:
        if METACHAIN_PATTERN.search(a):
            return False, f"Argument '{a}' contains forbidden shell metacharacters (;, &, |, `, $, <, >)."
        if SENSITIVE_PATHS_PATTERN.search(a):
            return False, f"Argument '{a}' references restricted system path which is blocked."

    return True, None


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Platform-appropriate process tree termination without orphaned children."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=3.0,
            )
        else:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class BaseExecutionAdapter:
    """Abstract adapter contract for environment-specific command execution."""

    def is_available(self) -> tuple[bool, str | None]:
        raise NotImplementedError

    def execute(
        self,
        command: ValidatedCommand,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        raise NotImplementedError


# --- HOST ADAPTER ---

class HostExecutionAdapter(BaseExecutionAdapter):
    """Executes commands directly on the host operating system."""

    def is_available(self) -> tuple[bool, str | None]:
        return True, None

    def execute(
        self,
        command: ValidatedCommand,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        if not isinstance(command, ValidatedCommand) or not _verify_gate_signature(command):
            raise SecurityGateError(
                "Choke point violation: low-level execution adapters accept ONLY a gate-validated ValidatedCommand."
            )

        binary = command.binary
        args = list(command.args)
        full_cmd_str = command.command_string or " ".join([binary] + args)
        start_ts = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        if cancel_token and cancel_token.is_set():
            err_msg = "Process execution cancelled by user before process creation."
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="host",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=err_msg,
                exit_code=-1,
                cancelled=True,
                status=ExecutionStatus.CANCELLED,
                error="Execution cancelled before process creation.",
                task_id=task_id,
                output_hash=hashlib.sha256(err_msg.encode("utf-8")).hexdigest(),
            )

        # Locate executable and prepare command tokens with cross-platform fallback
        bin_lower = binary.lower()
        is_nt = (os.name == "nt")
        exe_path: str | None = None
        cmd_tokens: list[str] = []

        if is_nt and bin_lower == "echo":
            exe_path = os.environ.get("COMSPEC", "cmd.exe")
            cmd_tokens = [exe_path, "/c", "echo"] + args
        elif is_nt and bin_lower == "dir":
            exe_path = os.environ.get("COMSPEC", "cmd.exe")
            cmd_tokens = [exe_path, "/c", "dir"] + args
        elif is_nt and bin_lower == "date":
            exe_path = os.environ.get("COMSPEC", "cmd.exe")
            cmd_tokens = [exe_path, "/c", "date", "/t"]
        elif is_nt and bin_lower == "pwd":
            exe_path = sys.executable
            cmd_tokens = [exe_path, "-c", "import os; print(os.getcwd())"]
        elif is_nt and bin_lower == "whoami":
            w_path = shutil.which("whoami")
            if w_path:
                exe_path = w_path
                cmd_tokens = [exe_path] + args
            else:
                exe_path = sys.executable
                cmd_tokens = [exe_path, "-c", "import getpass; print(getpass.getuser())"]
        elif is_nt and bin_lower == "id":
            exe_path = sys.executable
            cmd_tokens = [exe_path, "-c", "import getpass; u = getpass.getuser(); print(f'uid=1000({u}) gid=1000({u}) groups=1000({u})')"]
        elif is_nt and bin_lower == "uname":
            exe_path = sys.executable
            cmd_tokens = [exe_path, "-c", "import platform; print(f'{platform.system()} {platform.node()} {platform.release()} {platform.version()} {platform.machine()}')"]
        elif is_nt and bin_lower == "printf":
            exe_path = sys.executable
            cmd_tokens = [exe_path, "-c", "import sys; fmt = sys.argv[1] if len(sys.argv) > 1 else ''; vals = tuple(sys.argv[2:]); sys.stdout.write(fmt % vals if vals else fmt)"] + args
        elif is_nt and bin_lower in ("ss", "netstat"):
            netstat_exe = shutil.which("netstat")
            if netstat_exe:
                exe_path = netstat_exe
                cmd_tokens = [netstat_exe, "-ano"]
        elif is_nt and bin_lower in ("ifconfig", "ipconfig"):
            ipc_exe = shutil.which("ipconfig")
            if ipc_exe:
                exe_path = ipc_exe
                cmd_tokens = [ipc_exe]
        elif bin_lower in ("python", "python3"):
            exe_path = sys.executable
            cmd_tokens = [exe_path] + args
        else:
            exe_path = shutil.which(binary)
            if exe_path:
                cmd_tokens = [exe_path] + args

        if not exe_path:
            duration_ms = (time.time() - t0) * 1000
            err_msg = f"Executable '{binary}' not found on host PATH."
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="host",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                stdout="",
                stderr=err_msg,
                exit_code=127,
                status=ExecutionStatus.ERROR,
                error=f"Executable '{binary}' was not found on host system PATH.",
                task_id=task_id,
                output_hash=hashlib.sha256(err_msg.encode("utf-8")).hexdigest(),
            )

        cwd = working_directory if (working_directory and os.path.exists(working_directory)) else None

        proc = None
        timed_out = False
        cancelled = False

        try:
            proc = subprocess.Popen(
                cmd_tokens,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            if cancel_token:
                def _watcher():
                    while proc.poll() is None:
                        if cancel_token.is_set():
                            self._kill_process_tree(proc)
                            break
                        time.sleep(0.05)
                threading.Thread(target=_watcher, daemon=True).start()

            raw_out, raw_err = b"", b""
            try:
                raw_out, raw_err = proc.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill_process_tree(proc)
                try:
                    raw_out, raw_err = proc.communicate(timeout=1.0)
                except Exception:
                    pass

            if cancel_token and cancel_token.is_set():
                cancelled = True
            duration_ms = (time.time() - t0) * 1000
            end_ts = datetime.now(timezone.utc).isoformat()

            out_text, out_trunc = _safe_decode(raw_out or b"")
            err_text, err_trunc = _safe_decode(raw_err or b"")
            is_truncated = out_trunc or err_trunc
            out_hash = hashlib.sha256((raw_out or b"") + (raw_err or b"")).hexdigest()

            if cancelled:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="host",
                    executable_path=exe_path,
                    working_directory=cwd,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr=err_text or "Process execution cancelled by user.",
                    exit_code=-1,
                    cancelled=True,
                    status=ExecutionStatus.CANCELLED,
                    error="Execution cancelled by user.",
                    task_id=task_id,
                    truncated=is_truncated,
                    output_hash=out_hash,
                )

            if timed_out:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="host",
                    executable_path=exe_path,
                    working_directory=cwd,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr=err_text or f"Execution timed out after {timeout_seconds} seconds.",
                    exit_code=124,
                    timed_out=True,
                    status=ExecutionStatus.TIMEOUT,
                    error=f"Command execution timed out after {timeout_seconds}s.",
                    task_id=task_id,
                    truncated=is_truncated,
                    output_hash=out_hash,
                )

            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="host",
                executable_path=exe_path,
                working_directory=cwd,
                start_timestamp=start_ts,
                completion_timestamp=end_ts,
                duration_ms=duration_ms,
                stdout=out_text,
                stderr=err_text,
                exit_code=proc.returncode,
                status=ExecutionStatus.SUCCESS if proc.returncode == 0 else ExecutionStatus.ERROR,
                task_id=task_id,
                truncated=is_truncated,
                output_hash=out_hash,
            )

        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
            err_str = str(exc)
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="host",
                executable_path=exe_path,
                working_directory=cwd,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                stdout="",
                stderr=err_str,
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"Host execution exception: {exc}",
                task_id=task_id,
                output_hash=hashlib.sha256(err_str.encode("utf-8")).hexdigest(),
            )

    def _kill_process_tree(self, proc: subprocess.Popen) -> None:
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                    timeout=2,
                )
            else:
                proc.terminate()
                proc.wait(timeout=1.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# --- WSL ADAPTER ---

class WSLExecutionAdapter(BaseExecutionAdapter):
    """Executes commands inside Windows Subsystem for Linux distributions."""

    def __init__(self, distro: str | None = None) -> None:
        self.distro = distro

    def is_available(self) -> tuple[bool, str | None]:
        wsl_info = detect_wsl_status()
        if not wsl_info.get("wsl_available"):
            return False, wsl_info.get("error") or "WSL is not available on this system."
        if self.distro and self.distro not in wsl_info.get("distributions", []):
            return False, f"WSL distribution '{self.distro}' is not installed."
        return True, None

    def execute(
        self,
        command: ValidatedCommand,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        if not isinstance(command, ValidatedCommand) or not _verify_gate_signature(command):
            raise SecurityGateError(
                "Choke point violation: low-level execution adapters accept ONLY a gate-validated ValidatedCommand."
            )

        binary = command.binary
        args = list(command.args)
        full_cmd_str = command.command_string or " ".join([binary] + args)
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()

        if cancel_token and cancel_token.is_set():
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr="Process execution cancelled by user before process creation.",
                exit_code=-1,
                cancelled=True,
                status=ExecutionStatus.CANCELLED,
                error="Execution cancelled before process creation.",
                task_id=task_id,
            )

        if not avail:
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=reason or "WSL is not available.",
                exit_code=127,
                status=ExecutionStatus.ENVIRONMENT_UNAVAILABLE,
                error=reason,
                task_id=task_id,
            )

        wsl_exe = shutil.which("wsl.exe") or shutil.which("wsl")
        wsl_info = detect_wsl_status()
        target_distro = self.distro or wsl_info.get("default_distro")

        cmd = [wsl_exe, "-d", target_distro, "--", binary] + args
        t0 = time.time()
        timed_out = False
        cancelled = False

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            if cancel_token:
                def _watcher_wsl():
                    while proc.poll() is None:
                        if cancel_token.is_set():
                            proc.kill()
                            break
                        time.sleep(0.05)
                threading.Thread(target=_watcher_wsl, daemon=True).start()

            raw_out, raw_err = b"", b""
            try:
                raw_out, raw_err = proc.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    raw_out, raw_err = proc.communicate(timeout=1.0)
                except Exception:
                    pass

            if cancel_token and cancel_token.is_set():
                cancelled = True
            duration_ms = (time.time() - t0) * 1000
            end_ts = datetime.now(timezone.utc).isoformat()
            out_text, out_trunc = _safe_decode(raw_out or b"")
            err_text, err_trunc = _safe_decode(raw_err or b"")
            out_hash = hashlib.sha256((raw_out or b"") + (raw_err or b"")).hexdigest()

            if cancelled:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="wsl",
                    executable_path=f"wsl:{target_distro}:{binary}",
                    working_directory=working_directory,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr="Execution cancelled by user.",
                    exit_code=-1,
                    cancelled=True,
                    status=ExecutionStatus.CANCELLED,
                    error="Execution cancelled by user.",
                    task_id=task_id,
                    truncated=out_trunc or err_trunc,
                    output_hash=out_hash,
                )

            if timed_out:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="wsl",
                    executable_path=f"wsl:{target_distro}:{binary}",
                    working_directory=working_directory,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr=f"WSL execution timed out after {timeout_seconds}s.",
                    exit_code=124,
                    timed_out=True,
                    status=ExecutionStatus.TIMEOUT,
                    error=f"WSL execution timed out after {timeout_seconds}s.",
                    task_id=task_id,
                    truncated=out_trunc or err_trunc,
                    output_hash=out_hash,
                )

            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=f"wsl:{target_distro}:{binary}",
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=end_ts,
                duration_ms=duration_ms,
                stdout=out_text,
                stderr=err_text,
                exit_code=proc.returncode,
                status=ExecutionStatus.SUCCESS if proc.returncode == 0 else ExecutionStatus.ERROR,
                task_id=task_id,
                truncated=out_trunc or err_trunc,
                output_hash=out_hash,
            )
        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
            err_str = str(exc)
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=f"wsl:{target_distro}:{binary}",
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                stdout="",
                stderr=err_str,
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"WSL execution error: {exc}",
                task_id=task_id,
                output_hash=hashlib.sha256(err_str.encode("utf-8")).hexdigest(),
            )


# --- KALI LINUX ADAPTER ---

class KaliExecutionAdapter(BaseExecutionAdapter):
    """Executes commands specifically targeting Kali Linux."""

    def is_available(self) -> tuple[bool, str | None]:
        kali_info = EnvironmentDetector.detect_kali()
        if not kali_info.get("available"):
            return False, "Kali Linux distribution not detected. Install via 'wsl --install -d kali-linux'."
        return True, None

    def execute(
        self,
        command: ValidatedCommand,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        if not isinstance(command, ValidatedCommand) or not _verify_gate_signature(command):
            raise SecurityGateError(
                "Choke point violation: low-level execution adapters accept ONLY a gate-validated ValidatedCommand."
            )

        binary = command.binary
        args = list(command.args)
        full_cmd_str = command.command_string or " ".join([binary] + args)
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()

        if cancel_token and cancel_token.is_set():
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr="Process execution cancelled by user before process creation.",
                exit_code=-1,
                cancelled=True,
                status=ExecutionStatus.CANCELLED,
                error="Execution cancelled before process creation.",
                task_id=task_id,
            )

        if not avail:
            err_msg = reason or "Kali Linux is not installed or registered."
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="kali",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=err_msg,
                exit_code=127,
                status=ExecutionStatus.ENVIRONMENT_UNAVAILABLE,
                error=reason,
                task_id=task_id,
                output_hash=hashlib.sha256(err_msg.encode("utf-8")).hexdigest(),
            )

        kali_info = EnvironmentDetector.detect_kali()
        distro = kali_info.get("distro_name")
        wsl_adapter = WSLExecutionAdapter(distro=distro)
        res = wsl_adapter.execute(
            command=command,
            working_directory=working_directory,
            timeout_seconds=timeout_seconds,
            cancel_token=cancel_token,
            task_id=task_id,
        )
        res.execution_environment = "kali"
        return res


# --- DOCKER ADAPTER ---

class DockerExecutionAdapter(BaseExecutionAdapter):
    """Executes commands inside temporary or running Docker security containers."""

    def __init__(self, container_image: str = "alpine:latest") -> None:
        self.container_image = container_image

    def is_available(self) -> tuple[bool, str | None]:
        docker_info = EnvironmentDetector.detect_docker()
        if not docker_info.get("available"):
            return False, "Docker CLI is not installed on system PATH."
        if not docker_info.get("daemon_running"):
            return False, "Docker daemon is not running. Please start Docker Desktop or the dockerd service."
        return True, None

    def execute(
        self,
        command: ValidatedCommand,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        if not isinstance(command, ValidatedCommand) or not _verify_gate_signature(command):
            raise SecurityGateError(
                "Choke point violation: low-level execution adapters accept ONLY a gate-validated ValidatedCommand."
            )

        binary = command.binary
        args = list(command.args)
        full_cmd_str = command.command_string or " ".join([binary] + args)
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()

        if cancel_token and cancel_token.is_set():
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="wsl",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr="Process execution cancelled by user before process creation.",
                exit_code=-1,
                cancelled=True,
                status=ExecutionStatus.CANCELLED,
                error="Execution cancelled before process creation.",
                task_id=task_id,
            )

        if not avail:
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="docker",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=reason or "Docker environment is unavailable.",
                exit_code=127,
                status=ExecutionStatus.ENVIRONMENT_UNAVAILABLE,
                error=reason,
                task_id=task_id,
            )

        docker_exe = shutil.which("docker")
        cmd = [docker_exe, "run", "--rm", self.container_image, binary] + args
        t0 = time.time()
        timed_out = False
        cancelled = False

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            if cancel_token:
                def _watcher_wsl():
                    while proc.poll() is None:
                        if cancel_token.is_set():
                            proc.kill()
                            break
                        time.sleep(0.05)
                threading.Thread(target=_watcher_wsl, daemon=True).start()

            raw_out, raw_err = b"", b""
            try:
                raw_out, raw_err = proc.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    raw_out, raw_err = proc.communicate(timeout=1.0)
                except Exception:
                    pass

            if cancel_token and cancel_token.is_set():
                cancelled = True
            duration_ms = (time.time() - t0) * 1000
            end_ts = datetime.now(timezone.utc).isoformat()
            out_text, out_trunc = _safe_decode(raw_out or b"")
            err_text, err_trunc = _safe_decode(raw_err or b"")
            out_hash = hashlib.sha256((raw_out or b"") + (raw_err or b"")).hexdigest()

            if cancelled:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="docker",
                    executable_path=f"docker:{self.container_image}:{binary}",
                    working_directory=working_directory,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr="Execution cancelled by user.",
                    exit_code=-1,
                    cancelled=True,
                    status=ExecutionStatus.CANCELLED,
                    error="Execution cancelled by user.",
                    task_id=task_id,
                    truncated=out_trunc or err_trunc,
                    output_hash=out_hash,
                )

            if timed_out:
                return ExecutionResult(
                    command=full_cmd_str,
                    args=args,
                    execution_environment="docker",
                    executable_path=f"docker:{self.container_image}:{binary}",
                    working_directory=working_directory,
                    start_timestamp=start_ts,
                    completion_timestamp=end_ts,
                    duration_ms=duration_ms,
                    stdout=out_text,
                    stderr=f"Docker container execution timed out after {timeout_seconds}s.",
                    exit_code=124,
                    timed_out=True,
                    status=ExecutionStatus.TIMEOUT,
                    error=f"Docker container execution timed out after {timeout_seconds}s.",
                    task_id=task_id,
                    truncated=out_trunc or err_trunc,
                    output_hash=out_hash,
                )

            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="docker",
                executable_path=f"docker:{self.container_image}:{binary}",
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=end_ts,
                duration_ms=duration_ms,
                stdout=out_text,
                stderr=err_text,
                exit_code=proc.returncode,
                status=ExecutionStatus.SUCCESS if proc.returncode == 0 else ExecutionStatus.ERROR,
                task_id=task_id,
                truncated=out_trunc or err_trunc,
                output_hash=out_hash,
            )
        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
            err_str = str(exc)
            return ExecutionResult(
                command=full_cmd_str,
                args=args,
                execution_environment="docker",
                executable_path=f"docker:{self.container_image}:{binary}",
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=duration_ms,
                stdout="",
                stderr=err_str,
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"Docker execution error: {exc}",
                task_id=task_id,
                output_hash=hashlib.sha256(err_str.encode("utf-8")).hexdigest(),
            )


# --- UNIFIED TERMINAL ENGINE ---

def _is_dangerous_inline_code(code_str: str) -> bool:
    DANGER_KEYWORDS = (
        "subprocess", "urllib", "requests", "http.client",
        "os.system", "os.popen", "pty", "shutil", "eval(", "exec(",
        "__import__", "/tmp/", "/etc/passwd", "/etc/shadow", "pwnd",
    )
    c_lower = code_str.lower()
    if any(kw in c_lower for kw in DANGER_KEYWORDS):
        return True
    if "socket" in c_lower:
        # Allow pure localhost DNS query for loopback diagnostic, otherwise block generic socket
        if not ("gethostbyname" in c_lower and "localhost" in c_lower):
            return True
    if re.search(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.", code_str):
        return True
    return False


class UnifiedTerminalEngine:
    """Coordinates command validation, security authorization, and multi-environment execution."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.audit = audit
        self._active_cancels: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self.command_history: list[dict[str, Any]] = []

        self._adapters: dict[str, BaseExecutionAdapter] = {
            ExecutionEnvironment.HOST.value: HostExecutionAdapter(),
            ExecutionEnvironment.WSL.value: WSLExecutionAdapter(),
            ExecutionEnvironment.KALI.value: KaliExecutionAdapter(),
            ExecutionEnvironment.LINUX.value: HostExecutionAdapter() if platform.system().lower() == "linux" else WSLExecutionAdapter(),
            ExecutionEnvironment.DOCKER.value: DockerExecutionAdapter(),
        }

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            evt = self._active_cancels.get(task_id)
            if evt:
                evt.set()
                return True
        return False

    def execute_command(
        self,
        command_string_or_args: str | list[str] | ValidatedCommand,
        environment: Literal["host", "wsl", "kali", "linux", "docker"] = "host",
        target: str | None = None,
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        task_id: str | None = None,
        cancel_token: threading.Event | None = None,
    ) -> ExecutionResult:
        t0 = time.time()
        start_ts = datetime.now(timezone.utc).isoformat()
        t_id = task_id or f"term-{uuid.uuid4().hex[:8]}"

        # 0. If already a ValidatedCommand, verify gate signature
        if isinstance(command_string_or_args, ValidatedCommand):
            if not _verify_gate_signature(command_string_or_args):
                return ExecutionResult(
                    command=command_string_or_args.command_string,
                    args=list(command_string_or_args.args),
                    execution_environment=environment,
                    start_timestamp=start_ts,
                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                    duration_ms=0.0,
                    stdout="",
                    stderr="SECURITY_ALERT: ValidatedCommand signature verification failed.",
                    exit_code=126,
                    status=ExecutionStatus.BLOCKED,
                    error="SECURITY_ALERT: Invalid gate signature.",
                    task_id=t_id,
                )
            adapter = self._adapters.get(command_string_or_args.execution_environment.lower()) or self._adapters["host"]
            cancel_evt = cancel_token or threading.Event()
            with self._lock:
                self._active_cancels[t_id] = cancel_evt
            try:
                res = adapter.execute(
                    command=command_string_or_args,
                    working_directory=working_directory or command_string_or_args.working_directory,
                    timeout_seconds=timeout_seconds,
                    cancel_token=cancel_evt,
                    task_id=t_id,
                )
            finally:
                with self._lock:
                    self._active_cancels.pop(t_id, None)
            return res

        # 1. Parse into binary and argument list with strict gate validation
        if isinstance(command_string_or_args, str):
            cmd_str = command_string_or_args.strip()
            if FORBIDDEN_SHELL_CHARS.search(cmd_str):
                return ExecutionResult(
                    command=cmd_str,
                    args=[],
                    execution_environment=environment,
                    start_timestamp=start_ts,
                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                    duration_ms=0.0,
                    stdout="",
                    stderr="SECURITY_ALERT: Command contains forbidden shell metacharacters or chaining (;&|`$( )><\\n).",
                    exit_code=126,
                    status=ExecutionStatus.BLOCKED,
                    error="SECURITY_ALERT: Shell metacharacters or chaining rejected by gate.",
                    task_id=t_id,
                )
            parsed = KaliCommandParser.parse(cmd_str)
            if parsed.is_dangerous or parsed.state == KaliCommandState.BLOCKED:
                return ExecutionResult(
                    command=cmd_str,
                    args=[],
                    execution_environment=environment,
                    start_timestamp=start_ts,
                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                    duration_ms=0.0,
                    stdout="",
                    stderr=f"SECURITY_ALERT: {parsed.reason}",
                    exit_code=126,
                    status=ExecutionStatus.BLOCKED,
                    error=f"SECURITY_ALERT: {parsed.reason}",
                    task_id=t_id,
                )
            binary = parsed.binary
            args = parsed.args
            inferred_target = target or parsed.target
            is_network = parsed.is_network
            # Interpreter inline execution wrapper check
            try:
                sh_tokens = shlex.split(cmd_str)
            except Exception:
                sh_tokens = cmd_str.split()
            if sh_tokens:
                sh_b = os.path.basename(sh_tokens[0]).lower().split(".")[0]
                if sh_b in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"):
                    for a_tok in sh_tokens[1:]:
                        if a_tok.lower() in ("-c", "/c", "-command", "-e"):
                            return ExecutionResult(
                                command=cmd_str,
                                args=args,
                                execution_environment=environment,
                                start_timestamp=start_ts,
                                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                                duration_ms=0.0,
                                stdout="",
                                stderr="SECURITY_ALERT: Shell inline code execution (-c) is blocked by REDLOOP security gate.",
                                exit_code=126,
                                status=ExecutionStatus.BLOCKED,
                                error="SECURITY_ALERT: Shell execution wrapper rejected.",
                                task_id=t_id,
                            )
                elif sh_b in ("python", "python3"):
                    for idx_a, a_tok in enumerate(sh_tokens[1:], 1):
                        if a_tok.lower() == "-c" and idx_a < len(sh_tokens):
                            code_cand = " ".join(sh_tokens[idx_a:])
                            if _is_dangerous_inline_code(code_cand):
                                return ExecutionResult(
                                    command=cmd_str,
                                    args=args,
                                    execution_environment=environment,
                                    start_timestamp=start_ts,
                                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                                    duration_ms=0.0,
                                    stdout="",
                                    stderr="SECURITY_ALERT: Interpreter inline code execution (-c) with unauthorized payload is blocked by REDLOOP security gate.",
                                    exit_code=126,
                                    status=ExecutionStatus.BLOCKED,
                                    error="SECURITY_ALERT: Dangerous interpreter payload rejected.",
                                    task_id=t_id,
                                )
        else:
            if not command_string_or_args:
                return ExecutionResult(
                    command="",
                    args=[],
                    execution_environment=environment,
                    start_timestamp=start_ts,
                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                    duration_ms=0.0,
                    stdout="",
                    stderr="Empty command list provided.",
                    exit_code=127,
                    status=ExecutionStatus.ERROR,
                    error="Empty command list.",
                    task_id=t_id,
                )
            raw_b = os.path.basename(command_string_or_args[0]).lower().split(".")[0]
            is_py = (raw_b in ("python", "python3") or command_string_or_args[0] == sys.executable or os.path.abspath(str(command_string_or_args[0])) == os.path.abspath(sys.executable))
            # Rejection of shell metacharacters in any list token
            for idx_t, tok in enumerate(command_string_or_args):
                if not isinstance(tok, str):
                    return ExecutionResult(
                        command=" ".join(str(x) for x in command_string_or_args),
                        args=[],
                        execution_environment=environment,
                        start_timestamp=start_ts,
                        completion_timestamp=datetime.now(timezone.utc).isoformat(),
                        duration_ms=0.0,
                        stdout="",
                        stderr="SECURITY_ALERT: List command contains non-string token.",
                        exit_code=126,
                        status=ExecutionStatus.BLOCKED,
                        error="SECURITY_ALERT: Non-string token in command list.",
                        task_id=t_id,
                    )
                # If this token is code following -c in a python command, semicolons are python statement separators
                if is_py and idx_t >= 2 and command_string_or_args[idx_t - 1] == "-c":
                    continue
                if FORBIDDEN_LIST_CHARS.search(tok):
                    return ExecutionResult(
                        command=" ".join(str(x) for x in command_string_or_args),
                        args=[],
                        execution_environment=environment,
                        start_timestamp=start_ts,
                        completion_timestamp=datetime.now(timezone.utc).isoformat(),
                        duration_ms=0.0,
                        stdout="",
                        stderr="SECURITY_ALERT: List command contains forbidden shell metacharacters or chaining.",
                        exit_code=126,
                        status=ExecutionStatus.BLOCKED,
                        error="SECURITY_ALERT: Shell metacharacters in command list.",
                        task_id=t_id,
                    )
            # Interpreter inline execution wrapper check on list
            raw_b = os.path.basename(command_string_or_args[0]).lower().split(".")[0]
            if raw_b in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"):
                for arg_tok in command_string_or_args[1:]:
                    if arg_tok.lower() in ("-c", "/c", "-command", "-e"):
                        return ExecutionResult(
                            command=" ".join(command_string_or_args),
                            args=command_string_or_args[1:],
                            execution_environment=environment,
                            start_timestamp=start_ts,
                            completion_timestamp=datetime.now(timezone.utc).isoformat(),
                            duration_ms=0.0,
                            stdout="",
                            stderr="SECURITY_ALERT: Shell inline code execution (-c) is blocked by REDLOOP security gate.",
                            exit_code=126,
                            status=ExecutionStatus.BLOCKED,
                            error="SECURITY_ALERT: Shell execution wrapper rejected.",
                            task_id=t_id,
                        )
            elif raw_b in ("python", "python3"):
                for idx_a, arg_tok in enumerate(command_string_or_args[1:], 1):
                    if arg_tok.lower() == "-c" and idx_a < len(command_string_or_args):
                        code_cand = " ".join(command_string_or_args[idx_a:])
                        if _is_dangerous_inline_code(code_cand):
                            return ExecutionResult(
                                command=" ".join(command_string_or_args),
                                args=command_string_or_args[1:],
                                execution_environment=environment,
                                start_timestamp=start_ts,
                                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                                duration_ms=0.0,
                                stdout="",
                                stderr="SECURITY_ALERT: Interpreter inline code execution (-c) with unauthorized payload is blocked by REDLOOP security gate.",
                                exit_code=126,
                                status=ExecutionStatus.BLOCKED,
                                error="SECURITY_ALERT: Dangerous interpreter payload rejected.",
                                task_id=t_id,
                            )
            binary = command_string_or_args[0]
            args = command_string_or_args[1:]
            cmd_str = " ".join(command_string_or_args)
            inferred_target = target
            is_network = binary.lower() in KaliCommandParser.NETWORK_TOOLS

        # 2. Binary allowlist check and scope verification gate
        bin_clean = os.path.basename(binary).lower()
        if bin_clean.endswith(".exe"):
            bin_clean = bin_clean[:-4]

        is_sys_exec = (binary == sys.executable or os.path.abspath(binary) == os.path.abspath(sys.executable))
        if bin_clean not in ALLOWED_EXECUTABLES and not is_sys_exec:
            if self.audit:
                self.audit.log(
                    module="terminal",
                    event="binary_blocked",
                    status="BLOCKED",
                    details={"binary": binary, "command": cmd_str},
                )
            return ExecutionResult(
                command=cmd_str,
                args=args,
                execution_environment=environment,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=f"SECURITY_ALERT: Binary '{binary}' is not permitted by REDLOOP trusted allowlist.",
                exit_code=126,
                status=ExecutionStatus.BLOCKED,
                error=f"SECURITY_ALERT: Binary '{binary}' is not in trusted allowlist.",
                task_id=t_id,
            )

        is_net_cmd = bin_clean in ALLOWED_NETWORK_BINARIES
        if is_net_cmd:
            try:
                extracted_targets = extract_network_targets(cmd_str)
            except Exception as exc:
                if self.audit:
                    self.audit.log(
                        module="terminal",
                        event="scope_blocked",
                        status="BLOCKED",
                        details={"command": cmd_str, "reason": str(exc)},
                    )
                return ExecutionResult(
                    command=cmd_str,
                    args=args,
                    execution_environment=environment,
                    start_timestamp=start_ts,
                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                    duration_ms=0.0,
                    stdout="",
                    stderr=f"SCOPE_BLOCKED: Command rejected by security gate: {exc}",
                    exit_code=126,
                    status=ExecutionStatus.BLOCKED,
                    error=f"SCOPE_BLOCKED: {exc}",
                    task_id=t_id,
                )

            if self.scope_guard is not None:
                for tgt, prt in extracted_targets:
                    try:
                        self.scope_guard.is_target_authorized(tgt, "scan", port=prt, require_port=True)
                    except Exception as exc:
                        if self.audit:
                            self.audit.log(
                                module="terminal",
                                event="scope_blocked",
                                status="BLOCKED",
                                details={"target": tgt, "port": prt, "command": cmd_str, "reason": str(exc)},
                            )
                        return ExecutionResult(
                            command=cmd_str,
                            args=args,
                            execution_environment=environment,
                            start_timestamp=start_ts,
                            completion_timestamp=datetime.now(timezone.utc).isoformat(),
                            duration_ms=0.0,
                            stdout="",
                            stderr=f"SCOPE_BLOCKED: Target '{tgt}' on port {prt} is not authorized in scope: {exc}",
                            exit_code=126,
                            status=ExecutionStatus.BLOCKED,
                            error=f"SCOPE_BLOCKED: Target '{tgt}' on port {prt} is not in authorized scope.",
                            task_id=t_id,
                        )

                    is_ip = False
                    try:
                        ipaddress.ip_address(tgt)
                        is_ip = True
                    except ValueError:
                        is_ip = False

                    if not is_ip:
                        try:
                            addr_info = socket.getaddrinfo(tgt, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                            resolved_ips = list({item[4][0] for item in addr_info})
                        except Exception as e:
                            return ExecutionResult(
                                command=cmd_str,
                                args=args,
                                execution_environment=environment,
                                start_timestamp=start_ts,
                                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                                duration_ms=0.0,
                                stdout="",
                                stderr=f"SCOPE_BLOCKED: DNS resolution failed for '{tgt}': {e}",
                                exit_code=126,
                                status=ExecutionStatus.BLOCKED,
                                error=f"SCOPE_BLOCKED: DNS resolution failed: {e}",
                                task_id=t_id,
                            )
                        for rip in resolved_ips:
                            try:
                                self.scope_guard.validate_resolved_ip(tgt, rip, action="scan")
                                self.scope_guard.is_target_authorized(rip, "scan", port=prt, require_port=True)
                            except Exception as exc:
                                if self.audit:
                                    self.audit.log(
                                        module="terminal",
                                        event="scope_blocked",
                                        status="BLOCKED",
                                        details={"target": tgt, "resolved_ip": rip, "port": prt, "command": cmd_str, "reason": str(exc)},
                                    )
                                return ExecutionResult(
                                    command=cmd_str,
                                    args=args,
                                    execution_environment=environment,
                                    start_timestamp=start_ts,
                                    completion_timestamp=datetime.now(timezone.utc).isoformat(),
                                    duration_ms=0.0,
                                    stdout="",
                                    stderr=f"SCOPE_BLOCKED: Hostname '{tgt}' resolved to '{rip}', which is not authorized: {exc}",
                                    exit_code=126,
                                    status=ExecutionStatus.BLOCKED,
                                    error=f"SCOPE_BLOCKED: Resolved IP '{rip}' not authorized.",
                                    task_id=t_id,
                                )

        # 3. Select environment adapter
        adapter = self._adapters.get(environment.lower()) or self._adapters["host"]

        # 4. Register cancellation token
        cancel_evt = cancel_token or threading.Event()
        with self._lock:
            self._active_cancels[t_id] = cancel_evt

        scope_id = ""
        scope_sig = ""
        if self.scope_guard:
            if getattr(self.scope_guard, "engagement_manager", None) and self.scope_guard.engagement_manager.get_active_engagement():
                act = self.scope_guard.engagement_manager.get_active_engagement()
                scope_id = act.id
                scope_sig = act.signature
            elif getattr(self.scope_guard, "scope_manager", None) and getattr(self.scope_guard.scope_manager, "scope", None):
                scope_id = getattr(self.scope_guard.scope_manager.scope, "id", "default")
                scope_sig = getattr(self.scope_guard.scope_manager.scope, "signature", "")

        val_cmd = ValidatedCommand(
            binary=binary,
            args=tuple(args),
            command_string=cmd_str,
            execution_environment=environment,
            working_directory=working_directory,
            targets=tuple(extracted_targets if is_net_cmd else ()),
            is_network=is_net_cmd,
            scope_id=scope_id,
            scope_snapshot_signature=scope_sig,
            gate_signature=_compute_gate_signature(binary, tuple(args), environment, scope_id, scope_sig),
        )

        try:
            res = adapter.execute(
                command=val_cmd,
                working_directory=working_directory,
                timeout_seconds=timeout_seconds,
                cancel_token=cancel_evt,
                task_id=t_id,
            )
        finally:
            with self._lock:
                self._active_cancels.pop(t_id, None)

        # 5. Audit Logging & Evidence generation
        if self.audit:
            self.audit.log(
                module="terminal",
                event="command_executed",
                status="SUCCESS" if res.exit_code == 0 else ("BLOCKED" if res.status == ExecutionStatus.BLOCKED else "ERROR"),
                details={
                    "command": res.command,
                    "environment": res.execution_environment,
                    "exit_code": res.exit_code,
                    "duration_ms": res.duration_ms,
                    "task_id": res.task_id,
                },
            )

        with self._lock:
            self.command_history.append({
                "task_id": res.task_id,
                "command": res.command,
                "args": res.args,
                "environment": res.execution_environment,
                "exit_code": res.exit_code,
                "status": res.status.value if isinstance(res.status, ExecutionStatus) else str(res.status),
                "duration_ms": res.duration_ms,
                "timestamp": res.completion_timestamp or res.start_timestamp,
                "output_hash": getattr(res, "output_hash", ""),
                "evidence_id": res.evidence_id,
            })
            if len(self.command_history) > 500:
                self.command_history = self.command_history[-500:]

        return res

    def get_command_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent executed terminal commands."""
        with self._lock:
            return list(self.command_history[-limit:])

    def detect_installed_security_tools(self) -> dict[str, dict[str, Any]]:
        """Detect presence, path, and version of standard cybersecurity CLI tools with millisecond latency."""
        tools_to_check = [
            "python", "nmap", "curl", "git", "gobuster", "nikto",
            "whatweb", "wget", "tshark", "nuclei", "docker"
        ]
        results: dict[str, dict[str, Any]] = {}
        for tool_name in tools_to_check:
            installed = False
            tool_path = None
            version = None
            environment = "host"

            if tool_name == "python":
                installed = True
                tool_path = sys.executable
                version = f"{platform.python_implementation()} {platform.python_version()}"
            else:
                found = shutil.which(tool_name)
                if found:
                    installed = True
                    tool_path = found
                    try:
                        flag = "--version" if tool_name not in ("nikto", "whatweb") else "-Version"
                        p = subprocess.run([found, flag], capture_output=True, text=True, timeout=2.0)
                        v_out = (p.stdout or p.stderr).strip().splitlines()
                        if v_out:
                            version = v_out[0][:80]
                    except Exception:
                        version = "Available"

            results[tool_name] = {
                "tool": tool_name,
                "installed": installed,
                "path": tool_path,
                "version": version or ("Available" if installed else "Not installed"),
                "environment": environment,
                "status": "AVAILABLE" if installed else "ABSENT",
            }
        return results
