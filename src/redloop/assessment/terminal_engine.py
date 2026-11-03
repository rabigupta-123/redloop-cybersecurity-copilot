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

import os
import platform
import re
import shlex
import shutil
import signal
import sys
import subprocess
import threading
import time
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
        }


def _safe_decode(raw: bytes) -> tuple[str, bool]:
    """Decodes raw bytes handling multi-encoding and limits output to MAX_OUTPUT_BYTES."""
    truncated = False
    if len(raw) > MAX_OUTPUT_BYTES:
        raw = raw[:MAX_OUTPUT_BYTES]
        truncated = True

    for enc in ("utf-8", "utf-16-le", "cp437", "latin-1"):
        try:
            text = raw.decode(enc)
            return text, truncated
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace"), truncated


# --- BASE EXECUTION ADAPTER ---


# --- PROCESS MANAGEMENT & SECURITY RESTRICTIONS ---

ALLOWED_EXECUTABLES = {
    # Recon & Port Scanning
    "nmap", "masscan", "rustscan", "ping", "traceroute", "tracert", "fping", "netstat", "ss",
    # DNS & OSINT
    "nslookup", "dig", "host", "whois", "subfinder", "amass",
    # Web & HTTP
    "curl", "httpx", "nikto", "gobuster", "dirb", "ffuf", "nuclei", "wapiti", "wpscan",
    # TLS & Cryptography
    "openssl", "testssl.sh", "sslscan",
    # Runtime & Diagnostics
    "python", "python3", "python.exe", "python3.exe", "echo", "uname", "wsl", "wsl.exe", "docker", "docker.exe", "git", "git.exe",
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
        binary: str,
        args: list[str],
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
        binary: str,
        args: list[str],
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        start_ts = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        full_cmd_str = " ".join([binary] + args)

        if cancel_token and cancel_token.is_set():
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
                stderr="Process execution cancelled by user before process creation.",
                exit_code=-1,
                cancelled=True,
                status=ExecutionStatus.CANCELLED,
                error="Execution cancelled before process creation.",
                task_id=task_id,
            )

        # Locate executable
        if binary in ("python", "python3"):
            import sys
            exe_path = sys.executable
        else:
            exe_path = shutil.which(binary)
        if not exe_path:
            duration_ms = (time.time() - t0) * 1000
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
                stderr=f"Executable '{binary}' not found on host PATH.",
                exit_code=127,
                status=ExecutionStatus.ERROR,
                error=f"Executable '{binary}' was not found on host system PATH.",
                task_id=task_id,
            )

        cwd = working_directory if (working_directory and os.path.exists(working_directory)) else None
        cmd_tokens = [exe_path] + args

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
            )

        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
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
                stderr=str(exc),
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"Host execution exception: {exc}",
                task_id=task_id,
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
        binary: str,
        args: list[str],
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()
        full_cmd_str = " ".join([binary] + args)

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
            )
        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
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
                stderr=str(exc),
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"WSL execution error: {exc}",
                task_id=task_id,
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
        binary: str,
        args: list[str],
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()
        full_cmd_str = " ".join([binary] + args)

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
                execution_environment="kali",
                executable_path=None,
                working_directory=working_directory,
                start_timestamp=start_ts,
                completion_timestamp=datetime.now(timezone.utc).isoformat(),
                duration_ms=0.0,
                stdout="",
                stderr=reason or "Kali Linux is not installed or registered.",
                exit_code=127,
                status=ExecutionStatus.ENVIRONMENT_UNAVAILABLE,
                error=reason,
                task_id=task_id,
            )

        kali_info = EnvironmentDetector.detect_kali()
        distro = kali_info.get("distro_name")
        wsl_adapter = WSLExecutionAdapter(distro=distro)
        res = wsl_adapter.execute(
            binary=binary,
            args=args,
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
        binary: str,
        args: list[str],
        working_directory: str | None = None,
        timeout_seconds: int = 30,
        cancel_token: threading.Event | None = None,
        task_id: str | None = None,
    ) -> ExecutionResult:
        avail, reason = self.is_available()
        start_ts = datetime.now(timezone.utc).isoformat()
        full_cmd_str = " ".join([binary] + args)

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
            )
        except Exception as exc:
            duration_ms = (time.time() - t0) * 1000
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
                stderr=str(exc),
                exit_code=1,
                status=ExecutionStatus.ERROR,
                error=f"Docker execution error: {exc}",
                task_id=task_id,
            )


# --- UNIFIED TERMINAL ENGINE ---

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
        command_string_or_args: str | list[str],
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

        # 1. Parse into binary and argument list
        if isinstance(command_string_or_args, str):
            cmd_str = command_string_or_args.strip()
            # Safety parse via KaliCommandParser
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
            binary = command_string_or_args[0]
            args = command_string_or_args[1:]
            cmd_str = " ".join(command_string_or_args)
            inferred_target = target
            is_network = binary.lower() in KaliCommandParser.NETWORK_TOOLS

        # 2. Scope verification gate for active network probes
        if is_network and inferred_target:
            if self.scope_guard is not None:
                authorized = self.scope_guard.is_target_authorized(inferred_target, "scan")
                if not authorized:
                    if self.audit:
                        self.audit.log(
                            module="terminal",
                            event="scope_blocked",
                            status="BLOCKED",
                            details={"target": inferred_target, "command": cmd_str},
                        )
                    return ExecutionResult(
                        command=cmd_str,
                        args=args,
                        execution_environment=environment,
                        start_timestamp=start_ts,
                        completion_timestamp=datetime.now(timezone.utc).isoformat(),
                        duration_ms=0.0,
                        stdout="",
                        stderr=f"SCOPE_BLOCKED: Target '{inferred_target}' is not authorized in scope.",
                        exit_code=126,
                        status=ExecutionStatus.BLOCKED,
                        error=f"SCOPE_BLOCKED: Target '{inferred_target}' is not in authorized scope.",
                        task_id=t_id,
                    )

        # 3. Select environment adapter
        adapter = self._adapters.get(environment.lower()) or self._adapters["host"]

        # 4. Register cancellation token
        cancel_evt = cancel_token or threading.Event()
        with self._lock:
            self._active_cancels[t_id] = cancel_evt

        try:
            res = adapter.execute(
                binary=binary,
                args=args,
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

        return res
