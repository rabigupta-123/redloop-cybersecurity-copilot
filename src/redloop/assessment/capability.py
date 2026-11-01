"""Runtime detection of security tools and assessment engine capabilities.

Never fakes tool presence or tool results.
Reports tool availability truthfully; missing tools yield UNAVAILABLE status.
Provides explicit installation guidance and supported environment boundaries (Phase 9).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    notes: str = ""
    reason: str = ""
    installation_guidance: str = ""
    supported_environment: str = "Native / WSL / Docker"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "notes": self.notes,
            "reason": self.reason,
            "installation_guidance": self.installation_guidance,
            "supported_environment": self.supported_environment,
        }


class CapabilityMatrix:
    """Discovers and catalogs installed external security tools at runtime."""

    KNOWN_TOOLS: tuple[tuple[str, list[str], str, str], ...] = (
        (
            "nmap",
            ["nmap", "--version"],
            "Download from https://nmap.org/download.html or run 'winget install Insecure.Nmap' (Windows) / 'apt install nmap' (Linux)",
            "Native (Connect Scan) / Elevated Npcap (SYN Scan) / Kali WSL",
        ),
        (
            "gobuster",
            ["gobuster", "version"],
            "Install via 'go install github.com/OJ/gobuster/v3@latest' or 'apt install gobuster'",
            "Native / WSL / Kali Docker",
        ),
        (
            "nikto",
            ["nikto", "-Version"],
            "Install via 'apt install nikto' or clone https://github.com/sullo/nikto",
            "WSL / Kali Docker / Perl Native",
        ),
        (
            "docker",
            ["docker", "--version"],
            "Install Docker Desktop from https://www.docker.com/products/docker-desktop/",
            "Docker Daemon / Linux Containers",
        ),
        (
            "ollama",
            ["ollama", "--version"],
            "Install Ollama from https://ollama.com/download and run 'ollama serve'",
            "Local Loopback (http://127.0.0.1:11434)",
        ),
        (
            "npcap",
            [],
            "Install Npcap in WinPcap API-compatible mode from https://npcap.com/#download",
            "Windows Kernel Driver (Required for raw SYN stealth packets)",
        ),
        (
            "wsl",
            ["wsl", "--status"],
            "Install WSL2 and Kali Linux using 'wsl --install -d kali-linux'",
            "Windows Subsystem for Linux 2",
        ),
        (
            "curl",
            ["curl", "--version"],
            "Built-in on Windows 10/11 or install via winget / apt",
            "Native CLI",
        ),
        (
            "openssl",
            ["openssl", "version"],
            "Install via 'winget install ShiningLight.OpenSSL' or 'apt install openssl'",
            "Native CLI",
        ),
        (
            "dig",
            ["dig", "-v"],
            "Install BIND tools via 'winget install ISC.BIND' or 'apt install dnsutils'",
            "Native / WSL",
        ),
        (
            "nslookup",
            ["nslookup", "-version"],
            "Built-in Windows / Linux diagnostic tool",
            "Native CLI",
        ),
        (
            "git",
            ["git", "--version"],
            "Install from https://git-scm.com/downloads",
            "Native CLI",
        ),
        (
            "yara",
            ["yara", "--version"],
            "Install yara-python via 'pip install yara-python' or apt install yara",
            "Native Python / C Extensions",
        ),
        (
            "trivy",
            ["trivy", "--version"],
            "Install from https://aquasecurity.github.io/trivy/",
            "Native / Container Triage",
        ),
        (
            "semgrep",
            ["semgrep", "--version"],
            "Install via 'pip install semgrep'",
            "Python / SAST",
        ),
        (
            "gitleaks",
            ["gitleaks", "version"],
            "Install from https://github.com/gitleaks/gitleaks",
            "Native Secret Scanner",
        ),
        (
            "zap",
            ["zap.sh", "-version"],
            "Install OWASP ZAP from https://www.zaproxy.org/",
            "Java Runtime / Headless Daemon",
        ),
        (
            "nuclei",
            ["nuclei", "-version"],
            "Install via 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
            "Native / Go Tooling",
        ),
    )

    def __init__(self) -> None:
        self.tools: dict[str, ToolStatus] = {}
        self.detect_all()

    def detect_all(self) -> dict[str, ToolStatus]:
        """Probe the system PATH and system libraries for known security tools."""
        for tool_name, version_cmd, install_guide, supported_env in self.KNOWN_TOOLS:
            # Special case for Npcap on Windows
            if tool_name == "npcap":
                is_npcap = False
                npcap_path = None
                if sys.platform == "win32":
                    sys32 = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32"
                    npcap_path = os.path.join(sys32, "Npcap")
                    if os.path.exists(npcap_path) or os.path.exists(os.path.join(sys32, "wpcap.dll")):
                        is_npcap = True
                self.tools[tool_name] = ToolStatus(
                    name=tool_name,
                    available=is_npcap,
                    path=npcap_path if is_npcap else None,
                    version="Npcap Packet Driver" if is_npcap else None,
                    notes="Required for raw SYN scans without TCP connect overhead" if is_npcap else "Not detected; Nmap will use TCP Connect scan (-sT)",
                    reason="Npcap driver detected" if is_npcap else "Npcap packet driver not installed on Windows host",
                    installation_guidance=install_guide,
                    supported_environment=supported_env,
                )
                continue

            path = shutil.which(tool_name)
            if not path:
                self.tools[tool_name] = ToolStatus(
                    name=tool_name,
                    available=False,
                    path=None,
                    version=None,
                    notes="Executable not found on system PATH",
                    reason=f"Binary '{tool_name}' not in system PATH",
                    installation_guidance=install_guide,
                    supported_environment=supported_env,
                )
                continue

            version_str = None
            if version_cmd:
                try:
                    proc = subprocess.run(
                        version_cmd,
                        capture_output=True,
                        text=True,
                        timeout=3.0,
                        check=False,
                    )
                    output = proc.stdout.strip() or proc.stderr.strip()
                    if output:
                        version_str = output.splitlines()[0][:80]
                except Exception:
                    version_str = "detected"

            self.tools[tool_name] = ToolStatus(
                name=tool_name,
                available=True,
                path=path,
                version=version_str or "detected",
                notes="Available for assessment operations",
                reason="Executable verified and accessible",
                installation_guidance=install_guide,
                supported_environment=supported_env,
            )
        return self.tools

    def is_available(self, tool_name: str) -> bool:
        status = self.tools.get(tool_name)
        return bool(status and status.available)

    def summary(self) -> dict[str, Any]:
        return {
            name: {
                "available": status.available,
                "version": status.version,
                "path": status.path,
                "reason": status.reason,
                "installation_guidance": status.installation_guidance,
                "supported_environment": status.supported_environment,
            }
            for name, status in self.tools.items()
        }


# Singleton capability matrix
_matrix: CapabilityMatrix | None = None


def get_capabilities() -> CapabilityMatrix:
    global _matrix
    if _matrix is None:
        _matrix = CapabilityMatrix()
    return _matrix
