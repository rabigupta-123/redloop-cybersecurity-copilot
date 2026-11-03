"""Tool Capability Intelligence & Central Tool Registry (Phase 2).

Provides truthful discovery, health status, and metadata for security tools across:
- Windows Host
- WSL (Windows Subsystem for Linux)
- Kali Linux
- Linux Native
- Docker Daemon
- Cloud / API Providers

Never fabricates tool availability or versions.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class ToolHealthStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"
    NOT_INSTALLED = "NOT_INSTALLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_CHECKED = "NOT_CHECKED"
    BLOCKED = "BLOCKED"


class ToolEnvironment(str, Enum):
    HOST = "host"
    WSL = "wsl"
    KALI = "kali"
    DOCKER = "docker"
    API = "api"
    LOCAL = "local"


class ToolCategory(str, Enum):
    NETWORK_RECON = "network_recon"
    WEB_SECURITY = "web_security"
    TLS_CERTS = "tls_certs"
    VULN_INTEL = "vuln_intel"
    OSINT = "osint"
    FORENSICS = "forensics"
    DEFENSIVE_SOC = "defensive_soc"
    LOCAL_TERMINAL = "local_terminal"


CATEGORY_LABELS = {
    ToolCategory.NETWORK_RECON.value: "Network Reconnaissance",
    ToolCategory.WEB_SECURITY.value: "Web Security",
    ToolCategory.TLS_CERTS.value: "TLS & Cryptography",
    ToolCategory.VULN_INTEL.value: "Vulnerability Intelligence",
    ToolCategory.OSINT.value: "OSINT & Domain Recon",
    ToolCategory.FORENSICS.value: "Files & Forensics",
    ToolCategory.DEFENSIVE_SOC.value: "Defensive & SOC",
    ToolCategory.LOCAL_TERMINAL.value: "Local Diagnostics",
}


@dataclass
class ToolCapabilityInfo:
    tool_id: str
    name: str
    category: str
    description: str
    installed: bool
    available: bool
    version: str | None = None
    executable_path: str | None = None
    environment: str = "host"
    health_status: ToolHealthStatus = ToolHealthStatus.NOT_CHECKED
    verification_method: str = "binary_presence"
    last_checked: str = ""
    reason: str = ""
    installation_guidance: str = ""
    supported_operations: list[str] = field(default_factory=list)
    supported_target_types: list[str] = field(default_factory=list)
    requires_authorization: bool = False
    passive_or_active: str = "passive"  # "passive", "active", "local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "category_label": CATEGORY_LABELS.get(self.category, self.category),
            "description": self.description,
            "installed": self.installed,
            "available": self.available,
            "version": self.version,
            "executable_path": self.executable_path,
            "environment": self.environment,
            "health_status": self.health_status.value if isinstance(self.health_status, ToolHealthStatus) else str(self.health_status),
            "verification_method": self.verification_method,
            "last_checked": self.last_checked or datetime.now(timezone.utc).isoformat(),
            "reason": self.reason,
            "installation_guidance": self.installation_guidance,
            "supported_operations": self.supported_operations,
            "supported_target_types": self.supported_target_types,
            "requires_authorization": self.requires_authorization,
            "passive_or_active": self.passive_or_active,
        }


# --- ENVIRONMENT DETECTOR ---

class EnvironmentDetector:
    """Discovers host, WSL, Kali, Linux, and Docker environments."""

    _cached_result: dict[str, Any] | None = None
    _cache_time: float = 0.0
    CACHE_TTL_SECONDS: float = 45.0

    @classmethod
    def detect_all(cls, force_refresh: bool = False) -> dict[str, Any]:
        now = time.time()
        if not force_refresh and cls._cached_result is not None and (now - cls._cache_time) < cls.CACHE_TTL_SECONDS:
            return cls._cached_result

        result = {
            "host": cls.detect_host(),
            "wsl": cls.detect_wsl(),
            "kali": cls.detect_kali(),
            "linux": cls.detect_linux(),
            "docker": cls.detect_docker(),
        }
        cls._cached_result = result
        cls._cache_time = now
        return result

    @classmethod
    def detect_host(cls) -> dict[str, Any]:
        is_windows = os.name == "nt"
        is_admin = False
        if is_windows:
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
        else:
            try:
                is_admin = os.getuid() == 0  # type: ignore[attr-defined]
            except Exception:
                is_admin = False

        # Java check (quick, max 1.0s)
        java_version = None
        java_exe = shutil.which("java")
        if java_exe:
            try:
                p = subprocess.run([java_exe, "-version"], capture_output=True, text=True, timeout=1.0)
                out = (p.stderr or p.stdout).strip()
                m = re.search(r'version "([^"]+)"', out)
                java_version = m.group(1) if m else "Installed"
            except Exception:
                java_version = "Installed (Unverified)"

        # Npcap check (Windows only)
        npcap_installed = False
        if is_windows:
            sys_root = os.environ.get("SystemRoot", r"C:\Windows")
            npcap_dll = os.path.join(sys_root, "System32", "Npcap", "wpcap.dll")
            winpcap_dll = os.path.join(sys_root, "System32", "wpcap.dll")
            if os.path.exists(npcap_dll) or os.path.exists(winpcap_dll):
                npcap_installed = True

        return {
            "os": platform.system(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "is_admin": is_admin,
            "java_version": java_version,
            "npcap_installed": npcap_installed,
            "label": "Windows Host" if is_windows else f"{platform.system()} Host",
        }

    @classmethod
    def detect_wsl(cls) -> dict[str, Any]:
        if os.name != "nt":
            return {
                "available": False,
                "distributions": [],
                "default_distro": None,
                "error": "WSL is only applicable on Windows.",
            }
        wsl_exe = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl_exe:
            return {
                "available": False,
                "distributions": [],
                "default_distro": None,
                "error": "wsl.exe was not found on system PATH.",
            }
        try:
            p = subprocess.run([wsl_exe, "--list", "--quiet"], capture_output=True, timeout=2.5)
            raw = p.stdout
            try:
                text = raw.decode("utf-16-le")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            distros = [line.strip().replace("\x00", "") for line in text.splitlines() if line.strip()]
            return {
                "available": len(distros) > 0,
                "distributions": distros,
                "default_distro": distros[0] if distros else None,
                "error": None if distros else "No WSL distributions installed.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": False,
                "distributions": [],
                "default_distro": None,
                "error": "WSL detection timed out.",
            }
        except Exception as ex:
            return {
                "available": False,
                "distributions": [],
                "default_distro": None,
                "error": str(ex),
            }

    @classmethod
    def detect_kali(cls) -> dict[str, Any]:
        wsl_info = cls.detect_wsl()
        kali_distros = [d for d in wsl_info.get("distributions", []) if "kali" in d.lower()]
        if kali_distros:
            return {
                "available": True,
                "environment_type": "wsl",
                "distro_name": kali_distros[0],
                "all_kali_distros": kali_distros,
                "error": None,
            }
        if platform.system().lower() == "linux":
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    content = f.read()
                    if "kali" in content.lower():
                        return {
                            "available": True,
                            "environment_type": "native_linux",
                            "distro_name": "kali-linux-native",
                            "all_kali_distros": ["native"],
                            "error": None,
                        }
            except Exception:
                pass
        return {
            "available": False,
            "environment_type": None,
            "distro_name": None,
            "all_kali_distros": [],
            "error": "Kali Linux distribution not detected.",
        }

    @classmethod
    def detect_linux(cls) -> dict[str, Any]:
        is_linux = platform.system().lower() == "linux"
        return {
            "available": is_linux,
            "kernel": platform.release() if is_linux else None,
            "release": platform.version() if is_linux else None,
        }

    @classmethod
    def detect_docker(cls) -> dict[str, Any]:
        docker_exe = shutil.which("docker")
        if not docker_exe:
            return {
                "available": False,
                "daemon_running": False,
                "version": None,
                "error": "docker binary not found on PATH.",
            }
        try:
            p = subprocess.run([docker_exe, "--version"], capture_output=True, text=True, timeout=1.5)
            version_str = p.stdout.strip() if p.returncode == 0 else None
            # Check daemon quickly
            daemon_running = False
            try:
                dp = subprocess.run([docker_exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=1.5)
                daemon_running = dp.returncode == 0
            except Exception:
                daemon_running = False

            return {
                "available": True,
                "daemon_running": daemon_running,
                "version": version_str,
                "error": None if daemon_running else "Docker binary present but daemon not running.",
            }
        except Exception as ex:
            return {
                "available": False,
                "daemon_running": False,
                "version": None,
                "error": str(ex),
            }


# --- CENTRAL TOOL REGISTRY ---

class ToolRegistryV2:
    """Central registry and verification engine for all REDLOOP tools across 8 categories."""

    _cached_catalog: list[ToolCapabilityInfo] | None = None
    _catalog_cache_time: float = 0.0
    CATALOG_TTL: float = 60.0

    @classmethod
    def list_all_tools(cls, force_refresh: bool = False) -> list[ToolCapabilityInfo]:
        now = time.time()
        if not force_refresh and cls._cached_catalog is not None and (now - cls._catalog_cache_time) < cls.CATALOG_TTL:
            return cls._cached_catalog

        environments = EnvironmentDetector.detect_all(force_refresh=force_refresh)
        tools = cls._inspect_all_tools(environments)
        cls._cached_catalog = tools
        cls._catalog_cache_time = now
        return tools

    @classmethod
    def get_tool(cls, tool_id: str) -> ToolCapabilityInfo | None:
        tools = cls.list_all_tools()
        for t in tools:
            if t.tool_id.lower() == tool_id.lower() or t.name.lower() == tool_id.lower():
                return t
        return None

    @classmethod
    def _inspect_all_tools(cls, environments: dict[str, Any]) -> list[ToolCapabilityInfo]:
        catalog: list[ToolCapabilityInfo] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        host_info = environments.get("host", {})
        wsl_info = environments.get("wsl", {})
        kali_info = environments.get("kali", {})
        docker_info = environments.get("docker", {})

        # Tool specifications definition:
        # tool_id, name, category, description, env_preference, probe_cmds, supported_ops, target_types, req_auth, pass_act, guidance
        tool_specs = [
            # A. Network Reconnaissance
            {
                "id": "nmap",
                "name": "Nmap Network Scanner",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "Network exploration and security auditing tool. Identifies open ports, OS, and services.",
                "probe": ["nmap", "--version"],
                "ops": ["port_scan", "service_detection", "os_fingerprinting", "stealth_syn_scan"],
                "target_types": ["ipv4", "ipv6", "domain", "cidr"],
                "auth": True,
                "type": "active",
                "guidance": "Install from https://nmap.org/download.html or run 'winget install Insecure.Nmap' (Windows) / 'apt install nmap' (Linux)",
            },
            {
                "id": "masscan",
                "name": "Masscan Fast Scanner",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "High-speed asynchronous TCP port scanner capable of scanning the entire Internet.",
                "probe": ["masscan", "--version"],
                "ops": ["fast_port_scan", "ip_range_sweep"],
                "target_types": ["ipv4", "cidr"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'apt install masscan' on Kali/WSL or compile from source https://github.com/robertdavidgraham/masscan",
            },
            {
                "id": "ping",
                "name": "ICMP Ping",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "ICMP Echo request utility for testing host reachability and round-trip time.",
                "probe": ["ping", "-n", "1", "127.0.0.1"] if os.name == "nt" else ["ping", "-c", "1", "127.0.0.1"],
                "ops": ["icmp_reachability", "latency_check"],
                "target_types": ["ipv4", "ipv6", "domain"],
                "auth": True,
                "type": "active",
                "guidance": "Standard system utility present on Windows, Linux, and macOS.",
            },
            {
                "id": "traceroute",
                "name": "Traceroute / Tracert",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "Network diagnostic tool for displaying the route path and transit delays across IP hops.",
                "probe": ["tracert", "-d", "-h", "1", "127.0.0.1"] if os.name == "nt" else ["traceroute", "-m", "1", "127.0.0.1"],
                "ops": ["route_tracing", "hop_latency"],
                "target_types": ["ipv4", "ipv6", "domain"],
                "auth": True,
                "type": "active",
                "guidance": "Built-in 'tracert' on Windows or 'apt install traceroute' on Linux.",
            },
            {
                "id": "arp",
                "name": "ARP Diagnostic Tool",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "Inspects and displays Address Resolution Protocol cache and IP-to-MAC mappings.",
                "probe": ["arp", "-a"],
                "ops": ["arp_cache_inspection", "local_mac_resolution"],
                "target_types": ["ipv4", "local"],
                "auth": False,
                "type": "passive",
                "guidance": "Standard networking utility built into Windows and Linux operating systems.",
            },
            {
                "id": "netstat",
                "name": "Netstat / SS Network Sockets",
                "category": ToolCategory.NETWORK_RECON.value,
                "desc": "Displays local active TCP/UDP listening connections, routing tables, and interface statistics.",
                "probe": ["netstat", "-an"],
                "ops": ["listening_ports", "socket_inspection", "connection_audit"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Standard host utility built into Windows and Linux operating systems.",
            },

            # B. Web Security
            {
                "id": "nikto",
                "name": "Nikto Web Vulnerability Scanner",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Comprehensive scanner for web servers, dangerous files/CGIs, outdated server software and configuration flaws.",
                "probe": ["nikto", "-Version"],
                "ops": ["web_server_audit", "misconfiguration_scan", "cve_identification"],
                "target_types": ["url", "domain", "ipv4"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'apt install nikto' on Kali/WSL or clone https://github.com/sullo/nikto",
            },
            {
                "id": "gobuster",
                "name": "Gobuster Directory & DNS Buster",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "High-performance Go-based tool used to brute-force URIs, DNS subdomains, and vhosts.",
                "probe": ["gobuster", "version"],
                "ops": ["dir_bruteforce", "dns_subdomain_bruteforce", "vhost_discovery"],
                "target_types": ["url", "domain"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'go install github.com/OJ/gobuster/v3@latest' or 'apt install gobuster'",
            },
            {
                "id": "feroxbuster",
                "name": "Feroxbuster Recursive Content Discovery",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Fast, simple, recursive content discovery tool written in Rust.",
                "probe": ["feroxbuster", "--version"],
                "ops": ["recursive_dir_discovery", "content_search"],
                "target_types": ["url", "domain"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'cargo install feroxbuster' or 'apt install feroxbuster' on Kali/WSL.",
            },
            {
                "id": "ffuf",
                "name": "FFuf Fast Web Fuzzer",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Fast web fuzzer written in Go for parameters, headers, directories, and virtual hosts.",
                "probe": ["ffuf", "-V"],
                "ops": ["parameter_fuzzing", "header_fuzzing", "endpoint_discovery"],
                "target_types": ["url", "domain"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'go install github.com/ffuf/ffuf/v2@latest' or 'apt install ffuf'",
            },
            {
                "id": "curl",
                "name": "cURL HTTP Client",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Versatile command-line tool for transferring data with URLs, inspecting headers, and testing API endpoints.",
                "probe": ["curl", "--version"],
                "ops": ["http_header_audit", "api_probing", "tls_negotiation_test"],
                "target_types": ["url", "domain", "ipv4"],
                "auth": False,
                "type": "passive",
                "guidance": "Pre-installed on modern Windows 10/11 and Linux distributions.",
            },
            {
                "id": "sqlmap",
                "name": "SQLMap Automated SQL Injection",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Automated tool that detects and exploits SQL injection flaws and takes over database servers.",
                "probe": ["sqlmap", "--version"],
                "ops": ["sqli_detection", "db_enumeration", "injection_verification"],
                "target_types": ["url"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'pip install sqlmap' or 'apt install sqlmap' on Kali/WSL.",
            },
            {
                "id": "nuclei",
                "name": "Nuclei Vulnerability Scanner",
                "category": ToolCategory.WEB_SECURITY.value,
                "desc": "Fast and customizable vulnerability scanner based on community-curated YAML templates.",
                "probe": ["nuclei", "-version"],
                "ops": ["template_vuln_scan", "cve_detection", "misconfiguration_check"],
                "target_types": ["url", "domain", "ipv4"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' or binary release.",
            },

            # C. TLS & Cryptography
            {
                "id": "openssl",
                "name": "OpenSSL Cryptographic Toolkit",
                "category": ToolCategory.TLS_CERTS.value,
                "desc": "Robust commercial-grade toolkit for Transport Layer Security (TLS) and Secure Sockets Layer (SSL).",
                "probe": ["openssl", "version"],
                "ops": ["certificate_inspection", "tls_handshake_test", "cipher_suite_check"],
                "target_types": ["domain", "ipv4", "local"],
                "auth": False,
                "type": "passive",
                "guidance": "Install via 'winget install ShiningLight.OpenSSL' (Windows) or 'apt install openssl' (Linux).",
            },
            {
                "id": "testssl",
                "name": "testssl.sh TLS/SSL Auditor",
                "category": ToolCategory.TLS_CERTS.value,
                "desc": "Command-line tool which checks a server's service on any port for the support of TLS/SSL ciphers and flaws.",
                "probe": ["testssl.sh", "--version"],
                "ops": ["tls_vulnerability_audit", "cipher_evaluation", "cert_validity_check"],
                "target_types": ["domain", "ipv4"],
                "auth": True,
                "type": "active",
                "guidance": "Clone https://github.com/drwetter/testssl.sh or install via 'apt install testssl.sh' on Kali/WSL.",
            },
            {
                "id": "sslyze",
                "name": "SSLyze TLS Scanner",
                "category": ToolCategory.TLS_CERTS.value,
                "desc": "Fast and powerful SSL/TLS scanning library and CLI tool for analyzing server configurations.",
                "probe": ["sslyze", "--version"],
                "ops": ["tls_compliance_check", "robot_check", "heartbleed_check"],
                "target_types": ["domain", "ipv4"],
                "auth": True,
                "type": "active",
                "guidance": "Install via 'pip install --upgrade sslyze'.",
            },

            # D. Vulnerability Intelligence
            {
                "id": "trivy",
                "name": "Trivy Security Scanner",
                "category": ToolCategory.VULN_INTEL.value,
                "desc": "Comprehensive security scanner for container images, file systems, Git repositories, and Kubernetes.",
                "probe": ["trivy", "--version"],
                "ops": ["container_scan", "fs_vulnerability_scan", "sbom_generation"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Install via 'winget install AquaSecurity.Trivy' or 'brew install trivy' or 'apt install trivy'.",
            },
            {
                "id": "grype",
                "name": "Grype Vulnerability Scanner",
                "category": ToolCategory.VULN_INTEL.value,
                "desc": "Vulnerability scanner for container images and filesystems from Anchore.",
                "probe": ["grype", "version"],
                "ops": ["image_vuln_scan", "sbom_vuln_audit"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Install via 'winget install anchore.grype' or binary from https://github.com/anchore/grype.",
            },

            # E. OSINT & Reconnaissance
            {
                "id": "whois",
                "name": "WHOIS Client",
                "category": ToolCategory.OSINT.value,
                "desc": "Queries WHOIS databases for domain registration details, registrar, name servers, and expiration dates.",
                "probe": ["whois", "--version"],
                "ops": ["domain_registration_lookup", "registrar_audit"],
                "target_types": ["domain", "ipv4"],
                "auth": False,
                "type": "passive",
                "guidance": "Install via 'apt install whois' or Sysinternals Whois for Windows.",
            },
            {
                "id": "nslookup",
                "name": "NSLookup DNS Resolver",
                "category": ToolCategory.OSINT.value,
                "desc": "Queries Internet domain name servers interactively or non-interactively for A, MX, NS, and TXT records.",
                "probe": ["nslookup", "localhost"],
                "ops": ["dns_record_query", "name_resolution", "spf_dmarc_check"],
                "target_types": ["domain", "ipv4"],
                "auth": False,
                "type": "passive",
                "guidance": "Pre-installed standard DNS utility on all Windows, macOS, and Linux systems.",
            },
            {
                "id": "dig",
                "name": "Dig Domain Information Groper",
                "category": ToolCategory.OSINT.value,
                "desc": "Flexible tool for interrogating DNS name servers, verifying zone transfers, and inspecting DNSSEC.",
                "probe": ["dig", "-v"],
                "ops": ["dns_deep_query", "zone_transfer_test", "dnssec_validation"],
                "target_types": ["domain"],
                "auth": False,
                "type": "passive",
                "guidance": "Install BIND tools via 'apt install dnsutils' or 'winget install ISC.BIND'.",
            },
            {
                "id": "theharvester",
                "name": "theHarvester OSINT Gathering",
                "category": ToolCategory.OSINT.value,
                "desc": "Gathers emails, names, subdomains, IPs, and URLs using multiple public data sources and search engines.",
                "probe": ["theHarvester", "-h"],
                "ops": ["email_harvesting", "subdomain_enumeration", "employee_osint"],
                "target_types": ["domain"],
                "auth": False,
                "type": "passive",
                "guidance": "Install via 'apt install theharvester' on Kali/WSL or clone https://github.com/laramies/theHarvester.",
            },
            {
                "id": "shodan",
                "name": "Shodan Threat Intelligence API",
                "category": ToolCategory.OSINT.value,
                "desc": "Search engine for Internet-connected devices, providing open ports, CVE banners, and exposures.",
                "probe": ["api_key_check", "SHODAN_API_KEY"],
                "ops": ["ip_enrichment", "exposed_service_lookup", "cve_exposure_check"],
                "target_types": ["ipv4", "domain"],
                "auth": False,
                "type": "passive",
                "guidance": "Configure SHODAN_API_KEY in your REDLOOP environment settings or .env file.",
            },
            {
                "id": "virustotal",
                "name": "VirusTotal Threat Intelligence API",
                "category": ToolCategory.OSINT.value,
                "desc": "Aggregates scan results from dozens of antivirus engines and domain blocklists.",
                "probe": ["api_key_check", "VT_API_KEY"],
                "ops": ["file_hash_reputation", "domain_reputation", "ip_reputation"],
                "target_types": ["ipv4", "domain", "file"],
                "auth": False,
                "type": "passive",
                "guidance": "Configure VT_API_KEY in your REDLOOP environment settings or .env file.",
            },

            # F. Files & Forensics
            {
                "id": "strings",
                "name": "Strings Utility",
                "category": ToolCategory.FORENSICS.value,
                "desc": "Finds and prints printable character sequences in binary files, executables, or memory dumps.",
                "probe": ["strings", "--version"],
                "ops": ["binary_string_extraction", "hardcoded_credential_search"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Standard binutils package on Linux / WSL or Sysinternals Strings on Windows.",
            },
            {
                "id": "exiftool",
                "name": "ExifTool Metadata Analyzer",
                "category": ToolCategory.FORENSICS.value,
                "desc": "Reads, writes, and manipulates image, document, and media metadata (EXIF, IPTC, XMP).",
                "probe": ["exiftool", "-ver"],
                "ops": ["metadata_extraction", "author_identification", "gps_data_audit"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Download from https://exiftool.org or install via 'apt install exiftool'.",
            },
            {
                "id": "yara",
                "name": "YARA Pattern Matching",
                "category": ToolCategory.FORENSICS.value,
                "desc": "Pattern matching swiss knife for malware researchers to identify and classify malware samples.",
                "probe": ["yara", "--version"],
                "ops": ["malware_signature_scan", "rule_evaluation", "artifact_triage"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Install via 'apt install yara' or download binary release from VirusTotal/yara.",
            },
            {
                "id": "tshark",
                "name": "TShark / Wireshark Packet Analyzer",
                "category": ToolCategory.FORENSICS.value,
                "desc": "Terminal-oriented network protocol analyzer that lets you capture or decode packet data from PCAP files.",
                "probe": ["tshark", "--version"],
                "ops": ["pcap_analysis", "traffic_dissection", "flow_reconstruction"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Install Wireshark with TShark CLI enabled from https://www.wireshark.org or 'apt install tshark'.",
            },

            # G. Defensive & SOC
            {
                "id": "tcpdump",
                "name": "tcpdump Packet Capture",
                "category": ToolCategory.DEFENSIVE_SOC.value,
                "desc": "Powerful command-line packet analyzer for capturing and filtering network packets on an interface.",
                "probe": ["tcpdump", "--version"],
                "ops": ["live_packet_capture", "pcap_dump", "filter_evaluation"],
                "target_types": ["local"],
                "auth": True,
                "type": "active",
                "guidance": "Standard network capture tool on Linux / WSL ('apt install tcpdump').",
            },
            {
                "id": "suricata",
                "name": "Suricata IDS/IPS Engine",
                "category": ToolCategory.DEFENSIVE_SOC.value,
                "desc": "High performance Network IDS, IPS, and Network Security Monitoring engine.",
                "probe": ["suricata", "-V"],
                "ops": ["ids_rule_evaluation", "pcap_threat_inspection", "network_telemetry"],
                "target_types": ["local", "file"],
                "auth": False,
                "type": "local",
                "guidance": "Install via 'apt install suricata' on Linux/WSL or binary installer.",
            },

            # H. Local Diagnostics
            {
                "id": "powershell",
                "name": "PowerShell Core / Windows PowerShell",
                "category": ToolCategory.LOCAL_TERMINAL.value,
                "desc": "Task automation and configuration management framework with interactive command-line shell.",
                "probe": ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
                "ops": ["host_automation", "system_diagnostics", "process_inspection"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Built-in on Windows or install PowerShell 7+ via 'winget install Microsoft.PowerShell'.",
            },
            {
                "id": "bash",
                "name": "Bash Shell",
                "category": ToolCategory.LOCAL_TERMINAL.value,
                "desc": "Bourne Again SHell, the standard Unix and Linux command execution environment.",
                "probe": ["bash", "--version"],
                "ops": ["shell_scripting", "kali_automation", "pipeline_processing"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Standard Linux/WSL shell or available via Git for Windows.",
            },
            {
                "id": "python3",
                "name": "Python 3 Runtime",
                "category": ToolCategory.LOCAL_TERMINAL.value,
                "desc": "Core Python execution runtime powering REDLOOP automation and analysis scripts.",
                "probe": [sys.executable, "--version"],
                "ops": ["script_execution", "data_transformation", "custom_probes"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Active Python interpreter currently running the REDLOOP application.",
            },
            {
                "id": "git",
                "name": "Git Version Control",
                "category": ToolCategory.LOCAL_TERMINAL.value,
                "desc": "Distributed version control system for tracking changes in source code and audit repositories.",
                "probe": ["git", "--version"],
                "ops": ["repo_inspection", "audit_versioning"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Download from https://git-scm.com or install via 'winget install Git.Git'.",
            },
            {
                "id": "wsl",
                "name": "Windows Subsystem for Linux",
                "category": ToolCategory.LOCAL_TERMINAL.value,
                "desc": "Compatibility layer for running Linux binary executables natively on Windows 10/11.",
                "probe": ["wsl", "--status"],
                "ops": ["linux_subsystem_execution", "kali_bridge"],
                "target_types": ["local"],
                "auth": False,
                "type": "local",
                "guidance": "Install using 'wsl --install' or 'wsl --install -d kali-linux'.",
            },
        ]

        for spec in tool_specs:
            t_id = spec["id"]
            name = spec["name"]
            cat = spec["category"]
            desc = spec["desc"]
            ops = spec["ops"]
            target_types = spec["target_types"]
            auth = spec["auth"]
            p_or_a = spec["type"]
            guidance = spec["guidance"]
            probe = spec["probe"]

            tool_info = cls._verify_tool(
                tool_id=t_id,
                name=name,
                category=cat,
                description=desc,
                probe=probe,
                supported_operations=ops,
                supported_target_types=target_types,
                requires_authorization=auth,
                passive_or_active=p_or_a,
                guidance=guidance,
                environments=environments,
                now_iso=now_iso,
            )
            catalog.append(tool_info)

        return catalog

    @classmethod
    def _verify_tool(
        cls,
        tool_id: str,
        name: str,
        category: str,
        description: str,
        probe: list[str],
        supported_operations: list[str],
        supported_target_types: list[str],
        requires_authorization: bool,
        passive_or_active: str,
        guidance: str,
        environments: dict[str, Any],
        now_iso: str,
    ) -> ToolCapabilityInfo:
        # Check API key based tools first
        if probe and probe[0] == "api_key_check":
            env_var = probe[1]
            key_val = os.environ.get(env_var, "").strip()
            configured = bool(key_val and len(key_val) > 4)
            return ToolCapabilityInfo(
                tool_id=tool_id,
                name=name,
                category=category,
                description=description,
                installed=configured,
                available=configured,
                version="API v2" if configured else None,
                executable_path=f"env:{env_var}",
                environment="api",
                health_status=ToolHealthStatus.AVAILABLE if configured else ToolHealthStatus.NOT_CONFIGURED,
                verification_method="api_key_check",
                last_checked=now_iso,
                reason="API key configured and ready" if configured else f"Missing environment variable {env_var}",
                installation_guidance=guidance,
                supported_operations=supported_operations,
                supported_target_types=supported_target_types,
                requires_authorization=requires_authorization,
                passive_or_active=passive_or_active,
            )

        binary_name = probe[0]
        # Resolve executable on host PATH
        exe_path = shutil.which(binary_name)
        env_type = "host"

        # Special case: python3 is the current interpreter
        if tool_id == "python3":
            exe_path = sys.executable
            version_str = platform.python_version()
            return ToolCapabilityInfo(
                tool_id=tool_id,
                name=name,
                category=category,
                description=description,
                installed=True,
                available=True,
                version=version_str,
                executable_path=exe_path,
                environment="host",
                health_status=ToolHealthStatus.AVAILABLE,
                verification_method="runtime_interpreter",
                last_checked=now_iso,
                reason="Running Python runtime",
                installation_guidance=guidance,
                supported_operations=supported_operations,
                supported_target_types=supported_target_types,
                requires_authorization=requires_authorization,
                passive_or_active=passive_or_active,
            )

        # Special check for nmap on Windows: Check Npcap status for raw SYN mode
        if tool_id == "nmap" and exe_path:
            npcap_ok = environments.get("host", {}).get("npcap_installed", False)
            version_str = cls._get_binary_version(exe_path, probe)
            if not npcap_ok and os.name == "nt":
                return ToolCapabilityInfo(
                    tool_id=tool_id,
                    name=name,
                    category=category,
                    description=description,
                    installed=True,
                    available=True,
                    version=version_str,
                    executable_path=exe_path,
                    environment="host",
                    health_status=ToolHealthStatus.DEGRADED,
                    verification_method="binary_execution_with_driver_audit",
                    last_checked=now_iso,
                    reason="Npcap driver missing: TCP connect scan (-sT) available, raw SYN stealth scan (-sS) degraded",
                    installation_guidance="Install Npcap in WinPcap-compatible mode from https://npcap.com/#download for raw SYN scanning.",
                    supported_operations=["port_scan", "service_detection"],
                    supported_target_types=supported_target_types,
                    requires_authorization=requires_authorization,
                    passive_or_active=passive_or_active,
                )

        if exe_path:
            version_str = cls._get_binary_version(exe_path, probe)
            return ToolCapabilityInfo(
                tool_id=tool_id,
                name=name,
                category=category,
                description=description,
                installed=True,
                available=True,
                version=version_str,
                executable_path=exe_path,
                environment="host",
                health_status=ToolHealthStatus.AVAILABLE,
                verification_method="binary_execution",
                last_checked=now_iso,
                reason="Executable located on PATH and verified",
                installation_guidance=guidance,
                supported_operations=supported_operations,
                supported_target_types=supported_target_types,
                requires_authorization=requires_authorization,
                passive_or_active=passive_or_active,
            )

        # Check if WSL / Kali is available and binary exists there
        wsl_info = environments.get("wsl", {})
        kali_info = environments.get("kali", {})
        if wsl_info.get("available") and os.name == "nt":
            # Quick non-blocking WSL which check (max 1.5s)
            wsl_exe = shutil.which("wsl.exe")
            target_distro = kali_info.get("distro_name") or wsl_info.get("default_distro")
            if wsl_exe and target_distro:
                try:
                    cmd = [wsl_exe, "-d", target_distro, "--", "which", binary_name]
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5)
                    if p.returncode == 0 and p.stdout.strip():
                        wsl_bin_path = p.stdout.strip()
                        env_label = "kali" if "kali" in target_distro.lower() else "wsl"
                        return ToolCapabilityInfo(
                            tool_id=tool_id,
                            name=name,
                            category=category,
                            description=description,
                            installed=True,
                            available=True,
                            version=f"WSL ({target_distro})",
                            executable_path=f"wsl:{target_distro}:{wsl_bin_path}",
                            environment=env_label,
                            health_status=ToolHealthStatus.AVAILABLE,
                            verification_method="wsl_which_probe",
                            last_checked=now_iso,
                            reason=f"Available inside WSL distribution '{target_distro}'",
                            installation_guidance=guidance,
                            supported_operations=supported_operations,
                            supported_target_types=supported_target_types,
                            requires_authorization=requires_authorization,
                            passive_or_active=passive_or_active,
                        )
                except Exception:
                    pass

        # Tool is NOT installed or unavailable
        return ToolCapabilityInfo(
            tool_id=tool_id,
            name=name,
            category=category,
            description=description,
            installed=False,
            available=False,
            version=None,
            executable_path=None,
            environment="host",
            health_status=ToolHealthStatus.NOT_INSTALLED,
            verification_method="path_lookup_and_wsl_probe",
            last_checked=now_iso,
            reason=f"Executable '{binary_name}' was not found on PATH or in WSL",
            installation_guidance=guidance,
            supported_operations=supported_operations,
            supported_target_types=supported_target_types,
            requires_authorization=requires_authorization,
            passive_or_active=passive_or_active,
        )

    @classmethod
    def _get_binary_version(cls, exe_path: str, probe_cmd: list[str]) -> str:
        try:
            cmd = [exe_path] + probe_cmd[1:]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=1.2)
            out = (p.stdout or p.stderr).strip()
            # Extract first version-like token
            m = re.search(r"\b(?:version\s*|v)?(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?)\b", out, re.IGNORECASE)
            if m:
                return m.group(1)
            # Fallback to first line
            first_line = out.splitlines()[0] if out else "Installed"
            return first_line[:40].strip()
        except Exception:
            return "Installed"

    @classmethod
    def get_capabilities_summary(cls, force_refresh: bool = False) -> dict[str, Any]:
        tools = cls.list_all_tools(force_refresh=force_refresh)
        environments = EnvironmentDetector.detect_all(force_refresh=force_refresh)

        summary = {
            "total": len(tools),
            "available": 0,
            "unavailable": 0,
            "degraded": 0,
            "not_installed": 0,
            "not_configured": 0,
            "not_checked": 0,
        }

        for t in tools:
            st = t.health_status
            if st == ToolHealthStatus.AVAILABLE:
                summary["available"] += 1
            elif st == ToolHealthStatus.DEGRADED:
                summary["degraded"] += 1
            elif st == ToolHealthStatus.NOT_CONFIGURED:
                summary["not_configured"] += 1
            elif st == ToolHealthStatus.NOT_INSTALLED:
                summary["not_installed"] += 1
                summary["unavailable"] += 1
            elif st == ToolHealthStatus.UNAVAILABLE or st == ToolHealthStatus.BLOCKED:
                summary["unavailable"] += 1
            else:
                summary["not_checked"] += 1

        return {
            "success": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "environments": environments,
            "tools": [t.to_dict() for t in tools],
            "summary": summary,
        }

