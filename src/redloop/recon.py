"""Narrow, explicitly port-scoped Nmap checks for literal loopback addresses."""

from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord
from redloop.scope import ScopeManager, UnauthorizedTargetError

MAX_PORTS = 16
DEFAULT_PORTS = (22, 80, 443, 3000, 8000, 8080, 8443)
NMAP_TIMEOUT_SECONDS = 60


class PortResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65_535)
    protocol: str = "tcp"
    state: str
    service: str | None = None
    version: str | None = None
    confidence: str | None = None
    escalation: dict[str, Any] | None = None


class ReconResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    source: str = "nmap"
    port_results: list[PortResult] = Field(default_factory=list)
    open_ports: list[PortResult] = Field(default_factory=list)
    scanned_ports: list[int] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    raw_summary: str = ""
    escalations: list[dict[str, Any]] = Field(default_factory=list)


class ReconError(Exception):
    """Base error for the constrained recon wrapper."""


class ReconDependencyError(ReconError):
    """Raised when the optional Nmap dependency is unavailable."""


class ReconExecutionError(ReconError):
    """Raised when a local Nmap invocation fails."""


class ReconProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    requested_ports: list[int]
    authorized_ports: list[int]
    scanned_ports: list[int]
    port_results: list[PortResult] = Field(default_factory=list)
    open_ports: list[PortResult] = Field(default_factory=list)
    scan_source: str = "nmap"


class NmapScanner:
    """Scan only explicitly authorized ports on a literal loopback IP."""

    def __init__(
        self,
        scope: ScopeManager,
        audit: AuditLogger,
        memory: EpisodicMemory | None = None,
        scanner: Any | None = None,
        raw_socket_fn: Any | None = None,
    ):
        self.scope = scope
        self.audit = audit
        self.memory = memory
        self.scanner = scanner
        self.raw_socket_fn = raw_socket_fn

    def quick_scan(
        self, target: str, ports: tuple[int, ...] | list[int] = DEFAULT_PORTS
    ) -> ReconResult:
        target = target.strip()
        validated_ports = self._validate_ports(ports)
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            self.audit.log(
                target,
                "recon",
                "nmap",
                "blocked",
                {"reason": "target_must_be_loopback_ip"},
            )
            raise ReconError(
                "Only literal IPv4/IPv6 loopback addresses are allowed"
            ) from exc
        if not address.is_loopback:
            self.audit.log(
                target,
                "recon",
                "nmap",
                "blocked",
                {"reason": "target_not_loopback"},
            )
            raise ReconError(
                "Only literal IPv4/IPv6 loopback addresses are allowed"
            )

        scope_labels: list[str] = []
        try:
            for port in validated_ports:
                entry = self.scope.check(target, "recon", port=port)
                if entry.label not in scope_labels:
                    scope_labels.append(entry.label)
        except UnauthorizedTargetError as exc:
            self.audit.log(
                target, "recon", "nmap", "blocked", {"reason": str(exc)}
            )
            raise

        self.audit.log(
            target,
            "recon",
            "nmap",
            "started",
            {"ports": list(validated_ports), "scope_entries": scope_labels},
            scope_entry=scope_labels[0] if scope_labels else None,
        )
        escalations: list[dict[str, Any]] = []
        try:
            scanner = self._get_scanner()
            scan_response = scanner.scan(
                hosts=target,
                arguments=f"-sT -Pn -sV -T3 -p {','.join(map(str, validated_ports))}",
                timeout=NMAP_TIMEOUT_SECONDS,
            )
            results = self._parse_results(target, scanner, validated_ports)
            results.scanned_ports = self._parse_scanned_ports(
                scan_response, validated_ports
            )
            if results.scanned_ports != list(validated_ports):
                raise ReconExecutionError(
                    "Nmap did not confirm that all requested ports were scanned"
                )

            # Bounded scan-reliability ladder for any "filtered" ports
            for item in results.port_results:
                if item.state == "filtered":
                    escalation = self._run_reliability_ladder(target, item)
                    escalations.append(escalation)
            results.escalations = escalations
            results.open_ports = [
                port
                for port in results.port_results
                if port.state == "open" or port.state.startswith("open")
            ]
            results.raw_summary = f"{len(results.open_ports)} open port(s)"
        except Exception as exc:
            self.audit.log(
                target,
                "recon",
                "nmap",
                "failed",
                {"error_type": type(exc).__name__},
                scope_entry=scope_labels[0] if scope_labels else None,
            )
            if isinstance(exc, ReconError):
                raise
            raise ReconExecutionError(
                f"Nmap scan failed: {type(exc).__name__}"
            ) from exc

        success_details: dict[str, Any] = {
            "ports_scanned": len(validated_ports),
            "open_ports": len(results.open_ports),
            "port_results": [
                port.model_dump() for port in results.port_results
            ],
            "open_port_details": [
                port.model_dump() for port in results.open_ports
            ],
            "scope_entries": scope_labels,
        }
        if escalations:
            success_details["escalations"] = escalations
        self.audit.log(
            target,
            "recon",
            "nmap",
            "success",
            success_details,
            scope_entry=scope_labels[0] if scope_labels else None,
        )
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description="loopback service port inventory",
                    approach="nmap version detection on explicitly scoped ports",
                    outcome="success",
                    module="recon",
                    details=f"ports_scanned={len(validated_ports)}; open={len(results.open_ports)}",
                )
            )
        return results

    def _get_scanner(self):
        if self.scanner is not None:
            return self.scanner
        try:
            import nmap
        except ImportError as exc:
            raise ReconDependencyError(
                "Recon requires the optional dependency `python-nmap`; "
                'install with `pip install -e ".[recon]"`.'
            ) from exc
        try:
            self.scanner = nmap.PortScanner()
        except (nmap.PortScannerError, OSError) as exc:
            raise ReconDependencyError(
                "Nmap executable is unavailable or could not be initialized."
            ) from exc
        return self.scanner

    def _scan_port_technique(
        self, target: str, port: int, arguments: str
    ) -> tuple[str, str | None, str | None]:
        self.scope.check(target, "recon", port=port)
        scanner = self._get_scanner()
        try:
            scanner.scan(
                hosts=target,
                arguments=f"{arguments} -p {port}",
                timeout=NMAP_TIMEOUT_SECONDS,
            )
            if target in scanner.all_hosts():
                host = scanner[target]
                for protocol in host.all_protocols():
                    if port in host[protocol]:
                        data = host[protocol][port]
                        st = str(data.get("state", "unknown"))
                        srv = _optional_text(data.get("name"))
                        ver = _optional_text(data.get("version"))
                        return st, srv, ver
        except Exception:
            pass
        return "filtered", None, None

    def _raw_socket_check(
        self, target: str, port: int
    ) -> tuple[str, str | None, str | None]:
        self.scope.check(target, "recon", port=port)
        if self.raw_socket_fn is not None:
            res = self.raw_socket_fn(target, port)
            if isinstance(res, tuple):
                return res
            return str(res), None, None
        try:
            with socket.create_connection((target, port), timeout=1.0):
                return "open", None, None
        except (ConnectionRefusedError, ConnectionResetError):
            return "closed", None, None
        except (socket.timeout, TimeoutError, OSError):
            return "filtered", None, None

    def _run_reliability_ladder(
        self, target: str, port_item: PortResult
    ) -> dict[str, Any]:
        port = port_item.port
        self.scope.check(target, "recon", port=port)
        start_ts = datetime.now(timezone.utc).isoformat()
        ladder_start = time.perf_counter()

        attempts: list[dict[str, Any]] = [
            {
                "technique": "-sT default",
                "state": "filtered",
                "timestamp": start_ts,
            }
        ]

        ladder_techniques = [
            ("-Pn", lambda: self._scan_port_technique(target, port, "-sT -Pn -sV -T3")),
            (
                "--disable-arp-ping",
                lambda: self._scan_port_technique(
                    target, port, "-sT -Pn --disable-arp-ping -sV -T3"
                ),
            ),
            (
                "-sT with explicit --source-port",
                lambda: self._scan_port_technique(
                    target, port, "-sT -Pn --source-port 53 -sV -T3"
                ),
            ),
            (
                "raw_socket_crosscheck",
                lambda: self._raw_socket_check(target, port),
            ),
        ]

        final_state = "filtered"
        final_source = "-sT default"
        confidence = "inconclusive"
        prev_state: str | None = None
        raw_socket_state: str | None = None

        for tech_name, tech_fn in ladder_techniques[:4]:
            self.scope.check(target, "recon", port=port)
            attempt_t0 = time.perf_counter()
            state, srv, ver = tech_fn()
            attempt_duration = round(time.perf_counter() - attempt_t0, 4)
            attempts.append({
                "technique": tech_name,
                "state": state,
                "duration_s": attempt_duration,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            if srv and not port_item.service:
                port_item.service = srv
            if ver and not port_item.version:
                port_item.version = ver

            if tech_name == "raw_socket_crosscheck":
                raw_socket_state = state

            # Stop immediately once two consecutive techniques agree on the same state.
            if (
                prev_state is not None
                and state == prev_state
                and state in ("open", "closed")
            ):
                final_state = state
                final_source = tech_name
                confidence = f"confirmed-agreement ({tech_name})"
                break

            prev_state = state

        if raw_socket_state == "open":
            nmap_states = [
                a["state"]
                for a in attempts
                if a["technique"] != "raw_socket_crosscheck"
            ]
            if all(s == "filtered" for s in nmap_states) or final_state != "open":
                final_state = "open"
                final_source = "raw_socket_crosscheck"
                confidence = "cross-checked, Nmap environment-limited"
                port_item.state = "open (nmap-unreliable-on-this-host)"
            else:
                port_item.state = final_state
        elif final_state in ("open", "closed"):
            port_item.state = final_state
        elif raw_socket_state == "closed":
            final_state = "closed"
            final_source = "raw_socket_crosscheck"
            confidence = "cross-checked, port closed"
            port_item.state = "closed"
        else:
            final_state = "filtered"
            final_source = attempts[-1]["technique"]
            confidence = "confirmed-filtered"
            port_item.state = "filtered"

        total_duration = round(time.perf_counter() - ladder_start, 4)
        escalation_record = {
            "port": port,
            "attempts": attempts,
            "final_state": final_state,
            "final_source": final_source,
            "confidence": confidence,
            "started_at": start_ts,
            "total_duration_s": total_duration,
        }
        port_item.confidence = confidence
        port_item.escalation = escalation_record
        return escalation_record

    @staticmethod
    def _validate_ports(ports: tuple[int, ...] | list[int]) -> tuple[int, ...]:
        if not isinstance(ports, (tuple, list)) or not ports:
            raise ValueError("At least one explicit port is required")
        if len(ports) > MAX_PORTS:
            raise ValueError(f"At most {MAX_PORTS} ports may be scanned per run")
        validated: list[int] = []
        for port in ports:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
                raise ValueError("Ports must be integers between 1 and 65535")
            if port in validated:
                raise ValueError("Duplicate ports are not allowed")
            validated.append(port)
        return tuple(validated)

    def _parse_results(
        self,
        target: str,
        scanner: Any,
        requested_ports: tuple[int, ...],
    ) -> ReconResult:
        port_results: list[PortResult] = []
        if target in scanner.all_hosts():
            host = scanner[target]
            for protocol in host.all_protocols():
                for port, data in host[protocol].items():
                    port_number = int(port)
                    if port_number not in requested_ports:
                        continue
                    port_results.append(
                        PortResult(
                            port=port_number,
                            protocol=str(protocol),
                            state=str(data.get("state", "unknown")),
                            service=_optional_text(data.get("name")),
                            version=_optional_text(data.get("version")),
                        )
                    )
        port_results.sort(key=lambda item: (item.protocol, item.port))
        open_ports = [result for result in port_results if result.state == "open"]
        return ReconResult(
            target=target,
            source="nmap",
            port_results=port_results,
            open_ports=open_ports,
            scanned_ports=list(requested_ports),
            raw_summary=f"{len(open_ports)} open port(s)",
        )

    @staticmethod
    def _parse_scanned_ports(
        response: Any, requested_ports: tuple[int, ...]
    ) -> list[int]:
        if not isinstance(response, dict):
            return []
        nmap_result = response.get("nmap")
        if isinstance(nmap_result, dict):
            response = nmap_result
        scaninfo = response.get("scaninfo")
        if not isinstance(scaninfo, dict):
            return []
        scanned: set[int] = set()
        for protocol_info in scaninfo.values():
            if not isinstance(protocol_info, dict):
                continue
            services = protocol_info.get("services")
            if not isinstance(services, str):
                continue
            for part in services.split(","):
                lower, separator, upper = part.partition("-")
                try:
                    first = int(lower)
                    last = int(upper) if separator else first
                except ValueError:
                    continue
                if 1 <= first <= last <= 65_535:
                    scanned.update(range(first, last + 1))
        return [port for port in requested_ports if port in scanned]

    def profile_target(
        self,
        target: str,
        ports: tuple[int, ...] | list[int] = DEFAULT_PORTS,
    ) -> ReconProfile:
        cleaned_target = target.strip()
        validated_ports = self._validate_ports(ports)
        if not cleaned_target:
            raise ValueError("Target must not be empty")
        try:
            address = ipaddress.ip_address(cleaned_target)
        except ValueError as exc:
            self.audit.log(
                cleaned_target,
                "recon_profile",
                "recon",
                "blocked",
                {"reason": "target_must_be_loopback_ip"},
            )
            raise ReconError(
                "Profile scanning is restricted to literal loopback IP addresses"
            ) from exc
        if not address.is_loopback:
            self.audit.log(
                cleaned_target,
                "recon_profile",
                "recon",
                "blocked",
                {"reason": "target_not_loopback"},
            )
            raise ReconError(
                "Profile scanning is restricted to literal loopback IP addresses"
            )

        try:
            authorized_ports = [
                port
                for port in validated_ports
                if self.scope.check(cleaned_target, "recon", port=port)
            ]
        except UnauthorizedTargetError as exc:
            self.audit.log(
                cleaned_target,
                "recon_profile",
                "recon",
                "blocked",
                {
                    "reason": str(exc),
                    "requested_ports": list(validated_ports),
                },
            )
            raise

        self.audit.log(
            cleaned_target,
            "recon_profile",
            "recon",
            "started",
            {
                "requested_ports": list(validated_ports),
                "authorized_ports": authorized_ports,
            },
        )
        try:
            scan = self.quick_scan(cleaned_target, validated_ports)
        except Exception as exc:
            self.audit.log(
                cleaned_target,
                "recon_profile",
                "recon",
                "failed",
                {
                    "requested_ports": list(validated_ports),
                    "authorized_ports": authorized_ports,
                    "scanned_ports": [],
                    "error_type": type(exc).__name__,
                },
            )
            raise
        self.audit.log(
            cleaned_target,
            "recon_profile",
            "recon",
            "success",
            {
                "requested_ports": list(validated_ports),
                "authorized_ports": authorized_ports,
                "scanned_ports": scan.scanned_ports,
                "open_ports": [
                    result.model_dump(mode="json") for result in scan.open_ports
                ],
                "port_results": [
                    result.model_dump(mode="json") for result in scan.port_results
                ],
                "scan_source": scan.source,
            },
        )
        return ReconProfile(
            target=cleaned_target,
            requested_ports=list(validated_ports),
            authorized_ports=authorized_ports,
            scanned_ports=scan.scanned_ports,
            port_results=scan.port_results,
            open_ports=scan.open_ports,
            scan_source=scan.source,
        )


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:200] or None
