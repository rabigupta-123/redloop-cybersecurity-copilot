"""REDLOOP Shodan OSINT & Threat Intelligence Engine.

Integrates with Shodan's REST API using the user's verified API key to perform:
- Passive host reconnaissance (open ports, banners, services, ISP, ASN, OS)
- Vulnerability & CVE discovery from global banner telemetry
- DNS & domain host resolution
- Passive attack surface discovery mapped to REDLOOP Findings and Evidence
- Cryptographically chained audit logging under module="shodan"
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from redloop.transport import get_hardened_client
from pydantic import BaseModel, Field

from redloop.assessment.models import (
    AttackSurfaceGraph,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger


class ShodanHostData(BaseModel):
    ip: str
    hostnames: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    os: str | None = None
    org: str | None = None
    asn: str | None = None
    country_name: str | None = None
    city: str | None = None
    vulns: list[str] = Field(default_factory=list)
    banners: list[dict[str, Any]] = Field(default_factory=list)


class ShodanEngine:
    """Enterprise Shodan threat intelligence & OSINT engine."""

    BASE_URL = "https://api.shodan.io"

    def __init__(
        self,
        audit: AuditLogger,
        scope_guard: AssessmentScopeGuard | None = None,
        api_key: str | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "").strip()

    def is_configured(self) -> bool:
        """Return True if a non-empty Shodan API key is available."""
        return bool(self.api_key and not self.api_key.startswith("***"))

    def check_api_info(self) -> dict[str, Any]:
        """Verify API key status and return plan/credits information."""
        if not self.is_configured():
            return {"configured": False, "error": "SHODAN_API_KEY is not set."}
        try:
            with get_hardened_client(timeout=8.0) as client:
                resp = client.get(f"{self.BASE_URL}/api-info?key={self.api_key}")
                if resp.status_code == 200:
                    data = resp.json()
                    data["configured"] = True
                    return data
                return {
                    "configured": False,
                    "error": f"Shodan API returned HTTP {resp.status_code}: {resp.text}",
                }
        except Exception as exc:
            return {"configured": False, "error": f"Failed to connect to Shodan API: {exc}"}

    def query_host(self, target_ip: str) -> dict[str, Any]:
        """Perform passive reconnaissance on target IP via Shodan."""
        if not self.is_configured():
            return {
                "success": False,
                "error": "Shodan API key is not configured. Set SHODAN_API_KEY in environment or settings.",
            }

        # Authoritative Scope Verification before OSINT query
        if self.scope_guard:
            try:
                self.scope_guard.is_target_authorized(target_ip, "recon")
            except Exception as exc:
                return {"success": False, "error": f"Scope authorization rejected for Shodan OSINT: {exc}"}

        # For loopback, Shodan has no public scan records. Return truthful zero-port intelligence
        is_loopback = target_ip in ("127.0.0.1", "::1", "localhost")

        t0 = time.monotonic()
        try:
            if is_loopback:
                # Loopback has no external Shodan index. Provide a truthful advisory result without fabricated ports.
                result_data = {
                    "ip": target_ip,
                    "hostnames": ["localhost"],
                    "ports": [],
                    "os": "Local Environment",
                    "org": "Loopback Security Boundary",
                    "asn": None,
                    "country_name": None,
                    "city": None,
                    "vulns": [],
                    "banners": [],
                    "notice": "Target is a loopback/private interface. Public internet scanners do not index private loopback addresses.",
                }
            else:
                with get_hardened_client(timeout=12.0) as client:
                    resp = client.get(f"{self.BASE_URL}/shodan/host/{target_ip}?key={self.api_key}")
                    if resp.status_code == 200:
                        raw = resp.json()
                        result_data = {
                            "ip": raw.get("ip_str", target_ip),
                            "hostnames": raw.get("hostnames", []),
                            "ports": raw.get("ports", []),
                            "os": raw.get("os"),
                            "org": raw.get("org"),
                            "asn": raw.get("asn"),
                            "country_name": raw.get("country_name"),
                            "city": raw.get("city"),
                            "vulns": list(raw.get("vulns", [])),
                            "banners": [
                                {
                                    "port": b.get("port"),
                                    "transport": b.get("transport"),
                                    "product": b.get("product"),
                                    "version": b.get("version"),
                                    "banner": b.get("data", "")[:200],
                                }
                                for b in raw.get("data", [])[:10]
                            ],
                        }
                    elif resp.status_code == 404:
                        result_data = {
                            "ip": target_ip,
                            "hostnames": [],
                            "ports": [],
                            "vulns": [],
                            "banners": [],
                            "notice": f"Target {target_ip} not found in Shodan's global scan index (no public exposure detected).",
                        }
                    else:
                        raise ValueError(f"Shodan API error {resp.status_code}: {resp.text[:200]}")

            # Audit logging
            self.audit.log(
                target=target_ip,
                action="osint_query",
                module="shodan",
                status="success",
                details={
                    "ports_found": len(result_data.get("ports", [])),
                    "vulns_found": len(result_data.get("vulns", [])),
                    "duration_seconds": round(time.monotonic() - t0, 3),
                },
            )
            return {"success": True, "data": result_data}

        except Exception as exc:
            self.audit.log(
                target=target_ip,
                action="osint_query",
                module="shodan",
                status="failed",
                details={"error": str(exc)},
            )
            return {"success": False, "error": str(exc)}

    def assess_shodan(self, target: str, operation_id: str) -> StageResult:
        """Run Shodan OSINT assessment as a standard pipeline stage."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []

        if not self.is_configured():
            return StageResult(
                stage="osint_shodan",
                status=StageStatus.UNAVAILABLE,
                reason="Shodan API key is not configured. Set SHODAN_API_KEY to enable global threat intelligence.",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        res = self.query_host(target)
        if not res.get("success"):
            err_msg = str(res.get("error", ""))
            is_blocked = "scope" in err_msg.lower() or "authorization" in err_msg.lower()
            return StageResult(
                stage="osint_shodan",
                status=StageStatus.BLOCKED if is_blocked else StageStatus.FAILED,
                reason=f"Shodan query failed: {err_msg}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        data = res.get("data", {})
        ev_id = f"ev-shodan-{uuid.uuid4().hex[:8]}"
        raw_repr = str(data)
        ev_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

        ev = Evidence(
            id=ev_id,
            operation_id=operation_id,
            target=target,
            request_metadata={"action": "shodan_host_query", "target": target},
            response_metadata={"ports": data.get("ports", []), "vulns_count": len(data.get("vulns", []))},
            response_excerpt=f"Shodan OSINT: {len(data.get('ports', []))} open ports, {len(data.get('vulns', []))} indexed CVEs.",
            tool_output=f"SHODAN INTELLIGENCE: IP {data.get('ip')} (Org: {data.get('org', 'N/A')}, ASN: {data.get('asn', 'N/A')}). Disclosed ports: {data.get('ports', [])}",
            parser_result=data,
            sha256_hash=ev_hash,
        )
        evidence_list.append(ev)

        # Generate findings for each indexed CVE
        for cve in data.get("vulns", []):
            findings.append(
                Finding(
                    id=f"RL-SHODAN-{uuid.uuid4().hex[:6].upper()}",
                    title=f"Publicly Indexed Vulnerability ({cve})",
                    category="osint_vulnerability",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target,
                    target=target,
                    protocol="internet_facing",
                    description=f"Shodan threat intelligence detected unpatched vulnerability {cve} on publicly exposed asset {target}.",
                    evidence=[ev],
                    detection_method="shodan_threat_intelligence",
                    impact="Adversaries actively scan Shodan to locate vulnerable target infrastructure.",
                    remediation=f"Apply vendor patch for {cve} immediately or restrict public internet exposure via firewall.",
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                    cvss_score=8.5,
                    risk_score=8.5,
                )
            )

        # Generate informational finding for exposed service banners
        if data.get("ports"):
            findings.append(
                Finding(
                    id=f"RL-SHODAN-PORTS-{uuid.uuid4().hex[:6].upper()}",
                    title=f"Public Port Exposure Disclosed via Shodan ({len(data['ports'])} ports)",
                    category="attack_surface",
                    severity=Severity.MEDIUM if len(data["ports"]) > 3 else Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    asset=target,
                    target=target,
                    protocol="tcp",
                    description=f"Shodan indexes public exposure on ports {data['ports']} for {target}.",
                    evidence=[ev],
                    detection_method="shodan_banner_telemetry",
                    impact="Public port visibility facilitates automated adversary reconnaissance.",
                    remediation="Audit exposed firewall ingress rules and remove public access to non-essential services.",
                    references=["https://www.shodan.io"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                    cvss_score=5.0,
                    risk_score=5.0,
                )
            )

        return StageResult(
            stage="osint_shodan",
            status=StageStatus.SUCCESS,
            reason=f"Shodan retrieved intelligence for {target}: {len(data.get('ports', []))} ports, {len(findings)} findings.",
            duration_seconds=round(time.monotonic() - t0, 2),
            findings=findings,
            evidence=evidence_list,
            data=data,
        )
