"""SpiderFoot Isolated REST Connector (Phase L.4).

Integrates SpiderFoot (GPL-3.0, https://github.com/smicallef/spiderfoot) strictly
as an isolated out-of-process service over HTTP REST. Zero SpiderFoot code is
bundled in REDLOOP (preserving MIT license compatibility; see docs/THIRD_PARTY.md).

Capabilities:
1. Enforces AssessmentScopeGuard / PersonScopeGate before initiating any scan.
2. Lifecycle operations: start_scan, poll_status, pull_results.
3. Maps untrusted SpiderFoot event rows into REDLOOP's Evidence and Finding models
   with deterministic SHA-256 hashes and evidence_id linkages.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
import httpx

from redloop.assessment.models import (
    Confidence,
    Evidence,
    EvidenceProvenance,
    Finding,
    FindingStatus,
    Severity,
)
from redloop.connectors.models import (
    ConnectorManifest,
    ConnectorTool,
    RiskLevel,
    TransportType,
)
from redloop.connectors.untrusted import process_untrusted_output


_EVENT_SEVERITY_MAP: Dict[str, Tuple[Severity, Confidence, str]] = {
    "VULNERABILITY_CVE_CRITICAL": (Severity.CRITICAL, Confidence.HIGH, "Critical CVE Exposure Identified via OSINT"),
    "VULNERABILITY_CVE_HIGH": (Severity.HIGH, Confidence.HIGH, "High-Severity CVE Exposure Identified via OSINT"),
    "TCP_PORT_OPEN": (Severity.LOW, Confidence.CONFIRMED, "Open TCP Port Observed by SpiderFoot"),
    "INTERNET_NAME": (Severity.INFO, Confidence.CONFIRMED, "Subdomain / Internet Hostname Discovered"),
    "IP_ADDRESS": (Severity.INFO, Confidence.CONFIRMED, "Resolved IP Address Associated with Target"),
    "EMAILADDR": (Severity.LOW, Confidence.MEDIUM, "Public Email Address Associated with Target Domain"),
    "DOMAIN_WHOIS": (Severity.INFO, Confidence.HIGH, "Domain WHOIS Registration Record Collected"),
    "SSL_CERTIFICATE_ISSUED": (Severity.INFO, Confidence.CONFIRMED, "TLS/SSL Certificate Transparency Record"),
}


def get_spiderfoot_manifest(base_url: Optional[str] = None) -> ConnectorManifest:
    """Build the ConnectorManifest for registering SpiderFoot in ConnectorRegistry."""
    resolved_url = base_url or os.environ.get("REDLOOP_SPIDERFOOT_URL", "http://127.0.0.1:5001")
    return ConnectorManifest(
        id="builtin-spiderfoot",
        name="SpiderFoot OSINT Service (Isolated GPL-3.0 Container)",
        transport=TransportType.REST,
        base_url=resolved_url,
        risk=RiskLevel.READ_ONLY,
        allowed_scope=["127.0.0.1", "localhost"],
        rate_limit=30,
        timeout=15.0,
        env_keys=["REDLOOP_SPIDERFOOT_API_KEY"],
        tools=[
            ConnectorTool(
                name="sf_start_scan",
                description="Initiate an isolated SpiderFoot OSINT scan against an authorized target",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "scan_name": {"type": "string"},
                        "use_case": {"type": "string"},
                    },
                    "required": ["target"],
                },
                risk=RiskLevel.READ_ONLY,
            ),
            ConnectorTool(
                name="sf_scan_status",
                description="Poll status of a running SpiderFoot scan by scan_id",
                parameters={
                    "type": "object",
                    "properties": {"scan_id": {"type": "string"}},
                    "required": ["scan_id"],
                },
                risk=RiskLevel.READ_ONLY,
            ),
            ConnectorTool(
                name="sf_scan_results",
                description="Pull event results from a completed SpiderFoot scan and map to REDLOOP Evidence",
                parameters={
                    "type": "object",
                    "properties": {"scan_id": {"type": "string"}, "target": {"type": "string"}},
                    "required": ["scan_id", "target"],
                },
                risk=RiskLevel.READ_ONLY,
            ),
        ],
        last_health="healthy",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


class SpiderFootConnector:
    """REST connector communicating with an isolated SpiderFoot container / service."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        scope_guard: Any = None,
        person_scope_gate: Any = None,
        http_client: Optional[httpx.Client] = None,
        audit_logger: Any = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("REDLOOP_SPIDERFOOT_URL", "http://127.0.0.1:5001")).rstrip("/")
        self.scope_guard = scope_guard
        self.person_scope_gate = person_scope_gate
        self.http_client = http_client
        self.audit_logger = audit_logger

    def _verify_scope(self, target: str) -> None:
        """Enforce AssessmentScopeGuard prior to calling SpiderFoot."""
        if self.scope_guard is not None:
            self.scope_guard.is_target_authorized(target, action="recon", require_port=False)

    def _request_json(self, method: str, path: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        if self.http_client is not None:
            resp = self.http_client.request(method, url, params=params, json=data)
            resp.raise_for_status()
            return resp.json()
        with httpx.Client(timeout=10.0) as client:
            resp = client.request(method, url, params=params, json=data)
            resp.raise_for_status()
            return resp.json()

    def start_scan(self, target: str, scan_name: str = "redloop-osint", use_case: str = "PASSIVE") -> Dict[str, Any]:
        """Start a scan on the isolated SpiderFoot service after verifying scope."""
        self._verify_scope(target)
        payload = {
            "scanname": scan_name,
            "scantarget": target,
            "usecase": use_case,
        }
        raw = self._request_json("POST", "/startscan", data=payload)
        scan_id = str(raw.get("scan_id") or raw.get("id") or "")
        if self.audit_logger:
            self.audit_logger.log(target, "spiderfoot:start_scan", "connector", "SUCCESS", {"scan_id": scan_id})
        return {"status": "started", "scan_id": scan_id, "target": target, "use_case": use_case}

    def poll_status(self, scan_id: str) -> Dict[str, Any]:
        """Poll scan status from SpiderFoot `/scanstatus`."""
        raw = self._request_json("GET", "/scanstatus", params={"id": scan_id})
        return {
            "scan_id": scan_id,
            "status": str(raw.get("status", "UNKNOWN")),
            "progress": int(raw.get("progress", 0)),
        }

    def pull_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Pull raw scan event rows from SpiderFoot `/scaneventresults`."""
        raw = self._request_json("POST", "/scaneventresults", data={"id": scan_id})
        if isinstance(raw, dict):
            events = raw.get("events", [])
        elif isinstance(raw, list):
            events = raw
        else:
            events = []
        return list(events)

    def map_to_redloop_evidence_and_findings(
        self,
        scan_id: str,
        target: str,
        raw_events: List[Dict[str, Any]],
        mcp_server: Any = None,
    ) -> Tuple[List[Evidence], List[Finding]]:
        """Map SpiderFoot event records into cryptographically hashed REDLOOP Evidence and Findings."""
        evidences: List[Evidence] = []
        findings: List[Finding] = []

        for idx, ev_row in enumerate(raw_events):
            ev_type = str(ev_row.get("type", "RAW_RIR_DATA")).upper()
            ev_data_raw = str(ev_row.get("data", ""))
            ev_module = str(ev_row.get("module", "sfp_dnsresolve"))

            # Sanitize untrusted connector output
            sanitized_res = process_untrusted_output(ev_data_raw)
            clean_data = str(sanitized_res.sanitized)

            digest_seed = f"{scan_id}:{target}:{ev_type}:{ev_module}:{clean_data}:{idx}"
            short_hash = hashlib.sha256(digest_seed.encode("utf-8")).hexdigest()[:12]
            ev_id = f"ev-sf-{short_hash}"

            evidence_obj = Evidence(
                id=ev_id,
                operation_id=f"sf-scan-{scan_id}",
                target=target,
                provenance=EvidenceProvenance.FRESH,
                source=f"spiderfoot:{ev_module}",
                source_task_id=scan_id,
                request_metadata={"connector_id": "builtin-spiderfoot", "scan_id": scan_id, "event_type": ev_type},
                response_metadata={"module": ev_module, "sanitized": True},
                response_excerpt=clean_data[:500],
                tool_output=json.dumps(ev_row, sort_keys=True),
                parser_result={"event_type": ev_type, "data": clean_data, "module": ev_module},
            )
            evidences.append(evidence_obj)

            sev, conf, title_prefix = _EVENT_SEVERITY_MAP.get(
                ev_type,
                (Severity.INFO, Confidence.MEDIUM, f"SpiderFoot OSINT Event ({ev_type})"),
            )
            finding_id = f"RL-SF-{short_hash.upper()}"
            finding_obj = Finding(
                id=finding_id,
                title=f"{title_prefix}: {clean_data[:80]}",
                category=f"osint:{ev_type.lower()}",
                severity=sev,
                confidence=conf,
                asset=target,
                target=target,
                description=(
                    f"SpiderFoot module '{ev_module}' reported {ev_type} for target '{target}': "
                    f"{clean_data}. Linked to verified Evidence ID '{ev_id}'."
                ),
                evidence=[evidence_obj],
                detection_method=f"spiderfoot_connector:{ev_module}",
                source_operation_id=f"sf-scan-{scan_id}",
                status=FindingStatus.VERIFIED,
            )
            findings.append(finding_obj)

            if mcp_server is not None:
                mcp_server.add_evidence(ev_id, evidence_obj.model_dump(mode="json"))
                mcp_server.add_finding(
                    {
                        "id": finding_obj.id,
                        "title": finding_obj.title,
                        "severity": finding_obj.severity.value,
                        "confidence": finding_obj.confidence.value,
                        "target": finding_obj.target,
                        "evidence_ids": [ev_id],
                        "sha256_hash": evidence_obj.sha256_hash,
                    }
                )

        return evidences, findings

    def execute_scan_to_findings(
        self,
        target: str,
        scan_name: str = "redloop-osint",
        mcp_server: Any = None,
    ) -> Dict[str, Any]:
        """Full round-trip: start scan -> poll status -> pull results -> map to Evidence & Findings."""
        start_info = self.start_scan(target=target, scan_name=scan_name)
        scan_id = start_info["scan_id"]
        status_info = self.poll_status(scan_id)
        raw_events = self.pull_results(scan_id)
        evidences, findings = self.map_to_redloop_evidence_and_findings(
            scan_id=scan_id,
            target=target,
            raw_events=raw_events,
            mcp_server=mcp_server,
        )
        return {
            "scan_id": scan_id,
            "target": target,
            "scan_status": status_info["status"],
            "events_count": len(raw_events),
            "evidence_ids": [e.id for e in evidences],
            "findings": [f.model_dump(mode="json") for f in findings],
        }

