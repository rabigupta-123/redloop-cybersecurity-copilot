"""Universal Finding Normalization & Data Models (Phase 4.1 Hardened).

Provides canonical, deduplicated, and evidence-grounded security finding models
across all registered tools (Nmap, Nikto, Nuclei, TLS, HTTP, DNS, OSINT).

Verification states:
- OBSERVED: Directly recorded from at least one tool execution without corroboration.
- CORROBORATED: Observed independently by two or more distinct tools/methods.
- VALIDATED: Authenticated package changelog or deterministic exploit proof confirmed.
- CONTRADICTED: Disproved by contradictory evidence or verified vendor backport patch.
- UNVERIFIED: Inconclusive or missing evidence required for confirmation.
- NOT_ASSESSED: Finding scope not evaluated by authorized assessment run.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    OPEN_PORT = "open_port"
    SERVICE = "service"
    MISCONFIGURATION = "misconfiguration"
    TLS_ISSUE = "tls_issue"
    HEADER_MISSING = "header_missing"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    OSINT_INDICATOR = "osint_indicator"
    INFO_DISCLOSURE = "info_disclosure"


class VerificationStatus(str, Enum):
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    VALIDATED = "VALIDATED"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIED = "UNVERIFIED"
    NOT_ASSESSED = "NOT_ASSESSED"

    # Backward compatibility aliases
    SUPPORTED = "OBSERVED"
    CONFIRMED = "VALIDATED"
    FALSE_POSITIVE = "CONTRADICTED"
    UNABLE_TO_VERIFY = "UNVERIFIED"


class OperationalPriority(str, Enum):
    P1_CRITICAL_IMMEDIATE = "P1_CRITICAL_IMMEDIATE"
    P2_HIGH_URGENT = "P2_HIGH_URGENT"
    P3_MEDIUM_SCHEDULED = "P3_MEDIUM_SCHEDULED"
    P4_LOW_BACKLOG = "P4_LOW_BACKLOG"
    P5_INFORMATIONAL = "P5_INFORMATIONAL"


# =========================================================================
# Canonical Normalization Utilities
# =========================================================================

def normalize_target(target: str) -> tuple[str, str]:
    """Normalizes an IP address, domain, or host string into canonical form.
    
    Returns:
        (canonical_target, target_type) where target_type is 'ip', 'cidr', or 'domain'.
    """
    if not target:
        return "unknown", "domain"
    
    # Strip URL schemes, whitespace, and path components
    cleaned = re.sub(r"^[a-zA-Z]+://", "", target.strip())
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    
    # Strip port suffix if present (e.g. "127.0.0.1:8080" -> "127.0.0.1")
    if ":" in cleaned and not cleaned.startswith("["):
        # Check if IPv6 or host:port
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]
            
    # Check IPv4 / IPv6
    try:
        ip = ipaddress.ip_address(cleaned)
        return str(ip), "ip"
    except ValueError:
        pass
        
    # Check CIDR
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        return str(net), "cidr"
    except ValueError:
        pass
        
    # Canonical domain (lowercase)
    return cleaned.lower(), "domain"


def normalize_protocol(protocol: str | None) -> str:
    """Normalizes transport protocols to lowercase canonical names."""
    if not protocol:
        return "tcp"
    proto = protocol.strip().lower()
    if proto in ("tcp", "udp", "icmp", "http", "https"):
        return proto
    return proto


def normalize_port(port: int | str | None) -> int | None:
    """Validates and normalizes network port numbers in range 1-65535."""
    if port is None:
        return None
    try:
        p = int(port)
        if 1 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return None


def normalize_cve_id(cve: str) -> str | None:
    """Validates and canonicalizes CVE identifiers to standard CVE-YYYY-NNNN format."""
    if not cve:
        return None
    cleaned = cve.strip().upper()
    if re.match(r"^CVE-\d{4}-\d{4,}$", cleaned):
        return cleaned
    return None


def normalize_component(component: str | None) -> str:
    """Standardizes software/component identifiers to lowercase normalized strings."""
    if not component:
        return "unknown"
    cleaned = component.strip().lower()
    cleaned = re.sub(r"[\s_]+", "-", cleaned)
    return cleaned or "unknown"


# =========================================================================
# Finding & Remediation Models
# =========================================================================

@dataclass
class FindingRemediation:
    summary: str = ""
    immediate_containment: str = ""
    permanent_fix: str = ""
    configuration_snippet: str | None = None
    config_example: str | None = None
    validation_steps: str = ""
    rollback_plan: str = ""
    regression_tests: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FalsePositiveAnalysis:
    likelihood: float = 0.0  # 0.0 (genuine) to 1.0 (definite false positive)
    is_false_positive: bool = False
    confidence_basis: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    recommended_action: str = ""
    limitations: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    task_id: str
    target: str
    target_type: str  # "ip", "domain", "cidr", "host"
    finding_type: FindingType
    title: str
    description: str
    severity: FindingSeverity
    step_id: str | None = None
    asset_id: str = ""
    cvss_version: str = "3.1"
    cvss_vector: str | None = None
    cvss_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected_component: str = "unknown"
    affected_version: str | None = None
    port: int | None = None
    protocol: str | None = None
    endpoint: str | None = None
    raw_evidence_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    source_tool: str = "redloop"
    source_tool_version: str | None = None
    first_seen: str = ""
    last_seen: str = ""
    verification_status: VerificationStatus = VerificationStatus.OBSERVED
    confidence: float = 0.8
    operational_priority: OperationalPriority = OperationalPriority.P3_MEDIUM_SCHEDULED
    risk_score: float | None = None
    cisa_kev: bool = False
    epss_score: float | None = None
    false_positive_status: FalsePositiveAnalysis = field(default_factory=FalsePositiveAnalysis)
    remediation: FindingRemediation | None = None
    references: list[str] = field(default_factory=list)
    intelligence_tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.first_seen:
            self.first_seen = datetime.now(timezone.utc).isoformat()
        if not self.last_seen:
            self.last_seen = self.first_seen
            
        # Target canonical normalization
        norm_tgt, norm_type = normalize_target(self.target)
        self.target = norm_tgt
        if not self.target_type or self.target_type == "host":
            self.target_type = norm_type
        if not self.asset_id:
            self.asset_id = f"asset:{self.target_type}:{self.target}"
            
        # Protocol and port normalization
        self.port = normalize_port(self.port)
        self.protocol = normalize_protocol(self.protocol)
        self.affected_component = normalize_component(self.affected_component)
        
        # Link raw_evidence_id into evidence_ids list
        if self.raw_evidence_id and self.raw_evidence_id not in self.evidence_ids:
            self.evidence_ids.append(self.raw_evidence_id)
        elif self.evidence_ids and not self.raw_evidence_id:
            self.raw_evidence_id = self.evidence_ids[0]

    @property
    def fingerprint(self) -> str:
        """Deterministic canonical signature used for truthful deduplication.
        
        Avoids relying on mutable natural-language finding titles.
        Binds normalized target, port, protocol, component, endpoint, finding_type,
        and sorted canonical CVE/CWE identifiers.
        """
        norm_tgt, _ = normalize_target(self.target)
        norm_port = str(self.port or 0)
        norm_proto = normalize_protocol(self.protocol)
        norm_type = self.finding_type.value if hasattr(self.finding_type, "value") else str(self.finding_type).lower()
        norm_comp = normalize_component(self.affected_component)
        norm_endpoint = (self.endpoint or "").strip().lower()
        
        cves = [normalize_cve_id(c) for c in self.cve_ids if normalize_cve_id(c)]
        cve_str = ",".join(sorted(set(cves)))
        cwes = [c.strip().upper() for c in self.cwe_ids if c]
        cwe_str = ",".join(sorted(set(cwes)))
        
        # Identity is anchored on target asset, port, protocol, component, type, and specific vulnerability identifiers
        raw = f"{norm_tgt}|{norm_port}|{norm_proto}|{norm_type}|{norm_comp}|{norm_endpoint}|{cve_str}|{cwe_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "task_id": self.task_id,
            "step_id": self.step_id,
            "asset_id": self.asset_id,
            "target": self.target,
            "target_type": self.target_type,
            "finding_type": self.finding_type.value if isinstance(self.finding_type, FindingType) else str(self.finding_type),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else str(self.severity),
            "operational_priority": self.operational_priority.value if isinstance(self.operational_priority, OperationalPriority) else str(self.operational_priority),
            "risk_score": round(self.risk_score, 1) if self.risk_score is not None else None,
            "cisa_kev": self.cisa_kev,
            "epss_score": round(self.epss_score, 4) if self.epss_score is not None else None,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "cvss_score": round(self.cvss_score, 1),
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "affected_component": self.affected_component,
            "affected_version": self.affected_version,
            "port": self.port,
            "protocol": self.protocol,
            "endpoint": self.endpoint,
            "raw_evidence_id": self.raw_evidence_id,
            "evidence_ids": self.evidence_ids,
            "source_tool": self.source_tool,
            "source_tool_version": self.source_tool_version,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "verification_status": self.verification_status.value if isinstance(self.verification_status, VerificationStatus) else str(self.verification_status),
            "confidence": round(self.confidence, 2),
            "false_positive_status": self.false_positive_status.to_dict() if hasattr(self.false_positive_status, "to_dict") else self.false_positive_status,
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "references": self.references,
            "intelligence_tags": self.intelligence_tags,
            "metadata": self.metadata,
        }


# =========================================================================
# Finding Normalizer & Deduplicator
# =========================================================================

class FindingNormalizer:
    """Universal parser and normalizer transforming raw tool telemetry into canonical Findings."""

    @classmethod
    def normalize_nmap(cls, raw_stdout: str, target: str, task_id: str, evidence_id: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        now_ts = datetime.now(timezone.utc).isoformat()
        canonical_target, target_type = normalize_target(target)

        # Regex for standard nmap port line: e.g. "80/tcp open http Apache httpd 2.4.52"
        port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-]+)(?:\s+(.*))?$", re.MULTILINE)
        for m in port_pattern.finditer(raw_stdout):
            port = int(m.group(1))
            proto = m.group(2).lower()
            state = m.group(3)
            service = m.group(4)
            version_info = (m.group(5) or "").strip()

            if state.lower() == "open":
                title = f"Open Port {port}/{proto} ({service})"
                desc = f"Service '{service}' detected listening on {canonical_target}:{port}/{proto}."
                if version_info:
                    desc += f" Version banner: {version_info}."

                ev_list = [evidence_id] if evidence_id else []
                f = Finding(
                    finding_id=f"fnd-nmap-{uuid.uuid4().hex[:8]}",
                    task_id=task_id,
                    target=canonical_target,
                    target_type=target_type,
                    finding_type=FindingType.OPEN_PORT,
                    title=title,
                    description=desc,
                    severity=FindingSeverity.LOW if port in (80, 443) else FindingSeverity.MEDIUM,
                    cvss_score=3.7 if port not in (80, 443) else 2.1,
                    port=port,
                    protocol=proto,
                    affected_component=service,
                    affected_version=version_info or None,
                    source_tool="nmap",
                    raw_evidence_id=evidence_id,
                    evidence_ids=ev_list,
                    verification_status=VerificationStatus.OBSERVED,
                    first_seen=now_ts,
                    last_seen=now_ts,
                    remediation=FindingRemediation(
                        summary=f"Evaluate exposure of {service} on port {port}.",
                        immediate_containment=f"Restrict port {port} via firewall or bind to loopback if internal only.",
                        permanent_fix="Disable unused service or enforce mutual TLS/VPN access controls.",
                        validation_steps=f"nmap -p {port} -sV {canonical_target}",
                        rollback_plan="Re-enable service listener or restore previous firewall rule.",
                    ),
                )
                findings.append(f)

        return findings

    @classmethod
    def normalize_http_headers(cls, raw_headers: str, target: str, task_id: str, evidence_id: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        now_ts = datetime.now(timezone.utc).isoformat()
        canonical_target, target_type = normalize_target(target)
        lower_headers = raw_headers.lower()
        ev_list = [evidence_id] if evidence_id else []

        required_sec_headers = [
            ("strict-transport-security", "Missing HTTP Strict Transport Security (HSTS)", FindingSeverity.MEDIUM, 4.3, "CWE-319",
             "HSTS prevents man-in-the-middle protocol downgrade attacks by enforcing TLS communication."),
            ("content-security-policy", "Missing Content Security Policy (CSP)", FindingSeverity.MEDIUM, 4.7, "CWE-79",
             "CSP restricts sources of executable scripts, mitigating Cross-Site Scripting (XSS) and data injection."),
            ("x-content-type-options", "Missing X-Content-Type-Options Header", FindingSeverity.LOW, 2.6, "CWE-16",
             "Ensures browsers respect declared MIME types, preventing MIME-sniffing drive-by downloads."),
            ("x-frame-options", "Missing Anti-Clickjacking Header (X-Frame-Options)", FindingSeverity.LOW, 3.1, "CWE-1021",
             "Prevents framing of web application UI inside malicious third-party iframes."),
        ]

        for hdr, title, sev, score, cwe, why in required_sec_headers:
            if hdr not in lower_headers:
                findings.append(
                    Finding(
                        finding_id=f"fnd-hdr-{uuid.uuid4().hex[:8]}",
                        task_id=task_id,
                        target=canonical_target,
                        target_type=target_type,
                        finding_type=FindingType.HEADER_MISSING,
                        title=title,
                        description=f"Web server on {canonical_target} does not return the security header '{hdr}'. {why}",
                        severity=sev,
                        cvss_score=score,
                        cwe_ids=[cwe],
                        affected_component="http-server",
                        port=443 if "https" in target else 80,
                        protocol="tcp",
                        source_tool="curl",
                        raw_evidence_id=evidence_id,
                        evidence_ids=ev_list.copy(),
                        verification_status=VerificationStatus.OBSERVED,
                        first_seen=now_ts,
                        last_seen=now_ts,
                        remediation=FindingRemediation(
                            summary=f"Configure '{hdr}' in web server response headers.",
                            immediate_containment=f"Add `{hdr}` header directive in reverse proxy or edge load balancer.",
                            permanent_fix=f"Enforce `{hdr}` across all production virtual hosts and API gateways.",
                            configuration_snippet=f"Header always set {hdr} 'default-src https:'" if hdr == "content-security-policy" else f"Header always set {hdr} 'max-age=31536000; includeSubDomains'",
                            validation_steps=f"curl -sI https://{canonical_target}/ | grep -i '{hdr}'",
                            rollback_plan=f"Remove `{hdr}` header directive from proxy configuration.",
                        ),
                    )
                )

        # Detect exposed server banner e.g. Server: Apache/2.4.52 (Ubuntu)
        server_match = re.search(r"server:\s*([^\r\n]+)", raw_headers, re.IGNORECASE)
        if server_match:
            srv = server_match.group(1).strip()
            if any(ch in srv for ch in ("/", ".", " ")):
                comp = srv.split("/")[0].strip().lower()
                ver = srv.split("/")[1].strip() if "/" in srv else None
                findings.append(
                    Finding(
                        finding_id=f"fnd-banner-{uuid.uuid4().hex[:8]}",
                        task_id=task_id,
                        target=canonical_target,
                        target_type=target_type,
                        finding_type=FindingType.INFO_DISCLOSURE,
                        title=f"Detailed Web Server Banner Disclosed ({srv})",
                        description=f"Server returned version identification '{srv}'. Disclosing software versions simplifies targeted reconnaissance.",
                        severity=FindingSeverity.LOW,
                        cvss_score=2.6,
                        cwe_ids=["CWE-200"],
                        affected_component=comp,
                        affected_version=ver,
                        port=443 if "https" in target else 80,
                        protocol="tcp",
                        source_tool="curl",
                        raw_evidence_id=evidence_id,
                        evidence_ids=ev_list.copy(),
                        verification_status=VerificationStatus.OBSERVED,
                        first_seen=now_ts,
                        last_seen=now_ts,
                        remediation=FindingRemediation(
                            summary="Suppress detailed server version disclosure tokens.",
                            immediate_containment="Configure ServerTokens Prod and ServerSignature Off in Apache, or server_tokens off in Nginx.",
                            permanent_fix="Sanitize edge response headers to omit operating system and patch level banners.",
                            configuration_snippet="ServerTokens Prod\nServerSignature Off",
                            validation_steps=f"curl -sI http://{canonical_target}/ | grep -i 'Server:'",
                            rollback_plan="Revert ServerTokens setting to Full.",
                        ),
                    )
                )

        return findings

    @classmethod
    def deduplicate(cls, findings: list[Finding]) -> list[Finding]:
        """Truthful deduplication based on stable deterministic finding fingerprints.
        
        - Preserves all independent evidence references.
        - Preserves earliest first_seen timestamp and advances last_seen.
        - Distinguishes duplicate observations by same tool from independent corroboration.
        - Promotes to CORROBORATED when 2+ distinct tools independently report the finding.
        - NEVER elevates to VALIDATED merely from multi-tool observations.
        """
        seen: dict[str, Finding] = {}
        tool_sources: dict[str, set[str]] = {}

        for f in findings:
            fp = f.fingerprint
            if fp not in seen:
                seen[fp] = f
                tool_sources[fp] = {f.source_tool}
            else:
                existing = seen[fp]
                existing.last_seen = f.last_seen
                tool_sources[fp].add(f.source_tool)

                # Merge independent evidence references
                for ev in f.evidence_ids:
                    if ev and ev not in existing.evidence_ids:
                        existing.evidence_ids.append(ev)
                if f.raw_evidence_id and f.raw_evidence_id not in existing.evidence_ids:
                    existing.evidence_ids.append(f.raw_evidence_id)

                # Track legacy metadata corroborating_evidences
                if not existing.metadata.get("corroborating_evidences"):
                    existing.metadata["corroborating_evidences"] = []
                for ev in existing.evidence_ids:
                    if ev not in existing.metadata["corroborating_evidences"]:
                        existing.metadata["corroborating_evidences"].append(ev)

                # Distinct independent corroboration (2+ distinct tools)
                if len(tool_sources[fp]) >= 2:
                    existing.verification_status = VerificationStatus.CORROBORATED
                    existing.confidence = min(0.95, max(existing.confidence, 0.85) + 0.1)

        return list(seen.values())


# =========================================================================
# Finding Store (In-Memory Thread-Safe Repository)
# =========================================================================

class FindingStore:
    """Thread-safe in-memory and searchable store for normalized findings."""

    _instance: FindingStore | None = None

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}

    @classmethod
    def get_instance(cls) -> FindingStore:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def add_finding(self, finding: Finding) -> None:
        self._findings[finding.finding_id] = finding

    def add_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add_finding(f)

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def list_findings(
        self,
        task_id: str | None = None,
        target: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        verification: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Finding]:
        results = list(self._findings.values())
        if task_id:
            results = [f for f in results if f.task_id == task_id]
        if target:
            norm_tgt, _ = normalize_target(target)
            results = [f for f in results if f.target == norm_tgt or f.target == target]
        if severity:
            results = [f for f in results if f.severity.value.upper() == severity.upper()]
        if priority:
            results = [f for f in results if f.operational_priority.value.upper() == priority.upper()]
        if verification:
            results = [f for f in results if f.verification_status.value.upper() == verification.upper()]
            
        # Stable sort: highest risk score first, then earliest first_seen
        results.sort(key=lambda x: (-(x.risk_score or 0.0), x.first_seen or ""))
        
        # Apply pagination
        if offset > 0:
            results = results[offset:]
        if limit > 0:
            results = results[:limit]
            
        return results

    def clear(self) -> None:
        self._findings.clear()
