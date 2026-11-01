"""DNS security assessment engine.

Audits:
- Resource records: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA
- DNSSEC presence and signature indicators
- Mail security hygiene (SPF, DMARC policies)
- Dangling CNAME / subdomain takeover indicators
- Zone transfer (AXFR) test (only when explicitly authorized)
"""

from __future__ import annotations

import time
from typing import Any

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from redloop.assessment.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger


class DNSEngine:
    """Performs deep, deterministic DNS configuration and hygiene checks."""

    RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
        nameserver: str | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0
        if nameserver:
            self.resolver.nameservers = [nameserver]

    def assess_target(
        self,
        domain: str,
        test_axfr: bool = False,
        operation_id: str = "op-dns",
    ) -> StageResult:
        """Run deep DNS assessment against authorized target."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []
        records_collected: dict[str, list[str]] = {}

        # 1. Scope verification
        try:
            self.scope_guard.is_target_authorized(
                domain, "dns_check", op_class=OperationClass.READ_ONLY
            )
        except Exception as exc:
            return StageResult(
                stage="dns_assessment",
                status=StageStatus.BLOCKED,
                reason=f"Scope authorization rejected: {exc}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        # 2. Query standard records
        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records_collected[rtype] = [str(r.to_text()) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            except Exception:
                continue

        # Check DNSSEC
        has_dnssec = False
        try:
            dnskey = self.resolver.resolve(domain, "DNSKEY")
            if dnskey:
                has_dnssec = True
        except Exception:
            has_dnssec = False

        # Query DMARC at _dmarc.<domain>
        dmarc_records: list[str] = []
        try:
            dmarc_ans = self.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [str(r.to_text()).strip('"') for r in dmarc_ans]
        except Exception:
            pass

        data = {
            "domain": domain,
            "records": records_collected,
            "dnssec": has_dnssec,
            "dmarc": dmarc_records,
        }

        # 3. Create evidence artifact
        ev = Evidence(
            operation_id=operation_id,
            target=domain,
            request_metadata={"domain": domain, "queried_types": list(self.RECORD_TYPES)},
            response_metadata={"records_found": list(records_collected.keys()), "dnssec": has_dnssec},
            response_excerpt=str(data),
            tool_output=f"Resolved DNS records for {domain}: {list(records_collected.keys())}",
            parser_result=data,
        )
        evidence_list.append(ev)

        # 4. Analyze findings deterministically without inventing claims
        txt_records = records_collected.get("TXT", [])
        spf_records = [r for r in txt_records if "v=spf1" in r]

        # Check SPF presence if domain has MX (handles email) or A records
        if ("MX" in records_collected or "A" in records_collected) and not spf_records:
            findings.append(
                Finding(
                    title="Missing SPF Record (Email Spoofing Risk)",
                    category="dns_email_security",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    asset=domain,
                    target=domain,
                    protocol="dns",
                    description=f"Domain {domain} does not publish an SPF (Sender Policy Framework) TXT record.",
                    evidence=[ev],
                    detection_method="dns_txt_record_query",
                    impact="Receiving mail servers cannot cryptographically verify authorized sending hosts, increasing risk of domain impersonation.",
                    remediation="Publish a valid SPF record (e.g. 'v=spf1 mx -all' or appropriate mail service include).",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # Check DMARC
        if not dmarc_records and ("MX" in records_collected or "A" in records_collected):
            findings.append(
                Finding(
                    title="Missing DMARC Policy Record",
                    category="dns_email_security",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    asset=domain,
                    target=domain,
                    protocol="dns",
                    description=f"No DMARC TXT record found at _dmarc.{domain}.",
                    evidence=[ev],
                    detection_method="dns_dmarc_query",
                    impact="Absence of a DMARC policy allows unauthenticated spoofed mail claiming to originate from this domain to be delivered without enforcement.",
                    remediation="Publish a DMARC record at _dmarc." + domain + " with at least 'v=DMARC1; p=quarantine;' or 'p=reject;'.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )
        elif dmarc_records and any("p=none" in r for r in dmarc_records):
            findings.append(
                Finding(
                    title="DMARC Policy Set to None (Monitor-Only)",
                    category="dns_email_security",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    asset=domain,
                    target=domain,
                    protocol="dns",
                    description=f"DMARC record at _dmarc.{domain} specifies 'p=none', offering no enforcement against spoofing.",
                    evidence=[ev],
                    detection_method="dns_dmarc_query",
                    impact="Mail servers will deliver unauthorized emails claiming to be from this domain without quarantine or rejection.",
                    remediation="Transition DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once verified.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # Check Dangling CNAME indicator
        cnames = records_collected.get("CNAME", [])
        for cname in cnames:
            cname_target = cname.rstrip(".")
            try:
                self.resolver.resolve(cname_target, "A")
            except dns.resolver.NXDOMAIN:
                findings.append(
                    Finding(
                        title=f"Dangling CNAME Indicator ({cname_target})",
                        category="dns_takeover_risk",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        asset=domain,
                        target=domain,
                        protocol="dns",
                        description=f"CNAME record points to {cname_target}, which returns NXDOMAIN (non-existent domain).",
                        evidence=[ev],
                        detection_method="dns_cname_resolution_probe",
                        impact="If the destination domain or third-party service name is claimable by an external party, it may allow subdomain takeover.",
                        remediation="Remove or update the obsolete CNAME record immediately.",
                        references=["https://cwe.mitre.org/data/definitions/1059.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )
            except Exception:
                pass

        # Check Zone Transfer (AXFR) only if explicitly enabled
        if test_axfr:
            ns_list = records_collected.get("NS", [])
            for ns in ns_list:
                ns_clean = ns.rstrip(".")
                try:
                    # Attempt AXFR safely
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=3.0))
                    if zone and len(zone.nodes) > 1:
                        findings.append(
                            Finding(
                                title=f"DNS Zone Transfer (AXFR) Allowed on {ns_clean}",
                                category="dns_misconfiguration",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                asset=domain,
                                target=domain,
                                protocol="dns",
                                description=f"Nameserver {ns_clean} permitted unrestricted zone transfer (AXFR) for {domain}.",
                                evidence=[ev],
                                detection_method="dns_zone_transfer_probe",
                                impact="Full internal and external subdomain topology and host mappings are revealed to unauthorized parties.",
                                remediation="Restrict AXFR zone transfers to authorized secondary nameserver IP addresses only.",
                                references=["https://cwe.mitre.org/data/definitions/200.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )
                except Exception:
                    # Zone transfer correctly refused/failed
                    pass

        return StageResult(
            stage="dns_assessment",
            status=StageStatus.SUCCESS,
            reason=f"Resolved {len(records_collected)} record types for {domain}.",
            duration_seconds=round(time.monotonic() - t0, 2),
            findings=findings,
            evidence=evidence_list,
            data=data,
        )

    assess_dns = assess_target
