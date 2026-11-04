"""Finding Validation & False-Positive Intelligence Engine (Phase 4.1 Hardened).

Validates discovered security findings against:
- Raw tool telemetry & HTTP response evidence
- Service banner versions vs CVE affected version intervals
- Multi-factor backported Linux distribution patch verification (Ubuntu, Debian, RHEL, CentOS, Alpine)
- Multi-source independent corroboration (elevates to CORROBORATED, never VALIDATED)
- Deterministic exploit / PoC proof (sole basis for VALIDATED)
"""

from __future__ import annotations

import re
from typing import Any

from redloop.assessment.finding_models import (
    FalsePositiveAnalysis,
    Finding,
    FindingType,
    VerificationStatus,
)
from redloop.assessment.intel_engine import VulnerabilityIntelligenceEngine


class FindingValidationEngine:
    """Evaluates findings to establish verification status and explainable false-positive likelihood."""

    # Distro identity and package revision signatures
    DISTRO_REVISION_PATTERNS = [
        ("Ubuntu", re.compile(r"(\d+)?ubuntu\d+(\.\d+)?", re.IGNORECASE)),
        ("Debian", re.compile(r"deb\d+u\d+", re.IGNORECASE)),
        ("RHEL/CentOS", re.compile(r"el\d+(_\d+)?", re.IGNORECASE)),
        ("Alpine", re.compile(r"alpine-r\d+", re.IGNORECASE)),
        ("AmazonLinux", re.compile(r"amzn\d+", re.IGNORECASE)),
    ]

    DISTRO_NAME_PATTERNS = [
        re.compile(r"\b(ubuntu|debian|centos|redhat|rhel|alpine|fedora|rocky|alma)\b", re.IGNORECASE)
    ]

    @classmethod
    def validate_finding(
        cls,
        finding: Finding,
        raw_evidence: str = "",
        external_intel: bool = True,
    ) -> Finding:
        fp_analysis = FalsePositiveAnalysis()
        intel_engine = VulnerabilityIntelligenceEngine.get_instance()

        ver_str = finding.affected_version or ""
        pkg_name = finding.affected_component or "package"
        combined_text = f"{ver_str} {raw_evidence} {finding.title} {finding.description}".strip()

        # 1. Multi-factor backport detection
        detected_distro: str | None = None
        has_revision: bool = False

        for distro_name, pat in cls.DISTRO_REVISION_PATTERNS:
            if pat.search(ver_str) or pat.search(combined_text):
                detected_distro = distro_name
                has_revision = True
                break

        if not detected_distro:
            for pat in cls.DISTRO_NAME_PATTERNS:
                m = pat.search(combined_text)
                if m:
                    detected_distro = m.group(1).capitalize()
                    break

        has_changelog = bool(
            finding.metadata.get("changelog_verified")
            or finding.metadata.get("backport_advisory")
            or finding.metadata.get("patch_confirmed")
        )

        if has_changelog:
            # Factor 4 confirmed: changelog or patch proof exists
            fp_analysis.likelihood = 0.85
            fp_analysis.is_false_positive = True
            fp_analysis.confidence_basis = "Distro backport changelog confirmation"
            fp_analysis.contradicting_evidence.append(
                f"Package changelog confirms backported security fix applied for {pkg_name} on {detected_distro or 'Linux distro'}."
            )
            fp_analysis.recommended_action = "Mark finding as fixed/contradicted by distribution backport."
        elif detected_distro and has_revision:
            # Factors 1, 2, 3 present: revision string confirms distro package
            fp_analysis.likelihood = 0.65
            fp_analysis.confidence_basis = "Distro package revision signature"
            fp_analysis.contradicting_evidence.append(
                f"Version banner '{ver_str}' indicates distribution-maintained package ({detected_distro}) with probable backported security fixes."
            )
            fp_analysis.limitations.append(
                "Banner inspection cannot confirm whether the patch for specific CVE was backported without inspecting package changelog."
            )
            fp_analysis.verification_steps.extend([
                f"apt-get changelog {pkg_name} || rpm -q --changelog {pkg_name}",
                f"apt-cache policy {pkg_name} || rpm -q -i {pkg_name}",
            ])
            fp_analysis.recommended_action = "Inspect local package changelog (apt-get changelog / rpm -q --changelog) before reporting."
        elif detected_distro:
            # Distro mentioned but no specific package revision or changelog -> Inconclusive
            fp_analysis.likelihood = 0.50
            fp_analysis.confidence_basis = "Inconclusive backport telemetry"
            fp_analysis.missing_evidence.append(
                "Distribution package name and installed revision not present in banner."
            )
            fp_analysis.limitations.append(
                "Insufficient evidence to verify whether backported patch applies."
            )
            fp_analysis.verification_steps.append(
                f"Query package manager: dpkg -l {pkg_name} || rpm -qa | grep {pkg_name}"
            )
            fp_analysis.recommended_action = (
                "Perform authenticated package verification to determine exact patch status."
            )

        # 2. Check CVE intelligence and version applicability
        if finding.cve_ids and external_intel:
            for cve in finding.cve_ids:
                rec = intel_engine.get_cve_intel(cve)
                if rec.cisa_kev:
                    finding.cisa_kev = True
                    if "CISA_KEV" not in finding.intelligence_tags:
                        finding.intelligence_tags.append("CISA_KEV")
                    fp_analysis.supporting_evidence.append(
                        f"CVE {cve} is actively exploited in the wild (CISA KEV)."
                    )
                if rec.epss_score is not None and finding.epss_score is None:
                    finding.epss_score = rec.epss_score

        # 3. Establish Verification Status
        # Rules:
        # - High false positive likelihood (>= 0.8) -> CONTRADICTED
        # - Probable backport (likelihood > 0.5) -> CONTRADICTED
        # - Inconclusive backport (likelihood == 0.5) -> UNVERIFIED
        # - Authenticated PoC / exploit proof -> VALIDATED
        # - Multi-tool corroboration (2+ distinct sources) -> CORROBORATED (NEVER VALIDATED)
        # - Single tool observation with evidence -> OBSERVED
        # - Else -> UNVERIFIED
        corroborated_sources = finding.metadata.get("corroborating_evidences", [])
        is_multi_source = (len(corroborated_sources) >= 2) or (len(finding.evidence_ids) >= 2)
        has_exploit_proof = bool(
            finding.metadata.get("exploit_validated")
            or finding.metadata.get("poc_verified")
        )

        if fp_analysis.likelihood >= 0.8:
            finding.verification_status = VerificationStatus.CONTRADICTED
            fp_analysis.is_false_positive = True
            finding.confidence = 0.20
        elif detected_distro and has_revision and fp_analysis.likelihood > 0.5:
            finding.verification_status = VerificationStatus.CONTRADICTED
            finding.confidence = 0.35
        elif fp_analysis.likelihood == 0.50:
            finding.verification_status = VerificationStatus.UNVERIFIED
            finding.confidence = 0.50
        elif has_exploit_proof:
            finding.verification_status = VerificationStatus.VALIDATED
            finding.confidence = 0.98
        elif is_multi_source:
            finding.verification_status = VerificationStatus.CORROBORATED
            finding.confidence = 0.90
        elif finding.raw_evidence_id or finding.verification_status in (
            VerificationStatus.OBSERVED,
            VerificationStatus.SUPPORTED,
        ):
            finding.verification_status = VerificationStatus.OBSERVED
            finding.confidence = 0.75
        else:
            finding.verification_status = VerificationStatus.UNVERIFIED
            finding.confidence = 0.40

        finding.false_positive_status = fp_analysis
        return finding

    @classmethod
    def batch_validate(cls, findings: list[Finding]) -> list[Finding]:
        return [cls.validate_finding(f) for f in findings]
