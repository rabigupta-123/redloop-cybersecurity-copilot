"""Deterministic Risk Analytics & Technology-Aware Remediation Intelligence Engine (Phase 4.1 Hardened).

Features:
- Quantitative Composite Risk Scoring (CVSS + EPSS + CISA KEV + Asset Criticality + Verification Status)
- Truthful Operational Prioritization (P1 Immediate to P5 Informational)
- Technology-Aware Concrete Remediation Guidance (Immediate containment, permanent fix, config snippet, validation steps, rollback)

Formula:
    Risk = BaseCVSS_100 * KEV_Multiplier * EPSS_Multiplier * Exposure_Multiplier * Criticality_Multiplier * Verification_Multiplier
    where:
    - BaseCVSS_100: Raw CVSS v3.1/v4.0 score * 10 (or severity default if unindexed: Critical=95, High=75, Medium=50, Low=25, Info=5)
    - KEV_Multiplier: 1.35 if confirmed in CISA KEV, else 1.0
    - EPSS_Multiplier: 1.0 + (EPSS_probability * 0.3), where EPSS in [0.0, 1.0]
    - Exposure_Multiplier: 1.15 if Internet-exposed, else 0.85
    - Criticality_Multiplier: clamped to [0.8, 1.5]
    - Verification_Multiplier: VALIDATED/CORROBORATED=1.0, OBSERVED=0.85, UNVERIFIED=0.6, NOT_ASSESSED=0.5, CONTRADICTED=0.15, FALSE_POSITIVE=0.0
    - Final composite score is clamped strictly to [0.0, 100.0]
"""

from __future__ import annotations

import logging
import math
from typing import Any

from redloop.assessment.finding_models import (
    Finding,
    FindingRemediation,
    FindingSeverity,
    OperationalPriority,
    VerificationStatus,
)

logger = logging.getLogger("redloop.risk_remediation")


class RiskAnalyticsEngine:
    """Computes transparent, reproducible risk scores and operational priorities."""

    @staticmethod
    def calculate_risk(
        finding: Finding,
        asset_criticality_factor: float = 1.0,  # 0.8 to 1.5
        is_internet_exposed: bool = True,
    ) -> tuple[float, OperationalPriority, dict[str, Any]]:
        """Calculate quantitative risk score (0.0 to 100.0) and assign OperationalPriority.

        Returns:
            (risk_score, operational_priority, score_breakdown)
        """
        # 0. Input validation (Reject NaN, Inf, out of range values)
        if math.isnan(asset_criticality_factor) or math.isinf(asset_criticality_factor):
            raise ValueError("asset_criticality_factor cannot be NaN or Infinite.")

        if finding.cvss_score is not None:
            if math.isnan(finding.cvss_score) or math.isinf(finding.cvss_score):
                raise ValueError("finding.cvss_score cannot be NaN or Infinite.")
            if finding.cvss_score < 0.0 or finding.cvss_score > 10.0:
                raise ValueError("finding.cvss_score must be between 0.0 and 10.0.")

        # 1. Base CVSS normalization (0.0 to 10.0 scale -> 0.0 to 100.0 baseline)
        if finding.cvss_score is not None and finding.cvss_score > 0.0:
            base_score = finding.cvss_score * 10.0
        else:
            severity_defaults = {
                FindingSeverity.CRITICAL: 95.0,
                FindingSeverity.HIGH: 75.0,
                FindingSeverity.MEDIUM: 50.0,
                FindingSeverity.LOW: 25.0,
                FindingSeverity.INFORMATIONAL: 5.0,
            }
            base_score = severity_defaults.get(finding.severity, 25.0)

        # 2. Threat Intelligence Multipliers
        # CISA KEV: Known actively exploited vulnerability in wild (+35% risk boost)
        kev_multiplier = 1.35 if finding.cisa_kev else 1.0

        # EPSS: Exploit Prediction Scoring System (0.0 - 1.0)
        # Adds up to +30% based on EPSS probability
        epss_prob = 0.0
        if finding.epss_score is not None:
            if math.isnan(finding.epss_score) or math.isinf(finding.epss_score):
                raise ValueError("finding.epss_score cannot be NaN or Infinite.")
            if finding.epss_score > 1.0:
                if finding.epss_score <= 100.0:
                    epss_prob = finding.epss_score / 100.0
                else:
                    raise ValueError("finding.epss_score exceeds maximum range (must be <= 1.0 or <= 100%).")
            elif finding.epss_score < 0.0:
                raise ValueError("finding.epss_score cannot be negative.")
            else:
                epss_prob = finding.epss_score

        epss_multiplier = 1.0 + (epss_prob * 0.3)

        # 3. Environmental & Asset Multipliers
        exposure_multiplier = 1.15 if is_internet_exposed else 0.85
        criticality_multiplier = max(0.8, min(1.5, float(asset_criticality_factor)))

        # 4. Verification Multiplier
        # Don't prioritize unverified or contradicted alerts
        verification_multipliers = {
            VerificationStatus.VALIDATED: 1.0,
            VerificationStatus.CORROBORATED: 1.0,
            VerificationStatus.OBSERVED: 0.85,
            VerificationStatus.UNVERIFIED: 0.6,
            VerificationStatus.NOT_ASSESSED: 0.5,
            VerificationStatus.CONTRADICTED: 0.15,
            VerificationStatus.FALSE_POSITIVE: 0.0,
            # Aliases
            VerificationStatus.CONFIRMED: 1.0,
            VerificationStatus.SUPPORTED: 0.85,
            VerificationStatus.UNABLE_TO_VERIFY: 0.5,
        }
        ver_multiplier = verification_multipliers.get(finding.verification_status, 0.7)

        # 5. Composite Risk Calculation
        raw_score = (
            base_score
            * kev_multiplier
            * epss_multiplier
            * exposure_multiplier
            * criticality_multiplier
            * ver_multiplier
        )
        final_score = round(max(0.0, min(100.0, raw_score)), 1)

        # 6. Operational Priority Determination
        # Strict deterministic mapping
        if finding.verification_status in (VerificationStatus.FALSE_POSITIVE, VerificationStatus.CONTRADICTED):
            priority = OperationalPriority.P5_INFORMATIONAL
        elif finding.cisa_kev and final_score >= 70.0:
            priority = OperationalPriority.P1_CRITICAL_IMMEDIATE
        elif final_score >= 85.0:
            priority = OperationalPriority.P1_CRITICAL_IMMEDIATE
        elif final_score >= 65.0:
            priority = OperationalPriority.P2_HIGH_URGENT
        elif final_score >= 40.0:
            priority = OperationalPriority.P3_MEDIUM_SCHEDULED
        elif final_score >= 15.0:
            priority = OperationalPriority.P4_LOW_BACKLOG
        else:
            priority = OperationalPriority.P5_INFORMATIONAL

        breakdown = {
            "base_score": base_score,
            "raw_cvss": finding.cvss_score,
            "kev_multiplier": kev_multiplier,
            "epss_probability": epss_prob,
            "epss_multiplier": round(epss_multiplier, 3),
            "exposure_multiplier": exposure_multiplier,
            "criticality_multiplier": criticality_multiplier,
            "verification_multiplier": ver_multiplier,
            "composite_score": final_score,
            "operational_priority": priority.value,
        }

        finding.risk_score = final_score
        finding.operational_priority = priority
        return final_score, priority, breakdown

    @classmethod
    def score_findings(cls, findings: list[Finding]) -> list[Finding]:
        """Batch compute risk scores for all findings."""
        for f in findings:
            cls.calculate_risk(f)
        return sorted(findings, key=lambda x: x.risk_score or 0.0, reverse=True)


class RemediationIntelligenceEngine:
    """Generates concrete, copy-pasteable remediation guidance with validation commands and rollback plans."""

    TEMPLATES: dict[str, dict[str, str]] = {
        "ssh_weak_ciphers": {
            "immediate_containment": "Restrict inbound TCP port 22 access via firewall to administrative bastion hosts only.",
            "permanent_fix": "Update /etc/ssh/sshd_config to restrict Ciphers, MACs, and KexAlgorithms to modern strong primitives, and disable root/password auth.",
            "configuration_snippet": (
                "# /etc/ssh/sshd_config.d/99-hardening.conf\n"
                "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512\n"
                "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n"
                "MACs hmac-sha2-512-etm@openssh.com\n"
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
            ),
            "validation_steps": "sshd -t && systemctl reload sshd && ssh -vv -oCiphers=3des-cbc target_host (verify connection rejected)",
            "rollback_plan": "rm -f /etc/ssh/sshd_config.d/99-hardening.conf && systemctl reload sshd",
        },
        "missing_security_headers": {
            "immediate_containment": "Deploy reverse proxy or Cloudflare/WAF header injection rule to add missing security headers.",
            "permanent_fix": "Configure web server (Nginx/Apache) or application framework middleware to emit HSTS, CSP, X-Content-Type-Options, and X-Frame-Options on all responses.",
            "configuration_snippet": (
                "# Nginx server/http block\n"
                "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;\n"
                "add_header X-Frame-Options 'SAMEORIGIN' always;\n"
                "add_header X-Content-Type-Options 'nosniff' always;\n"
                "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
            ),
            "validation_steps": "curl -sI https://target_host/ | grep -iE '(strict-transport|x-frame|x-content-type|content-security)'",
            "rollback_plan": "Comment out add_header directives in nginx.conf and run: nginx -s reload",
        },
        "tls_legacy_protocol": {
            "immediate_containment": "Place host behind TLS termination proxy or load balancer enforcing TLSv1.2/1.3.",
            "permanent_fix": "Disable SSLv3, TLS 1.0, and TLS 1.1 in web server or service configuration, allowing only TLSv1.2 and TLSv1.3.",
            "configuration_snippet": (
                "# Nginx SSL configuration\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_prefer_server_ciphers off;\n"
                "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\n"
            ),
            "validation_steps": "openssl s_client -connect target_host:443 -tls1_1 (should fail with handshake failure)",
            "rollback_plan": "Revert ssl_protocols to prior values in configuration and reload web server.",
        },
        "server_tokens_leak": {
            "immediate_containment": "Obfuscate Server and X-Powered-By response headers via edge proxy or reverse proxy.",
            "permanent_fix": "Disable detailed version banners in web server core configuration.",
            "configuration_snippet": (
                "# Apache (httpd.conf / apache2.conf)\n"
                "ServerTokens Prod\n"
                "ServerSignature Off\n\n"
                "# Nginx (nginx.conf)\n"
                "server_tokens off;\n"
            ),
            "validation_steps": "curl -sI http://target_host/ | grep -i 'Server:'",
            "rollback_plan": "Set ServerTokens Full / server_tokens on; reload service.",
        },
        "generic_cve_patch": {
            "immediate_containment": "Isolate affected service network segment or restrict source IP addresses via firewall/ACL rules.",
            "permanent_fix": "Upgrade the affected software component to the latest patched upstream or distribution release.",
            "configuration_snippet": (
                "# Ubuntu / Debian\n"
                "sudo apt-get update && sudo apt-get --only-upgrade install <package_name>\n\n"
                "# RHEL / CentOS / Rocky\n"
                "sudo dnf update <package_name>\n"
            ),
            "validation_steps": "dpkg -l <package_name> || rpm -q <package_name> (verify version is >= patched release)",
            "rollback_plan": "Downgrade package to prior version from local package cache or backup snapshot.",
        },
    }

    @classmethod
    def get_remediation_for_finding(cls, finding: Finding) -> FindingRemediation:
        """Determines best-matched actionable remediation guidance for a given finding."""
        key = "generic_cve_patch"
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()

        if "ciphers" in title_lower or "ssh" in title_lower and "weak" in desc_lower:
            key = "ssh_weak_ciphers"
        elif "header" in title_lower or "hsts" in title_lower or "csp" in title_lower:
            key = "missing_security_headers"
        elif "tls" in title_lower or "ssl" in title_lower:
            key = "tls_legacy_protocol"
        elif "server" in title_lower and "token" in title_lower or "banner" in title_lower:
            key = "server_tokens_leak"

        tmpl = cls.TEMPLATES.get(key, cls.TEMPLATES["generic_cve_patch"])

        pkg = finding.affected_component if finding.affected_component != "unknown" else "affected-package"
        snippet = tmpl.get("configuration_snippet")
        if snippet:
            snippet = snippet.replace("<package_name>", pkg)

        validation = tmpl.get("validation_steps", "").replace("<package_name>", pkg)
        validation = validation.replace("target_host", finding.target)

        return FindingRemediation(
            summary=f"Remediation procedure for {finding.title}",
            immediate_containment=tmpl.get("immediate_containment", ""),
            permanent_fix=tmpl.get("permanent_fix", ""),
            configuration_snippet=snippet,
            config_example=snippet,
            validation_steps=validation,
            rollback_plan=tmpl.get("rollback_plan", ""),
            references=finding.references,
        )

    @classmethod
    def enrich_finding(cls, finding: Finding) -> Finding:
        finding.remediation = cls.get_remediation_for_finding(finding)
        return finding
