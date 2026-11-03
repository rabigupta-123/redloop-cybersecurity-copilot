"""Deterministic Risk Analytics & Technology-Aware Remediation Intelligence Engine (Phase 4).

Features:
- Quantitative Composite Risk Scoring (CVSS + EPSS + CISA KEV + Asset Criticality + Verification Status)
- Truthful Operational Prioritization (P1 Immediate to P5 Informational)
- Technology-Aware Concrete Remediation Guidance (Immediate containment, permanent fix, config snippet, validation steps, rollback)
"""

from __future__ import annotations

import logging
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
        # 1. Base CVSS normalization (0.0 to 10.0 scale -> 0.0 to 100.0 baseline)
        if finding.cvss_score is not None and finding.cvss_score > 0.0:
            base_score = finding.cvss_score * 10.0
        else:
            severity_defaults = {
                FindingSeverity.CRITICAL: 95.0,
                FindingSeverity.HIGH: 75.0,
                FindingSeverity.MEDIUM: 50.0,
                FindingSeverity.LOW: 25.0,
                FindingSeverity.INFO: 5.0,
            }
            base_score = severity_defaults.get(finding.severity, 25.0)

        # 2. Threat Intelligence Multipliers
        # CISA KEV: Known actively exploited vulnerability in wild (+35% risk boost)
        kev_multiplier = 1.35 if finding.cisa_kev else 1.0

        # EPSS: Exploit Prediction Scoring System (0.0 - 1.0)
        # Adds up to +30% based on EPSS probability
        epss_prob = finding.epss_score if finding.epss_score is not None else 0.0
        epss_multiplier = 1.0 + (epss_prob * 0.3)

        # 3. Environmental & Asset Multipliers
        exposure_multiplier = 1.15 if is_internet_exposed else 0.85
        criticality_multiplier = max(0.8, min(1.5, asset_criticality_factor))

        # 4. Verification Multiplier
        # Don't prioritize unverified or contradicted alerts
        verification_multipliers = {
            VerificationStatus.CONFIRMED: 1.0,
            VerificationStatus.CORROBORATED: 1.0,
            VerificationStatus.SUPPORTED: 0.9,
            VerificationStatus.UNVERIFIED: 0.6,
            VerificationStatus.UNABLE_TO_VERIFY: 0.5,
            VerificationStatus.CONTRADICTED: 0.15,
            VerificationStatus.FALSE_POSITIVE: 0.0,
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
        if finding.verification_status == VerificationStatus.FALSE_POSITIVE:
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
    def enrich_finding(cls, finding: Finding) -> Finding:
        """Assign concrete remediation guidance to finding based on title, description, or cve_ids."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()

        matched_key = None
        if "header" in title_lower or "hsts" in title_lower or "csp" in title_lower or "x-frame" in title_lower:
            matched_key = "missing_security_headers"
        elif "ssh" in title_lower or "ssh" in desc_lower:
            matched_key = "ssh_weak_ciphers"
        elif "tls" in title_lower or "ssl" in title_lower or "protocol" in title_lower:
            matched_key = "tls_legacy_protocol"
        elif "server" in title_lower and ("token" in title_lower or "banner" in title_lower or "version" in title_lower):
            matched_key = "server_tokens_leak"
        elif finding.cve_ids:
            matched_key = "generic_cve_patch"

        if matched_key and matched_key in cls.TEMPLATES:
            tmpl = cls.TEMPLATES[matched_key]
            finding.remediation = FindingRemediation(
                immediate_containment=tmpl["immediate_containment"],
                permanent_fix=tmpl["permanent_fix"],
                configuration_snippet=tmpl["configuration_snippet"],
                validation_steps=tmpl["validation_steps"],
                rollback_plan=tmpl["rollback_plan"],
            )
        elif not finding.remediation:
            # Fallback sensible generic remediation
            finding.remediation = FindingRemediation(
                immediate_containment="Restrict network access to affected service to trusted management networks.",
                permanent_fix="Review service security configuration and update software to the latest stable vendor release.",
                configuration_snippet="# Review vendor documentation for specific configuration guidance.",
                validation_steps="Re-run assessment probe to confirm condition is resolved.",
                rollback_plan="Preserve pre-change configuration backup files before applying any changes.",
            )

        return finding

    @classmethod
    def batch_enrich(cls, findings: list[Finding]) -> list[Finding]:
        return [cls.enrich_finding(f) for f in findings]
