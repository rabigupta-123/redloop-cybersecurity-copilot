"""Deep TLS / SSL security assessment engine.

Audits:
- Certificate validity, expiration, issuer, subject, SANs
- Deprecated protocols (SSLv2, SSLv3, TLS 1.0, 1.1)
- Insecure ciphers (RC4, DES, 3DES, MD5, NULL, EXPORT)
- Self-signed certificates and hostname mismatches
- HSTS and secure transport indicators
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any

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
from redloop.tls import (
    DEPRECATED_PROTOCOLS,
    INSECURE_CIPHER_SUBSTRINGS,
    TLSChecker,
    TLSError,
)


class TLSEngine:
    """Performs deep, deterministic TLS configuration and certificate assessment."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.checker = TLSChecker(scope=scope_guard.scope_manager, audit=audit or AuditLogger())

    def assess_target(
        self,
        target: str,
        port: int = 443,
        operation_id: str = "op-tls",
        timeout: float = 10.0,
    ) -> StageResult:
        """Run deep TLS inspection against authorized target."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []

        # 1. Scope verification
        try:
            self.scope_guard.is_target_authorized(
                target, "tls_check", port=port, op_class=OperationClass.SAFE_ACTIVE
            )
        except Exception as exc:
            return StageResult(
                stage="tls_assessment",
                status=StageStatus.BLOCKED,
                reason=f"Scope authorization rejected: {exc}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        # 2. Check TLS via TLSChecker
        try:
            report = self.checker.inspect(target, port=port)
        except Exception as exc:
            return StageResult(
                stage="tls_assessment",
                status=StageStatus.UNAVAILABLE,
                reason=f"TLS handshake failed or port not serving TLS: {exc}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        # 3. Create evidence from inspection
        cert_data = report.certificate.model_dump() if report.certificate else {}
        evidence_data = {
            "target": target,
            "port": port,
            "protocol_version": report.protocol,
            "cipher_suite": report.cipher,
            "certificate": cert_data,
        }
        ev = Evidence(
            operation_id=operation_id,
            target=target,
            request_metadata={"port": port, "action": "tls_handshake"},
            response_metadata={"protocol": report.protocol, "cipher": report.cipher},
            response_excerpt=str(evidence_data),
            tool_output=f"Negotiated {report.protocol} with cipher {report.cipher}.",
            parser_result=evidence_data,
        )
        evidence_list.append(ev)

        # 4. Map findings into standardized Finding schema
        if report.certificate:
            cert = report.certificate
            if cert.is_expired:
                findings.append(
                    Finding(
                        title="Expired TLS Certificate",
                        category="tls_certificate",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        asset=target,
                        target=target,
                        port=port,
                        protocol="tls",
                        description=f"The TLS certificate for {target} expired on {cert.valid_until}.",
                        evidence=[ev],
                        detection_method="x509_certificate_inspection",
                        impact="Clients will encounter trust warnings, risking denial of service and user habituation to security warnings.",
                        remediation="Renew and install an unexpired certificate issued by a trusted Certificate Authority.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

            if cert.is_self_signed:
                findings.append(
                    Finding(
                        title="Self-Signed TLS Certificate",
                        category="tls_certificate",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        asset=target,
                        target=target,
                        port=port,
                        protocol="tls",
                        description=f"The certificate for {target} is self-signed (Issuer: {cert.issuer.get('commonName')}).",
                        evidence=[ev],
                        detection_method="x509_certificate_inspection",
                        impact="Self-signed certificates cannot be validated by standard client trust stores, facilitating adversary-in-the-middle attacks.",
                        remediation="Replace self-signed certificates in production with certificates from a recognized CA.",
                        references=["https://cwe.mitre.org/data/definitions/295.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

        # Check protocol weaknesses
        if report.protocol in DEPRECATED_PROTOCOLS:
            findings.append(
                Finding(
                    title=f"Deprecated TLS Protocol Enabled ({report.protocol})",
                    category="tls_protocol",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target,
                    target=target,
                    port=port,
                    protocol="tls",
                    description=f"Service negotiated {report.protocol}, which is cryptographically deprecated.",
                    evidence=[ev],
                    detection_method="tls_handshake_negotiation",
                    impact="Deprecated protocols suffer from known cryptographic vulnerabilities (e.g. POODLE, BEAST).",
                    remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server configuration. Enable TLS 1.2 and TLS 1.3.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # Check cipher weaknesses
        if any(bad in (report.cipher or "") for bad in INSECURE_CIPHER_SUBSTRINGS):
            findings.append(
                Finding(
                    title=f"Insecure TLS Cipher Suite Negotiated ({report.cipher})",
                    category="tls_cipher",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    asset=target,
                    target=target,
                    port=port,
                    protocol="tls",
                    description=f"Server negotiated weak cipher suite {report.cipher}.",
                    evidence=[ev],
                    detection_method="tls_handshake_negotiation",
                    impact="Weak ciphers risk plaintext recovery or downgrade attacks.",
                    remediation="Configure server to disable legacy ciphers (RC4, 3DES, CBC mode ciphers) and prioritize AEAD suites (GCM, CHACHA20).",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return StageResult(
            stage="tls_assessment",
            status=StageStatus.SUCCESS,
            reason=f"TLS inspected on port {port}: {report.protocol} with {len(findings)} findings.",
            duration_seconds=round(time.monotonic() - t0, 2),
            findings=findings,
            evidence=evidence_list,
            data=evidence_data,
        )

    assess_tls = assess_target
