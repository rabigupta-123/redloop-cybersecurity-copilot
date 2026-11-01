"""Read-only TLS configuration and certificate inspection for explicitly scoped targets."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord
from redloop.scope import ScopeManager, UnauthorizedTargetError

MAX_TIMEOUT_SECONDS = 10
DEFAULT_PORT = 443

INSECURE_CIPHER_SUBSTRINGS = (
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "ANON",
    "RC2",
    "IDEA",
)
DEPRECATED_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")


class TLSError(Exception):
    """Base exception for TLS inspection."""


class UnsafeTLSTargetError(TLSError):
    """Target is malformed or invalid."""


class TLSConnectionError(TLSError):
    """Network connection or TLS handshake failed."""


class TLSCertificateInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    valid_from: str | None = None
    valid_until: str | None = None
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_self_signed: bool = False
    san: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    version: int | None = None


class TLSFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: str
    severity: Literal["info", "low", "medium", "high"]
    description: str


class TLSReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    port: int
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    trusted_chain: bool = False
    certificate: TLSCertificateInfo | None = None
    findings: list[TLSFinding] = Field(default_factory=list)


def _parse_x509_name(name_entries: Any) -> dict[str, str]:
    """Normalize subject or issuer tuple from ssl.getpeercert()."""
    parsed: dict[str, str] = {}
    if not isinstance(name_entries, (list, tuple)):
        return parsed
    for item in name_entries:
        if isinstance(item, (list, tuple)):
            for rdn in item:
                if isinstance(rdn, tuple) and len(rdn) == 2:
                    k, v = rdn
                    parsed[str(k)] = str(v)
    return parsed


def _parse_cert_dict(cert: dict[str, Any], raw_der: bytes | None = None) -> TLSCertificateInfo:
    """Extract structured certificate metadata from ssl peer cert dictionary."""
    subject = _parse_x509_name(cert.get("subject", ()))
    issuer = _parse_x509_name(cert.get("issuer", ()))

    valid_from_str = cert.get("notBefore")
    valid_until_str = cert.get("notAfter")

    valid_from_iso: str | None = None
    valid_until_iso: str | None = None
    days_until_expiry: int | None = None
    is_expired = False

    time_fmt = "%b %d %H:%M:%S %Y %Z"
    if valid_from_str:
        try:
            dt_from = datetime.strptime(valid_from_str, time_fmt).replace(tzinfo=timezone.utc)
            valid_from_iso = dt_from.isoformat()
        except ValueError:
            valid_from_iso = valid_from_str

    if valid_until_str:
        try:
            dt_until = datetime.strptime(valid_until_str, time_fmt).replace(tzinfo=timezone.utc)
            valid_until_iso = dt_until.isoformat()
            now = datetime.now(timezone.utc)
            delta = dt_until - now
            days_until_expiry = delta.days
            is_expired = now > dt_until
        except ValueError:
            valid_until_iso = valid_until_str

    # Extract SAN
    san_list: list[str] = []
    for san_type, san_val in cert.get("subjectAltName", ()):
        san_list.append(f"{san_type}:{san_val}")

    is_self_signed = bool(subject and subject == issuer)

    serial = cert.get("serialNumber")
    version = cert.get("version")

    return TLSCertificateInfo(
        subject=subject,
        issuer=issuer,
        valid_from=valid_from_iso,
        valid_until=valid_until_iso,
        days_until_expiry=days_until_expiry,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
        san=san_list,
        serial_number=str(serial) if serial is not None else None,
        version=int(version) if version is not None else None,
    )


class TLSChecker:
    """Scope-checked TLS handshake and certificate security inspector."""

    def __init__(
        self,
        scope: ScopeManager,
        audit: AuditLogger,
        timeout: float = 5.0,
        memory: EpisodicMemory | None = None,
    ):
        if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT_SECONDS}")
        self.scope = scope
        self.audit = audit
        self.timeout = timeout
        self.memory = memory

    def inspect(self, target: str, port: int = DEFAULT_PORT) -> TLSReport:
        clean_target = target.strip()
        if not (1 <= port <= 65_535):
            raise ValueError("Port must be between 1 and 65535")

        # 1. Pipeline Step 1: Enforce Scope Authorization
        try:
            scope_entry = self.scope.check(clean_target, "tls_check", port=port)
        except UnauthorizedTargetError as exc:
            self.audit.log(
                clean_target,
                "tls_check",
                "tls",
                "blocked",
                {"port": port, "reason": str(exc)},
            )
            raise

        # 2. Pipeline Step 2: Audit started
        self.audit.log(
            clean_target,
            "tls_check",
            "tls",
            "started",
            {"port": port},
            scope_entry=scope_entry.label,
        )

        # 3. Pipeline Step 3: Bounded execution
        try:
            report = self._inspect_tls(clean_target, port)
        except Exception as exc:
            self.audit.log(
                clean_target,
                "tls_check",
                "tls",
                "failed",
                {"port": port, "error_type": type(exc).__name__, "detail": str(exc)[:500]},
                scope_entry=scope_entry.label,
            )
            if isinstance(exc, TLSError):
                raise
            raise TLSConnectionError(f"TLS inspection failed: {exc}") from exc

        # 4. Pipeline Step 4: Audit success
        self.audit.log(
            clean_target,
            "tls_check",
            "tls",
            "success",
            report.model_dump(mode="json"),
            scope_entry=scope_entry.label,
        )

        # 5. Episodic Memory Record (advisory, bounded)
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description=f"TLS certificate inspection for {clean_target}:{port}",
                    approach="ssl stdlib handshake and cert chain analysis",
                    outcome="success",
                    module="tls",
                    details=f"proto={report.protocol}; cipher={report.cipher}; findings={len(report.findings)}",
                )
            )

        return report

    def _inspect_tls(self, target: str, port: int) -> TLSReport:
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        server_hostname = None if is_ip else target

        # Check default system verification first
        trusted_chain = False
        initial_verification_error: str | None = None
        verify_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=server_hostname) as ss:
                    trusted_chain = True
        except ssl.SSLCertVerificationError as exc:
            initial_verification_error = exc.verify_message or str(exc)
        except Exception:
            # Sockets or handshake might fail with strict verification on self-signed certs
            pass

        # Connect with inspection context (allows reading cert metadata even if self-signed)
        inspect_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        inspect_ctx.check_hostname = False
        inspect_ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((target, port), timeout=self.timeout) as raw_sock:
                with inspect_ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as ssl_sock:
                    protocol = ssl_sock.version()
                    cipher_info = ssl_sock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else None
                    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else None

                    der_bytes = ssl_sock.getpeercert(binary_form=True)
                    decoded_cert: dict[str, Any] = {}
                    if der_bytes:
                        try:
                            # Use cryptography if available for comprehensive DER decoding
                            from cryptography import x509
                            cert_obj = x509.load_der_x509_certificate(der_bytes)
                            subject_dict = {
                                attr.oid._name: attr.value
                                for attr in cert_obj.subject
                            }
                            issuer_dict = {
                                attr.oid._name: attr.value
                                for attr in cert_obj.issuer
                            }
                            san_list: list[str] = []
                            try:
                                san_ext = cert_obj.extensions.get_extension_for_oid(
                                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                                )
                                for name in san_ext.value:
                                    san_list.append(str(name.value))
                            except Exception:
                                pass

                            now = datetime.now(timezone.utc)
                            not_before = cert_obj.not_valid_before_utc
                            not_after = cert_obj.not_valid_after_utc
                            days_left = (not_after - now).days
                            expired = now > not_after
                            self_signed = cert_obj.subject == cert_obj.issuer

                            cert_info = TLSCertificateInfo(
                                subject=subject_dict,
                                issuer=issuer_dict,
                                valid_from=not_before.isoformat(),
                                valid_until=not_after.isoformat(),
                                days_until_expiry=days_left,
                                is_expired=expired,
                                is_self_signed=self_signed,
                                san=san_list,
                                serial_number=str(cert_obj.serial_number),
                                version=cert_obj.version.value if hasattr(cert_obj.version, "value") else 3,
                            )
                        except Exception:
                            cert_info = None
                    else:
                        cert_info = None
        except (socket.timeout, TimeoutError) as exc:
            raise TLSConnectionError(f"Connection to {target}:{port} timed out after {self.timeout}s") from exc
        except (ConnectionRefusedError, ConnectionResetError) as exc:
            raise TLSConnectionError(f"Connection to {target}:{port} refused: {exc}") from exc
        except OSError as exc:
            raise TLSConnectionError(f"Network error connecting to {target}:{port}: {exc}") from exc

        # Evaluate Security Findings
        findings: list[TLSFinding] = []

        if not trusted_chain:
            findings.append(
                TLSFinding(
                    check="untrusted-certificate-authority",
                    severity="medium",
                    description=(
                        initial_verification_error
                        or "Certificate chain could not be verified against the trusted root store."
                    ),
                )
            )

        if protocol in DEPRECATED_PROTOCOLS:
            findings.append(
                TLSFinding(
                    check="deprecated-tls-protocol",
                    severity="high",
                    description=f"Negotiated legacy TLS protocol '{protocol}'. Minimum TLSv1.2 or TLSv1.3 is recommended.",
                )
            )

        if cipher_bits is not None and cipher_bits < 128:
            findings.append(
                TLSFinding(
                    check="weak-cipher-strength",
                    severity="high",
                    description=f"Cipher secret key strength ({cipher_bits} bits) is below the minimum safe threshold (128 bits).",
                )
            )

        if cipher_name:
            c_upper = cipher_name.upper()
            for pattern in INSECURE_CIPHER_SUBSTRINGS:
                if pattern in c_upper:
                    findings.append(
                        TLSFinding(
                            check="insecure-cipher-suite",
                            severity="high",
                            description=f"Cipher suite '{cipher_name}' uses legacy or broken algorithm component '{pattern}'.",
                        )
                    )
                    break
            if "-CBC-" in c_upper or "_CBC_" in c_upper:
                findings.append(
                    TLSFinding(
                        check="cbc-cipher-mode",
                        severity="low",
                        description=f"Cipher suite '{cipher_name}' uses CBC mode; authenticated AEAD (GCM/CHACHA20) is preferred.",
                    )
                )

        if cert_info is not None:
            if cert_info.is_expired:
                findings.append(
                    TLSFinding(
                        check="certificate-expired",
                        severity="high",
                        description=f"Certificate expired on {cert_info.valid_until}.",
                    )
                )
            elif cert_info.days_until_expiry is not None and cert_info.days_until_expiry <= 30:
                findings.append(
                    TLSFinding(
                        check="certificate-expiring-soon",
                        severity="medium",
                        description=f"Certificate expires in {cert_info.days_until_expiry} day(s) on {cert_info.valid_until}.",
                    )
                )

            if cert_info.is_self_signed:
                findings.append(
                    TLSFinding(
                        check="self-signed-certificate",
                        severity="medium",
                        description="Certificate subject matches issuer (self-signed).",
                    )
                )

            # Check SAN / Hostname matching
            if server_hostname:
                matched = False
                cn = cert_info.subject.get("commonName")
                if cn and cn.lower() == server_hostname.lower():
                    matched = True
                for s in cert_info.san:
                    if s.lower() == server_hostname.lower():
                        matched = True
                        break
                if not matched:
                    findings.append(
                        TLSFinding(
                            check="hostname-mismatch",
                            severity="medium",
                            description=f"Target hostname '{server_hostname}' does not match certificate CN '{cn}' or SANs.",
                        )
                    )

        return TLSReport(
            target=target,
            port=port,
            protocol=protocol,
            cipher=cipher_name,
            cipher_bits=cipher_bits,
            trusted_chain=trusted_chain,
            certificate=cert_info,
            findings=findings,
        )
