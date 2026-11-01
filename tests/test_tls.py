"""Unit and real local integration tests for RedLoop TLS certificate and cipher inspection."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory
from redloop.scope import UnauthorizedTargetError
from redloop.tls import (
    TLSChecker,
    TLSConnectionError,
    TLSError,
    TLSReport,
    UnsafeTLSTargetError,
)


class FakeScope:
    def __init__(self, allowed_targets=None, denied_port=None):
        self.allowed_targets = allowed_targets or ["127.0.0.1", "localhost"]
        self.denied_port = denied_port
        self.checked = []

    def check(self, target, action, port=None):
        self.checked.append((target, action, port))
        if target not in self.allowed_targets or port == self.denied_port:
            raise UnauthorizedTargetError(f"Target {target}:{port} not authorized for {action}")
        return SimpleNamespace(label="test-scope-entry")


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append((target, action, module, status, details or {}, scope_entry))


def _generate_test_cert_and_key(
    cn: str = "localhost",
    days_valid: int = 90,
    sans: list[str] | None = None,
) -> tuple[str, str]:
    """Generate a real self-signed certificate and private key file."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RedLoop Test Lab"),
    ])

    now = datetime.now(timezone.utc)
    if days_valid >= 0:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)
    else:
        not_before = now + timedelta(days=days_valid - 10)
        not_after = now + timedelta(days=days_valid)

    san_names = []
    for s in (sans or [cn, "127.0.0.1"]):
        try:
            ip = ipaddress.ip_address(s)
            san_names.append(x509.IPAddress(ip))
        except ValueError:
            san_names.append(x509.DNSName(s))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".pem") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert_pem_path = f.name

    return cert_pem_path, cert_pem_path


def _start_real_tls_server(cert_file: str) -> tuple[int, threading.Thread, threading.Event]:
    """Start a real local TLS listener on an ephemeral loopback port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    port = server_sock.getsockname()[1]
    stop_event = threading.Event()

    def run_server():
        server_sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                client, _ = server_sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                ssl_conn = ctx.wrap_socket(client, server_side=True)
                ssl_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                ssl_conn.close()
            except Exception:
                pass
        server_sock.close()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    return port, thread, stop_event


# -----------------------------------------------------------------------------
# Unit & Scope Enforcement Tests
# -----------------------------------------------------------------------------

def test_tls_scope_denial_blocks_before_network():
    """Unscoped target must fail closed before any socket or network activity."""
    scope = FakeScope(allowed_targets=["127.0.0.1"], denied_port=9999)
    audit = FakeAudit()
    checker = TLSChecker(scope, audit)

    with pytest.raises(UnauthorizedTargetError):
        checker.inspect("127.0.0.1", port=9999)

    assert len(scope.checked) == 1
    assert scope.checked[0] == ("127.0.0.1", "tls_check", 9999)
    assert len(audit.entries) == 1
    assert audit.entries[0][3] == "blocked"
    assert audit.entries[0][2] == "tls"


def test_tls_invalid_ports_and_timeouts_fail_validation():
    scope = FakeScope()
    audit = FakeAudit()
    checker = TLSChecker(scope, audit)

    with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
        checker.inspect("127.0.0.1", port=0)

    with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
        checker.inspect("127.0.0.1", port=70000)

    with pytest.raises(ValueError, match="timeout must be between 0 and 10"):
        TLSChecker(scope, audit, timeout=-1)


# -----------------------------------------------------------------------------
# Real Local Integration Tests
# -----------------------------------------------------------------------------

def test_real_local_tls_server_inspection(tmp_path):
    """Real TLS handshake against a local server: cert chain, SANs, cipher, expiry."""
    cert_path, _ = _generate_test_cert_and_key(cn="localhost", days_valid=60, sans=["localhost", "127.0.0.1"])
    port, thread, stop_event = _start_real_tls_server(cert_path)

    try:
        db_path = tmp_path / "audit.sqlite"
        audit = AuditLogger(db_path)
        scope = FakeScope(allowed_targets=["127.0.0.1"])
        memory = EpisodicMemory(db_path=tmp_path / "memory.sqlite")
        checker = TLSChecker(scope, audit, memory=memory)

        report = checker.inspect("127.0.0.1", port=port)

        assert isinstance(report, TLSReport)
        assert report.target == "127.0.0.1"
        assert report.port == port
        assert report.protocol is not None
        assert report.protocol.startswith("TLSv1.")
        assert report.cipher is not None
        assert report.cipher_bits is not None and report.cipher_bits >= 128

        # Cert assertions
        cert = report.certificate
        assert cert is not None
        assert cert.subject.get("commonName") == "localhost"
        assert cert.subject.get("organizationName") == "RedLoop Test Lab"
        assert cert.is_self_signed is True
        assert cert.is_expired is False
        assert cert.days_until_expiry is not None and cert.days_until_expiry > 0
        assert "localhost" in cert.san
        assert "127.0.0.1" in cert.san

        # Findings assertions
        finding_checks = [f.check for f in report.findings]
        assert "self-signed-certificate" in finding_checks
        assert "untrusted-certificate-authority" in finding_checks

        # Audit log assertions
        rows = audit.fetch(target="127.0.0.1", module="tls")
        assert len(rows) >= 2
        success_row = [r for r in rows if r["status"] == "success"][0]
        assert success_row["details"]["cipher"] == report.cipher
        assert success_row["details"]["protocol"] == report.protocol
        assert len(success_row["details"]["findings"]) == len(report.findings)

        # Memory store assertions
        recalled = memory.retrieve_similar("TLS certificate inspection", module="tls")
        assert len(recalled) == 1
        assert recalled[0].record.outcome == "success"

    finally:
        stop_event.set()
        thread.join(timeout=2)


def test_real_local_tls_expired_certificate_detection(tmp_path):
    """Real TLS server with an expired certificate triggers certificate-expired finding."""
    cert_path, _ = _generate_test_cert_and_key(cn="localhost", days_valid=-15)
    port, thread, stop_event = _start_real_tls_server(cert_path)

    try:
        scope = FakeScope(allowed_targets=["127.0.0.1"])
        audit = FakeAudit()
        checker = TLSChecker(scope, audit)

        report = checker.inspect("127.0.0.1", port=port)

        assert report.certificate is not None
        assert report.certificate.is_expired is True
        assert report.certificate.days_until_expiry is not None and report.certificate.days_until_expiry < 0

        finding_checks = [f.check for f in report.findings]
        assert "certificate-expired" in finding_checks
        expired_finding = [f for f in report.findings if f.check == "certificate-expired"][0]
        assert expired_finding.severity == "high"

    finally:
        stop_event.set()
        thread.join(timeout=2)


def test_real_local_tls_connection_refused():
    """Connecting to an authorized port that is closed raises TLSConnectionError and logs failed."""
    # Find a free closed port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    scope = FakeScope(allowed_targets=["127.0.0.1"])
    audit = FakeAudit()
    checker = TLSChecker(scope, audit, timeout=1.0)

    with pytest.raises(TLSConnectionError):
        checker.inspect("127.0.0.1", port=closed_port)

    assert any(e[3] == "failed" for e in audit.entries)


def test_workbench_tls_endpoint(tmp_path):
    """Test dashboard workbench /api/workbench/red/tls-check endpoint."""
    from fastapi.testclient import TestClient
    from redloop.dashboard import create_app
    from redloop.scope import sign_scope, ScopeManager
    import yaml
    from datetime import date

    cert_path, _ = _generate_test_cert_and_key(cn="localhost", days_valid=30)
    port, thread, stop_event = _start_real_tls_server(cert_path)

    try:
        secret = "test-tls-workbench-secret"
        scope_data = {
            "version": 1,
            "id": "tls-workbench-test",
            "authorized_by": "test",
            "signed_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "targets": [
                {
                    "cidr": "127.0.0.1/32",
                    "label": "loopback-tls",
                    "authorized_from": date.today().isoformat(),
                    "authorized_until": (date.today() + timedelta(days=1)).isoformat(),
                    "allowed_actions": ["tls_check"],
                    "ports": [port],
                }
            ],
        }
        scope_data["signature"] = sign_scope(scope_data, secret)
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
        scope_mgr = ScopeManager(scope_file, secret=secret)

        db_path = tmp_path / "audit.sqlite"
        app = create_app(str(db_path), scope_manager=scope_mgr)
        client = TestClient(app)

        # 1. Unauthorized port (e.g. 9999) -> 403 Forbidden
        unauth_resp = client.post(
            "/api/workbench/red/tls-check",
            json={"target": "127.0.0.1", "port": 9999},
            headers={"Origin": "http://testserver"},
        )
        assert unauth_resp.status_code == 403

        # 2. Authorized port -> 200 OK
        auth_resp = client.post(
            "/api/workbench/red/tls-check",
            json={"target": "127.0.0.1", "port": port},
            headers={"Origin": "http://testserver"},
        )
        assert auth_resp.status_code == 200
        data = auth_resp.json()
        assert data["target"] == "127.0.0.1"
        assert data["port"] == port
        assert data["certificate"]["is_self_signed"] is True

    finally:
        stop_event.set()
        thread.join(timeout=2)
