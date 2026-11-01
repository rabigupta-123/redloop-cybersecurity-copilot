"""Real localhost integration checks; no Internet targets or image pulls."""

from __future__ import annotations

import asyncio
import shutil
import socket
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import yaml

from redloop.audit import AuditLogger
from redloop.reporting import AuditReader
from redloop.scope import ScopeManager, sign_scope
from redloop.webapp import WebAppChecker

pytestmark = pytest.mark.integration

_SCOPE_SECRET = "redloop-local-integration-test-secret"


class _LocalHTTPHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(1.0)

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, TimeoutError):
            return

    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        for name, value in self.server.response_headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)

    def log_message(self, _format, *_args):
        return


def _signed_scope(path: Path, ports: list[int]) -> ScopeManager:
    today = date.today()
    raw = {
        "version": 1,
        "id": "redloop-local-integration",
        "authorized_by": "local integration test",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "local-integration-only",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=1)).isoformat(),
                "allowed_actions": ["recon", "web_test"],
                "ports": ports,
            }
        ],
    }
    raw["signature"] = sign_scope(raw, _SCOPE_SECRET)
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return ScopeManager(path, _SCOPE_SECRET)


def _reserve_closed_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _secure_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Set-Cookie": "session=fixture; Path=/; Secure; HttpOnly; SameSite=Strict",
    }


def _request(app, method, path, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def test_real_local_authorized_workflows_and_dashboard_evidence(tmp_path):
    pytest.importorskip("nmap")
    if not shutil.which("nmap"):
        pytest.skip("Nmap executable is not installed")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHTTPHandler)
    server.daemon_threads = True
    server.response_headers = _secure_headers()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    closed_port = _reserve_closed_local_port()
    while closed_port == server.server_port:
        closed_port = _reserve_closed_local_port()

    try:
        db_path = tmp_path / "audit.sqlite"
        scope = _signed_scope(
            tmp_path / "scope.yaml",
            [server.server_port, closed_port],
        )
        audit = AuditLogger(db_path)
        from redloop.dashboard import create_app

        app = create_app(str(db_path), scope_manager=scope)

        async def execute_real_workflows():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1",
            ) as client:
                scan = await client.post(
                    "/api/workbench/red/port-scan",
                    json={
                        "target": "127.0.0.1",
                        "ports": [server.server_port, closed_port],
                    },
                )
                secure_web = await client.post(
                    "/api/workbench/red/web-check",
                    json={"url": f"http://127.0.0.1:{server.server_port}/"},
                )
                server.response_headers = {
                    "Set-Cookie": "session=fixture; Path=/",
                    "Server": "local-fixture/1.0",
                }
                insecure_web = await client.post(
                    "/api/workbench/red/web-check",
                    json={"url": f"http://127.0.0.1:{server.server_port}/"},
                )
                forensic = await client.post(
                    "/api/workbench/blue/file-triage",
                    files={
                        "sample": (
                            "benign-fixture.txt",
                            b"benign local fixture; analyst@example.test",
                        )
                    },
                )
                purple = await client.get("/api/workbench/purple/summary")
                entries = await client.get("/api/entries")
                unauthorized = await client.post(
                    "/api/workbench/red/port-scan",
                    json={"target": "127.0.0.1", "ports": [1]},
                )
                return (
                    scan,
                    secure_web,
                    insecure_web,
                    forensic,
                    purple,
                    entries,
                    unauthorized,
                )

        (
            scan_response,
            secure_response,
            insecure_response,
            forensic_response,
            purple_response,
            entries_response,
            unauthorized_response,
        ) = asyncio.run(execute_real_workflows())

        assert scan_response.status_code == 200, scan_response.text
        scan = scan_response.json()
        assert scan["scanned_ports"] == [server.server_port, closed_port]
        port_states = {
            item["port"]: item["state"] for item in scan["port_results"]
        }
        assert set(port_states) == {server.server_port, closed_port}
        assert port_states[server.server_port] == "open"
        assert port_states[closed_port] in {"closed", "filtered"}
        assert [item["port"] for item in scan["open_ports"]] == [
            server.server_port
        ]

        assert secure_response.status_code == 200, secure_response.text
        assert secure_response.json()["status_code"] == 200
        assert secure_response.json()["findings"] == []
        assert insecure_response.status_code == 200, insecure_response.text
        insecure_checks = {
            finding["check"]
            for finding in insecure_response.json()["findings"]
        }
        assert "x-frame-options" in insecure_checks
        assert "cookie-attributes" in insecure_checks
        assert "technology-disclosure" in insecure_checks
        assert "fixture" not in insecure_response.text

        assert forensic_response.status_code == 200, forensic_response.text
        forensic = forensic_response.json()
        assert forensic["profile"]["sha256"]
        assert forensic["profile"]["file_type"] == "text/plain"
        assert forensic["iocs"]["emails"] == ["analyst@example.test"]

        assert unauthorized_response.status_code == 403
        assert purple_response.status_code == 200
        purple = purple_response.json()
        assert purple["external_detection"] is False
        assert purple["correlations"]
        correlation = purple["correlations"][0]
        assert correlation["classification"] == "DERIVED"
        assert correlation["target"] == "127.0.0.1"
        assert {item["module"] for item in correlation["evidence"]} >= {
            "nmap",
            "webapp",
        }
        assert entries_response.status_code == 200
        assert any(
            item["module"] == "forensics"
            and item["status"] == "success"
            for item in entries_response.json()["entries"]
        )

        audit_rows = audit.fetch(limit=100)
        assert any(
            row["module"] == "nmap"
            and row["status"] == "success"
            and row["details"].get("port_results")
            for row in audit_rows
        )
        assert any(
            row["module"] == "webapp"
            and row["status"] == "success"
            and row["details"].get("findings")
            for row in audit_rows
        )
        assert any(
            row["module"] == "nmap" and row["status"] == "blocked"
            for row in audit_rows
        )

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_local_ollama_response_is_recorded_and_visible(tmp_path, monkeypatch):
    try:
        local_tags = httpx.get(
            "http://127.0.0.1:11434/api/tags",
            timeout=2,
        )
    except httpx.HTTPError as exc:
        pytest.skip(f"Local Ollama is unavailable: {type(exc).__name__}")
    if not local_tags.is_success:
        pytest.skip("Local Ollama model catalog is unavailable")
    local_models = local_tags.json().get("models", [])
    chat_models = [
        item for item in local_models
        if "embed" not in item.get("name", "").casefold()
    ]
    if not chat_models:
        pytest.skip("No local Ollama chat model is available")
    model_name = min(
        chat_models,
        key=lambda item: int(item.get("size", 0)),
    )["name"]
    warmup = httpx.post(
        "http://127.0.0.1:11434/api/chat",
        json={
            "model": model_name,
            "messages": [
                {"role": "user", "content": "Reply with one word: ready."}
            ],
            "stream": False,
            "keep_alive": "5m",
            "options": {"num_ctx": 1024, "num_predict": 8},
        },
        timeout=120,
    )
    if not warmup.is_success:
        body = warmup.text or ""
        if "out-of-memory" in body or "failed to allocate" in body:
            pytest.skip(
                "Local Ollama runtime cannot allocate the model KV cache in this "
                f"environment: {body[:200]}"
            )
    assert warmup.is_success, warmup.text[:500]

    import redloop.chat as chat
    from redloop.dashboard import create_app
    from redloop.llm import LLMClient, LLMSettings
    from redloop.performance import TokenUsageStore

    db_path = tmp_path / "audit.sqlite"
    local_llm = LLMClient(
        LLMSettings(
            _env_file=None,
            llm_provider="ollama",
            llm_model=model_name,
            ollama_base_url="http://127.0.0.1:11434",
        )
    )
    original_acomplete = local_llm.acomplete

    async def bounded_acomplete(system_prompt, user_prompt, **kwargs):
        kwargs["max_tokens"] = 8
        kwargs["timeout"] = 120
        return await original_acomplete(system_prompt, user_prompt, **kwargs)

    monkeypatch.setattr(local_llm, "acomplete", bounded_acomplete)
    monkeypatch.setattr(chat, "get_llm", lambda: local_llm)
    app = create_app(str(db_path))

    first_page = _request(app, "GET", "/chat")
    cookie = first_page.cookies.get(chat.SESSION_COOKIE)
    assert first_page.status_code == 200
    assert cookie
    response = _request(
        app,
        "POST",
        "/chat",
        cookies={chat.SESSION_COOKIE: cookie},
        headers={"Origin": "http://127.0.0.1"},
        data={
            "message": "Reply with one word: ready.",
            "mode": "report",
            "model": f"ollama|{model_name}",
            "effort": "auto",
        },
    )

    assert response.status_code == 200, response.text
    usage = TokenUsageStore(f"{db_path}.chats.sqlite").get_summary()
    assert usage["requests"] == 1
    assert usage["recent"][0]["provider"] == "ollama"
    assert usage["recent"][0]["model"] == f"ollama/{model_name}"
    assert isinstance(usage["recent"][0]["usage_reported"], bool)
    performance = _request(
        app,
        "GET",
        "/api/performance/summary",
    ).json()
    assert performance["token_usage"]["requests"] == 1
    assert any(
        row["module"] == "chat"
        and row["status"] == "success"
        and row["details"].get("provider") == "ollama"
        for row in AuditReader(db_path).entries()[0]
    )


def test_real_docker_sandbox_execution_isolated_and_cleaned_up():
    docker = pytest.importorskip("docker")
    from docker.errors import DockerException, ImageNotFound, NotFound

    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        pytest.skip(f"Local Docker daemon unavailable: {type(exc).__name__}")

    from redloop.config import settings
    from redloop.sandbox import DockerSandbox

    try:
        client.images.get(settings.sandbox_image)
    except ImageNotFound:
        pytest.skip("Sandbox image is not cached locally; test will not pull images")

    sandbox = DockerSandbox(timeout=10)
    python_result = sandbox.run("print('sandbox-python-ok')")
    shell_result = sandbox.run("printf 'sandbox-shell-ok\\n'", language="bash")
    assert python_result.success
    assert "sandbox-python-ok" in python_result.stdout
    assert shell_result.success
    assert "sandbox-shell-ok" in shell_result.stdout

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as host_listener:
        host_listener.bind(("127.0.0.1", 0))
        host_listener.listen(1)
        host_port = host_listener.getsockname()[1]
        network_result = sandbox.run(
            "import socket\n"
            f"client = socket.create_connection(('127.0.0.1', {host_port}), timeout=1)\n"
            "client.close()\n"
            "raise SystemExit('unexpected host connection')\n"
        )
        assert not network_result.success

    with pytest.raises(ValueError, match="networking is disabled"):
        sandbox.run("pass", allowed_network="bridge")
    with pytest.raises(ValueError, match="networking is disabled"):
        DockerSandbox(network="host")
    with pytest.raises(ValueError, match="environment variables are disabled"):
        sandbox.run("pass", env={"TEST_SECRET": "must-not-be-injected"})

    timed_out = DockerSandbox(timeout=1).run(
        "import time\ntime.sleep(10)\n"
    )
    assert not timed_out.success
    assert "timed out" in timed_out.stderr.casefold()

    for result in (python_result, shell_result, network_result, timed_out):
        with pytest.raises(NotFound):
            client.containers.get(result.container_id)
    client.close()


def test_real_local_reliability_ladder_with_3_listeners(tmp_path):
    """3-listener integration regression test: simulate Nmap returning filtered
    while real OS sockets are open, proving the reliability ladder escalates,
    logs every step in the audit trail, enforces the 4-step cap, and never
    touches unauthorized ports."""
    from redloop.recon import NmapScanner, PortResult
    from redloop.scope import UnauthorizedTargetError

    # 1. Start 3 real local listeners
    servers = [
        ThreadingHTTPServer(("127.0.0.1", 0), _LocalHTTPHandler)
        for _ in range(3)
    ]
    for s in servers:
        s.daemon_threads = True
        s.response_headers = {"Content-Type": "text/plain"}
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()

    ports = [s.server_port for s in servers]

    try:
        # Verify direct sockets are genuinely open
        for p in ports:
            with socket.create_connection(("127.0.0.1", p), timeout=1.0) as sock:
                assert sock is not None

        db_path = tmp_path / "audit.sqlite"
        scope = _signed_scope(tmp_path / "scope.yaml", ports)
        audit = AuditLogger(db_path)

        # Simulate Nmap probes returning 'filtered' for all 3 ports
        class FakeHost:
            def __init__(self, data):
                self.data = data

            def all_protocols(self):
                return list(self.data)

            def __getitem__(self, protocol):
                return self.data[protocol]

        class FilteredNmapBackend:
            def __init__(self):
                self.calls = []

            def scan(self, hosts, arguments, timeout=0):
                self.calls.append((hosts, arguments))
                return {
                    "nmap": {
                        "scaninfo": {
                            "tcp": {"services": ",".join(str(p) for p in ports)}
                        }
                    }
                }

            def all_hosts(self):
                return ["127.0.0.1"]

            def __getitem__(self, target):
                assert target == "127.0.0.1"
                return FakeHost({
                    "tcp": {
                        p: {"state": "filtered", "name": "unknown", "version": ""}
                        for p in ports
                    }
                })

        backend = FilteredNmapBackend()
        # raw_socket_fn=None so it uses real socket.create_connection to the 3 real listeners!
        scanner = NmapScanner(scope=scope, audit=audit, scanner=backend)

        result = scanner.quick_scan("127.0.0.1", ports)

        # Confirm all 3 ports escalated to "open (nmap-unreliable-on-this-host)"
        assert len(result.port_results) == 3
        for item in result.port_results:
            assert item.state == "open (nmap-unreliable-on-this-host)"
            assert item.confidence == "cross-checked, Nmap environment-limited"
            assert item.escalation is not None
            assert item.escalation["final_state"] == "open"
            assert item.escalation["final_source"] == "raw_socket_crosscheck"
            # Exactly 4 ladder attempts: -Pn, --disable-arp-ping, --source-port, raw_socket_crosscheck (plus initial -sT default)
            attempts = item.escalation["attempts"]
            assert len(attempts) == 5
            techs = [a["technique"] for a in attempts]
            assert techs == [
                "-sT default",
                "-Pn",
                "--disable-arp-ping",
                "-sT with explicit --source-port",
                "raw_socket_crosscheck",
            ]

        assert [p.port for p in result.open_ports] == ports

        # Confirm audit record in database logged the full escalation path
        audit_rows = audit.fetch(limit=10)
        recon_entry = [r for r in audit_rows if r["module"] == "nmap" and r["status"] == "success"][0]
        assert "escalations" in recon_entry["details"]
        assert len(recon_entry["details"]["escalations"]) == 3
        for esc in recon_entry["details"]["escalations"]:
            assert esc["final_state"] == "open"
            assert esc["final_source"] == "raw_socket_crosscheck"
            assert esc["confidence"] == "cross-checked, Nmap environment-limited"
            assert len(esc["attempts"]) == 5

        # Confirm scope boundary: ladder NEVER touches unauthorized port
        unauthorized_item = PortResult(port=9999, protocol="tcp", state="filtered")
        with pytest.raises(UnauthorizedTargetError):
            scanner._run_reliability_ladder("127.0.0.1", unauthorized_item)

        # Confirm 4-step cap: never loops more than 4 retry steps
        class DisagreeingBackend(FilteredNmapBackend):
            def __init__(self):
                super().__init__()
                self.count = 0

            def scan(self, hosts, arguments, timeout=0):
                self.count += 1
                return super().scan(hosts, arguments, timeout)

            def __getitem__(self, target):
                st = "open" if self.count % 2 == 0 else "filtered"
                return FakeHost({"tcp": {ports[0]: {"state": st, "name": "test", "version": ""}}})

        disagree_scanner = NmapScanner(
            scope=scope,
            audit=audit,
            scanner=DisagreeingBackend(),
            raw_socket_fn=lambda t, p: ("filtered", None, None),
        )
        esc = disagree_scanner._run_reliability_ladder(
            "127.0.0.1", PortResult(port=ports[0], protocol="tcp", state="filtered")
        )
        retry_steps = [a for a in esc["attempts"] if a["technique"] != "-sT default"]
        assert len(retry_steps) == 4

    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
