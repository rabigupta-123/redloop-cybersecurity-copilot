import asyncio
import json
import sqlite3
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest

from redloop.reporting import AuditReader, AuditReportGenerator
from redloop.scope import ScopeManager, sign_scope


def make_audit_db(path, rows):
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                action TEXT NOT NULL,
                module TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                scope_entry TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def test_reader_filters_exact_target_and_parses_json(tmp_path):
    db = tmp_path / "audit.sqlite"
    make_audit_db(
        db,
        [
            (1, "2026-10-01T00:00:00Z", "alpha", "inspect", "web", "success", '{"ok":true}', None),
            (2, "2026-10-02T00:00:00Z", "alphabet", "inspect", "web", "blocked", '{"reason":"scope"}', None),
        ],
    )

    rows, truncated = AuditReader(db).entries(target="alpha", limit=10)

    assert len(rows) == 1
    assert rows[0]["target"] == "alpha"
    assert rows[0]["details"] == {"ok": True}
    assert not truncated


def test_report_contains_activity_summary_and_blocked_section(tmp_path):
    db = tmp_path / "audit.sqlite"
    make_audit_db(
        db,
        [
            (1, "2026-10-01T00:00:00Z", "lab-1", "inspect", "webapp", "success", '{"findings_count":2}', "lab"),
            (2, "2026-10-02T00:00:00Z", "lab-1", "recon", "executor", "blocked", '{"reason":"denied"}', None),
        ],
    )

    path = AuditReportGenerator(db, tmp_path / "reports").generate("lab-1")
    report = path.read_text(encoding="utf-8")

    assert path.exists()
    assert "Records included:** 2" in report
    assert "successful action is not necessarily a security finding" in report
    assert "## Blocked activity" in report
    assert "recon was blocked" in report
    assert '"findings_count": 2' in report


def test_report_escapes_markdown_in_target_and_fence_in_details(tmp_path):
    db = tmp_path / "audit.sqlite"
    details = json.dumps({"value": "```malicious markdown"})
    make_audit_db(
        db,
        [(1, "2026-10-01T00:00:00Z", "[target]", "inspect", "web", "success", details, None)],
    )

    path = AuditReportGenerator(db, tmp_path / "reports").generate("[target]")
    report = path.read_text(encoding="utf-8")

    assert r"\[target\]" in report
    assert report.count("```") == 2
    assert "` ` `" in report


def test_default_filename_is_safe_for_path_like_target(tmp_path):
    db = tmp_path / "audit.sqlite"
    make_audit_db(db, [])

    path = AuditReportGenerator(db, tmp_path / "reports").generate("../../target/name")

    assert path.parent == tmp_path / "reports"
    assert ".." not in path.name


def test_reader_rejects_excessive_limit(tmp_path):
    with pytest.raises(ValueError, match="limit"):
        AuditReader(tmp_path / "audit.sqlite").entries(limit=5_001)


def test_missing_database_returns_empty_results(tmp_path):
    reader = AuditReader(tmp_path / "absent.sqlite")

    assert reader.entries() == ([], False)
    assert reader.targets() == []


def test_dashboard_html_escapes_audit_values(tmp_path):
    pytest.importorskip("fastapi")
    from redloop.dashboard import create_app

    db = tmp_path / "audit.sqlite"
    make_audit_db(
        db,
        [
            (
                1,
                "2026-10-01T00:00:00Z",
                "<script>alert(1)</script>",
                "inspect",
                "webapp",
                "success",
                json.dumps({"note": "</pre><script>alert(2)</script>"}),
                None,
            )
        ],
    )
    async def request_dashboard():
        transport = httpx.ASGITransport(app=create_app(str(db)))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get("/")

    response = asyncio.run(request_dashboard())

    assert response.status_code == 200
    assert 'id="overview-title"' in response.text
    assert "Total Alerts" in response.text
    assert "Active target" in response.text
    assert 'class="badge badge-success">success</span>' in response.text
    assert "prefers-reduced-motion: reduce" in response.text
    assert "color-scheme: dark" in response.text
    assert "--bg: #0b0b10" in response.text
    assert "--accent: #f97316" in response.text
    assert 'aria-label="Primary navigation"' in response.text
    assert 'href="/chat"' in response.text
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "Content-Security-Policy" in response.headers


def test_dashboard_api_is_read_only_and_filters_target(tmp_path):
    pytest.importorskip("fastapi")
    from redloop.dashboard import create_app

    db = tmp_path / "audit.sqlite"
    make_audit_db(
        db,
        [
            (1, "2026-10-01T00:00:00Z", "alpha", "inspect", "webapp", "success", "{}", None),
            (2, "2026-10-02T00:00:00Z", "beta", "inspect", "webapp", "success", "{}", None),
            (3, "2026-10-03T00:00:00Z", "alpha", "recon", "nmap", "success", "{}", None),
        ],
    )
    async def request_entries():
        transport = httpx.ASGITransport(app=create_app(str(db)))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get("/api/entries", params={"target": "alpha"})

    response = asyncio.run(request_entries())

    assert response.status_code == 200
    assert {row["target"] for row in response.json()["entries"]} == {"alpha"}

    async def request_recon():
        transport = httpx.ASGITransport(app=create_app(str(db)))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get("/api/entries", params={"module": "recon"})

    recon_response = asyncio.run(request_recon())
    assert [row["module"] for row in recon_response.json()["entries"]] == ["nmap"]
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 3


def test_dashboard_scope_banner_uses_verified_scope_data(tmp_path):
    pytest.importorskip("fastapi")
    from redloop.dashboard import create_app

    db = tmp_path / "audit.sqlite"
    make_audit_db(
        db,
        [
            (
                1,
                "2026-10-21T12:00:00Z",
                "127.0.0.1",
                "recon",
                "nmap",
                "success",
                '{"open_ports":1}',
                "loopback",
            )
        ],
    )
    scope_path = tmp_path / "scope.yaml"
    authorized_from = date.today()
    authorized_until = authorized_from + timedelta(days=30)
    scope = {
        "version": 1,
        "id": "test",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat(),
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback-lab",
                "authorized_from": authorized_from.isoformat(),
                "authorized_until": authorized_until.isoformat(),
                "allowed_actions": ["recon", "web_test"],
            }
        ],
    }
    secret = "test-secret"
    scope["signature"] = sign_scope(scope, secret)
    import yaml

    scope_path.write_text(yaml.safe_dump(scope), encoding="utf-8")
    scope_manager = ScopeManager(scope_path, secret)

    async def request_dashboard():
        transport = httpx.ASGITransport(
            app=create_app(str(db), scope_manager=scope_manager)
        )
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get("/")

    response = asyncio.run(request_dashboard())

    assert response.status_code == 200
    assert (
        f"{authorized_from.isoformat()} → {authorized_until.isoformat()}"
        in response.text
    )
    assert "recon, web_test" in response.text
    assert ">In scope</span>" in response.text
    assert "Signature verified" in response.text
    assert ">1</div><div class=\"delta flat\">1 recon</div>" in response.text
