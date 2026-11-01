import asyncio

import httpx

from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from redloop.workbench import WORKBENCH_SCRIPT_CSP_HASH


def _request(app, method, path, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def test_workbench_page_has_real_workflows_and_csp_allows_its_script(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))

    response = _request(app, "GET", "/workbench")

    assert response.status_code == 200
    assert "web metadata check" in response.text.casefold()
    assert "Static hash" in response.text
    assert "audit evidence summary" in response.text
    assert "not detections or siem correlation" in response.text.casefold()
    assert "fonts.googleapis.com" not in response.text
    assert "https://fonts.googleapis.com" not in response.headers[
        "Content-Security-Policy"
    ]
    assert "demo data" not in response.text
    policy = response.headers["Content-Security-Policy"]
    assert f"'sha256-{WORKBENCH_SCRIPT_CSP_HASH}'" in policy


def test_static_triage_endpoint_analyzes_upload_and_records_audit(tmp_path):
    db_path = tmp_path / "audit.sqlite"
    app = create_app(str(db_path))

    response = _request(
        app,
        "POST",
        "/api/workbench/blue/file-triage",
        files={"sample": ("sample.txt", b"ioc https://example.test/path")},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["profile"]["filename"] == "sample.txt"
    assert report["iocs"]["urls"] == ["https://example.test/path"]
    audit_rows = AuditLogger(db_path).fetch(module="forensics")
    assert len(audit_rows) == 1
    assert audit_rows[0]["status"] == "success"


def test_purple_summary_groups_real_audit_events_without_claiming_siem_detection(tmp_path):
    db_path = tmp_path / "audit.sqlite"
    audit = AuditLogger(db_path)
    audit.log("127.0.0.1", "web_test", "webapp", "success", {"findings_count": 2})
    audit.log("sha256:sample", "static_analysis", "forensics", "success")

    response = _request(
        create_app(str(db_path)),
        "GET",
        "/api/workbench/purple/summary",
    )

    assert response.status_code == 200
    result = response.json()
    assert result["team_activity"]["red"]["success"] == 1
    assert result["team_activity"]["blue"]["success"] == 1
    assert result["source"] == "RedLoop local audit database"
    assert result["evidence_type"] == "observed_local_audit_events"
    assert result["external_detection"] is False
    assert result["correlations"] == []


def test_purple_summary_reproducibly_groups_local_success_evidence(tmp_path):
    db_path = tmp_path / "audit.sqlite"
    audit = AuditLogger(db_path)
    recon_id = audit.log(
        "127.0.0.1",
        "recon",
        "nmap",
        "success",
        {"port_results": [{"port": 8080, "state": "open"}]},
    )
    web_id = audit.log(
        "127.0.0.1",
        "web_test",
        "webapp",
        "success",
        {
            "status_code": 200,
            "findings": [{"check": "x-frame-options", "severity": "low"}],
        },
    )

    response = _request(
        create_app(str(db_path)),
        "GET",
        "/api/workbench/purple/summary",
    )

    assert response.status_code == 200
    correlation = response.json()["correlations"][0]
    assert correlation["classification"] == "DERIVED"
    assert correlation["kind"] == "same_target_temporal_group"
    assert correlation["target"] == "127.0.0.1"
    assert correlation["evidence_record_ids"] == [recon_id, web_id]
    assert [item["module"] for item in correlation["evidence"]] == [
        "nmap",
        "webapp",
    ]


def test_red_workflow_requires_verified_scope_and_blocks_remote_targets(tmp_path):
    unavailable = _request(
        create_app(str(tmp_path / "no-scope.sqlite")),
        "POST",
        "/api/workbench/red/web-check",
        json={"url": "http://127.0.0.1/"},
    )
    assert unavailable.status_code == 503

    class FakeScope:
        def check(self, target, action, port=None):
            return type("ScopeEntry", (), {"label": "test"})()

    blocked = _request(
        create_app(str(tmp_path / "scope.sqlite"), scope_manager=FakeScope()),
        "POST",
        "/api/workbench/red/web-check",
        json={"url": "http://192.0.2.10/"},
    )
    assert blocked.status_code == 400
    assert "loopback" in blocked.json()["detail"]

    remote_scan = _request(
        create_app(str(tmp_path / "scan-scope.sqlite"), scope_manager=FakeScope()),
        "POST",
        "/api/workbench/red/port-scan",
        json={"target": "192.0.2.10", "ports": [80]},
    )
    assert remote_scan.status_code == 400
    assert "loopback" in remote_scan.json()["detail"]


def test_workbench_rejects_cross_origin_state_changes(tmp_path):
    response = _request(
        create_app(str(tmp_path / "audit.sqlite")),
        "POST",
        "/api/workbench/blue/file-triage",
        headers={"Origin": "https://attacker.invalid"},
        files={"sample": ("sample.txt", b"contents")},
    )

    assert response.status_code == 403
