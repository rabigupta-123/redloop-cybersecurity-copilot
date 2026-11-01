import asyncio

import httpx

from redloop.audit import AuditLogger
from redloop.dashboard import create_app


def _request(app, method, path, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def test_checkpoint_endpoint_requires_explicit_creation_and_verifies(tmp_path):
    db_path = tmp_path / "audit.sqlite"
    app = create_app(str(db_path))

    empty = _request(app, "POST", "/api/audit/checkpoint")
    assert empty.status_code == 409

    AuditLogger(db_path).success("local", "seed_event", "test")
    created = _request(app, "POST", "/api/audit/checkpoint")
    assert created.status_code == 200
    assert created.json()["created"] is True
    assert created.json()["status"] == "CHECKPOINT_VALID"

    verified = _request(app, "GET", "/api/audit/checkpoint")
    assert verified.status_code == 200
    assert verified.json()["status"] == "CHECKPOINT_VALID"
    assert verified.json()["database_independent"] is True

    again = _request(app, "POST", "/api/audit/checkpoint")
    assert again.status_code == 200
    assert again.json()["created"] is False


def test_virustotal_invalid_indicator_is_labeled_not_clean(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "false")
    app = create_app(str(tmp_path / "audit.sqlite"))

    response = _request(
        app,
        "POST",
        "/api/threat-intel/virustotal",
        json={"indicator": "not-a-hash", "indicator_type": "file"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "INVALID_INPUT"
    assert payload["live"] is False
    assert payload["evidence_valid"] is True


def test_email_footprint_defaults_to_no_live_lookups(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))

    response = _request(
        app,
        "POST",
        "/api/osint/email/footprint",
        json={"email": "analyst@example.com"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["network_enabled"] is False
    assert payload["classification"] == "NOT_PUBLICLY_VERIFIABLE"
    assert any("Live external lookups are disabled" in item for item in payload["limitations"])
    assert payload["observations"][0]["status"] == "NOT_CHECKED"


def test_identity_observation_and_analyst_review_round_trip(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))

    added = _request(
        app,
        "POST",
        "/api/identity/observations",
        json={
            "entity_type": "email",
            "value": "analyst@example.com",
            "source": "manual",
            "method": "operator_paste",
        },
    )
    assert added.status_code == 200
    payload = added.json()
    cluster_id = payload["clusters"][0]["cluster_id"]
    assert payload["clusters"][0]["classification"] == "UNVERIFIED"
    assert payload["observation"]["evidence_valid"] is True

    reviewed = _request(
        app,
        "POST",
        f"/api/identity/clusters/{cluster_id}/review",
        json={"decision": "CONFIRM", "analyst": "alice", "note": "verified manually"},
    )
    assert reviewed.status_code == 200
    result = reviewed.json()
    assert result["review_status"] == "CONFIRMED"
    assert result["classification"] == "CONFIRMED_PUBLIC_ASSOCIATION"
    assert result["reviews"][0]["analyst"] == "alice"

    reviews = _request(app, "GET", f"/api/identity/reviews?cluster_id={cluster_id}")
    assert reviews.status_code == 200
    assert len(reviews.json()["reviews"]) == 1
    assert len(AuditLogger(tmp_path / "audit.sqlite").fetch(module="identity")) >= 2


def test_identity_review_rejects_missing_cluster(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))
    response = _request(
        app,
        "POST",
        "/api/identity/clusters/missing/review",
        json={"decision": "CONFIRM", "analyst": "alice"},
    )
    assert response.status_code == 404


def test_dashboard_exposes_new_workspaces_and_csp(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))
    response = _request(app, "GET", "/")
    assert response.status_code == 200
    html = response.text
    for marker in (
        'id="section-email-footprint"',
        'id="section-threat-intel"',
        'id="section-identity"',
        'id="email-footprint-input"',
        'id="vt-indicator-input"',
        'id="identity-clusters"',
        'id="audit-checkpoint-status"',
        'data-section="threat-intel"',
        'data-section="identity"',
    ):
        assert marker in html
    csp = response.headers["Content-Security-Policy"]
    assert "script-src" in csp
    assert "https://www.virustotal.com" not in csp
