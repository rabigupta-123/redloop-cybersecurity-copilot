"""Regression tests for hardening items 7-13.

Covers the real provider probe, vault-backed key resolution, RAG grounding,
chat history/attachment context, honest streaming, workbench CSP embedding,
and the unified palette tokens.
"""

from __future__ import annotations

import urllib.error
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from redloop.assessment.orchestrator import Task, TaskOrchestrator
from redloop.dashboard import create_app
from redloop.provider_gateway import ProviderGateway, ProviderKeyStore, ProviderStatus
from redloop.scope import ScopeManager, sign_scope
from redloop.unified_app import UNIFIED_CSS
from redloop.workbench import (
    WORKBENCH_SCRIPT_CSP_HASH,
    _WORKBENCH_SCRIPT,
)


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    def read(self, _size: int = -1) -> bytes:
        return b'{"ok":true}'

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.fixture
def gateway(tmp_path):
    store = ProviderKeyStore(
        storage_dir=str(tmp_path), master_secret="hardening_test_secret_123"
    )
    store.set_key("groq", "gsk_live_probe_key_123456", user_id="default")
    return ProviderGateway(key_store=store)


def test_provider_probe_uses_real_network_call(gateway, monkeypatch):
    calls = []

    def fake_urlopen(request, timeout=0):
        calls.append((request.full_url, timeout))
        return _FakeResponse(200)

    monkeypatch.setattr("redloop.provider_gateway.urllib.request.urlopen", fake_urlopen)
    result = gateway.test_provider("groq")

    assert result["success"] is True
    assert result["status"] == ProviderStatus.INFERENCE_READY.value
    assert calls and calls[0][0].endswith("/chat/completions")
    assert result["latency_ms"] < 5000
    assert result["tool_calling_verified"] is False


def test_provider_probe_reports_auth_failure(gateway, monkeypatch):
    def fake_urlopen(request, timeout=0):
        raise urllib.error.HTTPError(
            request.full_url, 401, "unauthorized", None, None
        )

    monkeypatch.setattr("redloop.provider_gateway.urllib.request.urlopen", fake_urlopen)
    result = gateway.test_provider("groq")

    assert result["success"] is False
    assert result["status"] == ProviderStatus.AUTH_FAILED.value
    assert "gsk_live_probe_key_123456" not in result["error"]


@pytest.mark.asyncio
async def test_general_chat_receives_history_attachments_and_rag(tmp_path, monkeypatch):
    orch = TaskOrchestrator(scope_manager=None, audit_db=str(tmp_path / "a.sqlite"))
    captured = {}

    async def fake_llm(**kwargs):
        captured.update(kwargs)
        return (
            {"text": "grounded answer", "provider": "offline", "model": "offline"},
            {"fallback_used": False},
        )

    class FakeRag:
        def build_rag_context(self, query, top_k=3):
            return "<untrusted_knowledge_reference>KB_MARKER</untrusted_knowledge_reference>"

    monkeypatch.setattr(orch, "_execute_llm_with_fallback", fake_llm)
    monkeypatch.setattr("redloop.rag_engine.get_rag_engine", lambda: FakeRag())

    task = Task(
        id="task-history",
        conversation_id="conv-history",
        type="general_chat",
        target="",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    result = await orch._handle_general_chat(
        prompt="What did we discuss?",
        task=task,
        model_choice="auto",
        effort_choice="auto",
        token_usage_store=None,
        start_time=0.0,
        history=[
            {"role": "user", "content": "earlier user turn"},
            {"role": "assistant", "content": "earlier assistant turn"},
        ],
        attachment_context="ATTACHMENT_MARKER",
    )

    assert result["response"] == "grounded answer"
    assert "KB_MARKER" in captured["system_prompt"]
    assert "earlier user turn" in captured["user_prompt"]
    assert "earlier assistant turn" in captured["user_prompt"]
    assert "ATTACHMENT_MARKER" in captured["user_prompt"]


def test_llm_uses_key_saved_in_vault(tmp_path, monkeypatch):
    from redloop.llm import LLMClient, LLMSettings, Provider

    store = ProviderKeyStore(
        storage_dir=str(tmp_path), master_secret="vault_llm_secret_456"
    )
    store.set_key("gemini", "vault_gemini_key_789", user_id="default")
    gateway = ProviderGateway(key_store=store)
    monkeypatch.setattr(
        "redloop.provider_gateway.get_provider_gateway", lambda: gateway
    )

    client = LLMClient(LLMSettings(_env_file=None, gemini_api_key=None))
    assert client._api_key(Provider.GEMINI) == "vault_gemini_key_789"


def test_workbench_embeds_script_and_matching_csp_hash(tmp_path):
    secret = "test-secret-32-bytes-long-padded!!"
    scope_path = tmp_path / "scope.yaml"
    scope_data = {
        "version": "1.0",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Localhost",
                "authorized_from": "2020-01-01T00:00:00Z",
                "authorized_until": "2099-01-01T00:00:00Z",
                "allowed_actions": ["scan", "check", "assess"],
                "ports": [80, 443],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_path.write_text(__import__("yaml").safe_dump(scope_data), encoding="utf-8")

    app = create_app(
        str(tmp_path / "audit.sqlite"),
        scope_manager=ScopeManager(scope_path, secret),
    )
    client = TestClient(app, base_url="http://127.0.0.1")
    res = client.get("/workbench")
    assert res.status_code == 200
    assert _WORKBENCH_SCRIPT in res.text
    assert "{script_content}" not in res.text
    assert f"sha256-{WORKBENCH_SCRIPT_CSP_HASH}" in res.text


def test_palette_has_single_source_of_truth():
    for token in (
        "--bg: #0b0b10",
        "--surface: #121218",
        "--surface-2: #17171f",
        "--surface-elevated: #1b1b24",
        "--accent: #f97316",
        "--accent-cyber: #2563eb",
    ):
        assert token in UNIFIED_CSS
