"""Tests for REDLOOP Standalone Chat (Part 3).

Verifies:
- SQLite persistence across sessions (messages, capabilities, metadata)
- Conversation rail operations (list with preview, create, rename, delete)
- Edit message with overwrite policy (truncates from edit point and re-executes)
- Regenerate response (re-runs last prompt)
- SSE streaming response endpoint (/api/chat/stream)
- Cancellation (/api/chat/conversations/{id}/cancel)
- Shared conversation state between Chat view and Copilot drawer
"""

import json
from pathlib import Path
import pytest
import yaml
from fastapi.testclient import TestClient

from redloop.chat import _ChatMessage, _ConversationStore
from redloop.dashboard import create_app
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def test_env(tmp_path):
    secret = "test-secret-32-bytes-long-padded!!"
    signed_scope_path = tmp_path / "signed_scope.yaml"

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
                "allowed_actions": ["recon", "port_scan", "nmap", "osint", "scan", "check", "assess"],
                "ports": [80, 443, 8080],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    signed_scope_path.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    scope_mgr = ScopeManager(signed_scope_path, secret)

    db_path = tmp_path / "audit.sqlite"
    app = create_app(str(db_path), scope_manager=scope_mgr)
    client = TestClient(app)

    return {
        "tmp_path": tmp_path,
        "db_path": db_path,
        "app": app,
        "client": client,
        "scope_mgr": scope_mgr,
    }


def test_sqlite_conversation_store_persistence(tmp_path):
    """Verify SQLite persistence across store re-instantiations."""
    db_file = tmp_path / "test_chat.sqlite"
    store1 = _ConversationStore(db_file)
    owner = "test-owner-token"

    cid = store1.get_or_create(owner, title="New chat")
    assert cid is not None

    # Append user turn
    pos1 = store1.append_turn(
        owner_token=owner,
        conversation_id=cid,
        role="user",
        content="What is SQL injection?",
        capability="USER",
    )
    assert pos1 == 0

    # Append assistant turn with capability and metadata
    pos2 = store1.append_turn(
        owner_token=owner,
        conversation_id=cid,
        role="assistant",
        content="SQL injection is a web security vulnerability.",
        capability="GENERAL_CHAT",
        model="auto",
        provider="groq",
        latency_ms=120.5,
        token_count=45,
        audit_event_id="evt-101",
    )
    assert pos2 == 1

    # Reload from disk using a fresh store instance
    store2 = _ConversationStore(db_file)
    conv = store2.load_conversation_dict(owner, cid)

    assert conv is not None
    assert conv["id"] == cid
    assert conv["title"] == "What is SQL injection?"  # Auto-titled from first prompt
    assert len(conv["messages"]) == 2

    user_msg = conv["messages"][0]
    assert user_msg["role"] == "user"
    assert user_msg["content"] == "What is SQL injection?"
    assert user_msg["capability"] == "USER"

    asst_msg = conv["messages"][1]
    assert asst_msg["role"] == "assistant"
    assert "SQL injection is a web security vulnerability" in asst_msg["content"]
    assert asst_msg["capability"] == "GENERAL_CHAT"
    assert asst_msg["model"] == "auto"
    assert asst_msg["provider"] == "groq"
    assert asst_msg["latency_ms"] == 120.5
    assert asst_msg["token_count"] == 45
    assert asst_msg["audit_event_id"] == "evt-101"


def test_conversation_rail_crud_api(test_env):
    """Test Create, Read, Update/Rename, and Delete of conversations via API."""
    client = test_env["client"]

    # 1. List conversations (auto-creates default or initial)
    res = client.get("/api/chat/conversations")
    assert res.status_code == 200
    convs = res.json()["conversations"]
    assert len(convs) >= 1

    # 2. Create new conversation with custom title
    res = client.post("/api/chat/conversations", json={"title": "Pentest Planning"})
    assert res.status_code == 200
    cid = res.json()["id"]
    assert cid

    # 3. Rename conversation
    res = client.post(f"/api/chat/conversations/{cid}/rename", json={"title": "Network Recon"})
    assert res.status_code == 200
    assert res.json()["title"] == "Network Recon"

    # 4. Fetch conversation details
    res = client.get(f"/api/chat/conversations/{cid}")
    assert res.status_code == 200
    assert res.json()["title"] == "Network Recon"
    assert res.json()["messages"] == []

    # 5. Delete conversation
    res = client.delete(f"/api/chat/conversations/{cid}")
    assert res.status_code == 200
    assert res.json()["ok"] is True

    # 6. Verify 404 after deletion
    res = client.get(f"/api/chat/conversations/{cid}")
    assert res.status_code == 404


def test_message_send_and_persistence(test_env):
    """Test sending a message persists user and assistant turns with capability badges."""
    client = test_env["client"]

    # Create chat
    res = client.post("/api/chat/conversations", json={"title": "General Security Query"})
    cid = res.json()["id"]

    # Send message
    res = client.post(
        "/api/chat/message",
        json={
            "message": "Explain how an XSS vulnerability works in detail.",
            "conversation_id": cid,
            "model": "auto",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "response" in data
    assert data["capability"] == "GENERAL_CHAT"

    # Verify both turns are persisted in SQLite
    res = client.get(f"/api/chat/conversations/{cid}")
    assert res.status_code == 200
    conv = res.json()
    messages = conv["messages"]
    assert len(messages) >= 2
    assert messages[0]["role"] == "user"
    assert "XSS vulnerability" in messages[0]["content"]
    assert messages[1]["role"] == "assistant"
    assert messages[1]["capability"] == "GENERAL_CHAT"
    assert messages[1]["token_count"] >= 0


def test_edit_message_overwrite_policy(test_env):
    """Verify message edit truncates subsequent messages and re-executes from edit point."""
    client = test_env["client"]

    # Create chat
    res = client.post("/api/chat/conversations", json={"title": "Edit Test"})
    cid = res.json()["id"]

    # Turn 0: user, Turn 1: assistant
    res1 = client.post(
        "/api/chat/message",
        json={"message": "First message: What is DNS?", "conversation_id": cid},
    )
    assert res1.status_code == 200

    # Turn 2: user, Turn 3: assistant
    res2 = client.post(
        "/api/chat/message",
        json={"message": "Second message: What is DHCP?", "conversation_id": cid},
    )
    assert res2.status_code == 200

    # Verify 4 messages exist (positions 0, 1, 2, 3)
    res = client.get(f"/api/chat/conversations/{cid}")
    conv = res.json()
    assert len(conv["messages"]) == 4

    # Edit position 2 (user's second message) -> should truncate position >= 2 and re-run
    res_edit = client.post(
        f"/api/chat/conversations/{cid}/messages/2/edit",
        json={"message": "Edited message: What is ARP?"},
    )
    assert res_edit.status_code == 200

    # Verify updated conversation has exactly 4 messages, with position 2 being ARP
    res = client.get(f"/api/chat/conversations/{cid}")
    conv_updated = res.json()
    msgs = conv_updated["messages"]
    assert len(msgs) == 4
    assert msgs[0]["content"] == "First message: What is DNS?"
    assert msgs[2]["content"] == "Edited message: What is ARP?"
    assert "DHCP" not in msgs[2]["content"]


def test_regenerate_response(test_env):
    """Verify regenerate re-runs the last user prompt and updates the assistant turn."""
    client = test_env["client"]

    res = client.post("/api/chat/conversations", json={"title": "Regenerate Test"})
    cid = res.json()["id"]

    res_msg = client.post(
        "/api/chat/message",
        json={"message": "Explain port 443.", "conversation_id": cid},
    )
    assert res_msg.status_code == 200

    # Regenerate response
    res_regen = client.post(f"/api/chat/conversations/{cid}/regenerate", json={})
    assert res_regen.status_code == 200
    data = res_regen.json()
    assert "response" in data
    assert data["capability"] == "GENERAL_CHAT"

    # Conversation still has exactly 2 turns
    res = client.get(f"/api/chat/conversations/{cid}")
    conv = res.json()
    assert len(conv["messages"]) == 2
    assert conv["messages"][0]["role"] == "user"
    assert conv["messages"][1]["role"] == "assistant"


def test_sse_chat_stream_endpoint(test_env):
    """Verify /api/chat/stream yields SSE chunks and finishes with done payload."""
    client = test_env["client"]

    res = client.post("/api/chat/conversations", json={"title": "Stream Test"})
    cid = res.json()["id"]

    res_stream = client.post(
        "/api/chat/stream",
        json={"message": "Explain the role of an ARP cache.", "conversation_id": cid},
    )
    assert res_stream.status_code == 200
    assert "text/event-stream" in res_stream.headers["content-type"]

    lines = res_stream.text.split("\n\n")
    events = [json.loads(line[6:]) for line in lines if line.startswith("data: ")]

    assert len(events) >= 1
    # Check that at least some chunk events arrived
    has_chunks = any("chunk" in e for e in events)
    has_done = any(e.get("done") is True for e in events)
    assert has_chunks or has_done

    # Verify conversation is persisted
    conv_res = client.get(f"/api/chat/conversations/{cid}")
    assert conv_res.status_code == 200
    assert len(conv_res.json()["messages"]) >= 2


def test_cancel_conversation_endpoint(test_env):
    """Verify /api/chat/conversations/{id}/cancel responds successfully."""
    client = test_env["client"]

    res = client.post("/api/chat/conversations/active-test-conv/cancel")
    assert res.status_code == 200
    assert res.json()["conversation_id"] == "active-test-conv"
    assert "cancelled" in res.json()


def test_shared_conversation_state_copilot_and_chat(test_env):
    """Verify full-screen Chat section and Copilot drawer read/write the same conversation."""
    client = test_env["client"]

    shared_cid = "shared-session-thread"

    # 1. Copilot drawer sends message
    res1 = client.post(
        "/api/chat/message",
        json={
            "message": "Investigate public IP 8.8.8.8 passive recon",
            "conversation_id": shared_cid,
        },
    )
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["capability"] == "OSINT_IP"

    # 2. Standalone Chat view fetches that exact conversation ID
    res2 = client.get(f"/api/chat/conversations/{shared_cid}")
    assert res2.status_code == 200
    conv = res2.json()
    assert len(conv["messages"]) == 2
    assert conv["messages"][0]["content"] == "Investigate public IP 8.8.8.8 passive recon"
    assert conv["messages"][1]["capability"] == "OSINT_IP"

    # 3. Standalone Chat sends follow-up
    res3 = client.post(
        "/api/chat/message",
        json={
            "message": "What AS number does it belong to?",
            "conversation_id": shared_cid,
        },
    )
    assert res3.status_code == 200

    # 4. Copilot drawer re-fetches and sees all 4 turns
    res4 = client.get(f"/api/chat/conversations/{shared_cid}")
    assert res4.status_code == 200
    assert len(res4.json()["messages"]) == 4
