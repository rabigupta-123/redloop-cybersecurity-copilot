import asyncio

import httpx

from redloop.llm import LLMSettings, Provider
from redloop.performance import metrics_collector


def make_client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1",
    )


class ChatLLM:
    def __init__(self):
        self.settings = LLMSettings(_env_file=None, llm_provider="ollama")
        self.default_provider = Provider.OLLAMA
        self.calls = []

    def is_provider_configured(self, provider):
        return provider == Provider.OLLAMA

    def complete(self, _system, prompt, **kwargs):
        self.calls.append(prompt)
        return {
            "text": f"Reply to: {prompt.splitlines()[-1]}",
            "provider": "ollama",
            "elapsed_seconds": 0.01,
        }


def test_chat_conversations_persist_switch_and_start_separately(tmp_path, monkeypatch):
    import redloop.chat as chat
    from redloop.dashboard import create_app

    monkeypatch.setattr(chat, "get_llm", ChatLLM)
    db_path = str(tmp_path / "audit.sqlite")
    initial_query_count = metrics_collector.get_summary()["total_queries"]

    async def run():
        async with make_client(create_app(db_path)) as client:
            await client.get("/chat")
            first = await client.post(
                "/chat",
                data={"message": "first topic", "mode": "general"},
                headers={"Origin": "http://127.0.0.1"},
            )
            assert first.status_code == 200
            first_list = await client.get("/api/chat/conversations")
            first_conversation = first_list.json()["conversations"][0]

            new_response = await client.post(
                "/api/chat/conversations",
                headers={"Origin": "http://127.0.0.1"},
            )
            assert new_response.status_code == 200
            second_id = new_response.json()["id"]
            second_page = await client.get(f"/chat?conversation={second_id}")
            # The prior conversation remains visible in the sidebar, not in this
            # conversation's message transcript.
            transcript = second_page.text.split(
                '<div class="conversation" id="conversation"', 1
            )[1].split(
                '</div>\n      <button class="scroll-bottom"', 1
            )[0]
            assert "first topic" not in transcript

            second = await client.post(
                "/chat",
                data={
                    "message": "second topic",
                    "mode": "general",
                    "conversation_id": second_id,
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            assert second.status_code == 200

            switched = await client.get(
                f"/chat?conversation={first_conversation['id']}"
            )
            return (
                first_conversation,
                second_id,
                first,
                switched,
                client.cookies.get(chat.SESSION_COOKIE),
            )

    (
        first_conversation,
        second_id,
        first_response,
        switched,
        browser_token,
    ) = asyncio.run(run())

    assert "first topic" in first_response.text
    assert "second topic" not in first_response.text
    assert "first topic" in switched.text
    assert "Reply to:" in switched.text
    assert first_conversation["title"] == "first topic"
    assert second_id != first_conversation["id"]
    assert metrics_collector.get_summary()["total_queries"] == initial_query_count + 2

    async def after_restart():
        async with make_client(create_app(db_path)) as client:
            client.cookies.set(chat.SESSION_COOKIE, browser_token)
            page = await client.get(
                f"/chat?conversation={first_conversation['id']}"
            )
            listing = await client.get("/api/chat/conversations")
            return page, listing

    restarted_page, restarted_list = asyncio.run(after_restart())
    assert restarted_page.status_code == 200
    assert "first topic" in restarted_page.text
    assert len(restarted_list.json()["conversations"]) == 2


def test_stop_cancels_async_provider_request_and_does_not_save_partial_turn(
    tmp_path, monkeypatch
):
    import redloop.chat as chat
    from redloop.dashboard import create_app

    class CancellableLLM(ChatLLM):
        def __init__(self):
            super().__init__()
            self.started = asyncio.Event()
            self.cancelled = False

        async def acomplete(self, *_args, **_kwargs):
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise

    llm = CancellableLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(
            create_app(str(tmp_path / "audit.sqlite"))
        ) as client:
            await client.get("/chat")
            conversations = (
                await client.get("/api/chat/conversations")
            ).json()["conversations"]
            conversation_id = conversations[0]["id"]
            task = asyncio.create_task(
                client.post(
                    "/chat",
                    data={
                        "message": "stop this",
                        "mode": "general",
                        "conversation_id": conversation_id,
                        "generation_id": "generation-1",
                    },
                    headers={"Origin": "http://127.0.0.1"},
                )
            )
            await asyncio.wait_for(llm.started.wait(), timeout=2)
            stopped = await client.post(
                "/api/chat/generations/generation-1/stop",
                headers={"Origin": "http://127.0.0.1"},
            )
            response = await asyncio.wait_for(task, timeout=2)
            page = await client.get(f"/chat?conversation={conversation_id}")
            return stopped, response, page

    stopped, response, page = asyncio.run(run())

    assert stopped.status_code == 202
    assert response.status_code == 409
    assert "Generation stopped" in response.text
    assert llm.cancelled
    assert "stop this" not in page.text


def test_conversations_are_owner_isolated_and_deletion_removes_messages(
    tmp_path, monkeypatch
):
    import redloop.chat as chat
    from redloop.dashboard import create_app

    monkeypatch.setattr(chat, "get_llm", ChatLLM)
    app = create_app(str(tmp_path / "audit.sqlite"))

    async def run():
        async with make_client(app) as owner, make_client(app) as other:
            await owner.get("/chat")
            await other.get("/chat")
            assert owner.cookies.get(chat.SESSION_COOKIE) != other.cookies.get(
                chat.SESSION_COOKIE
            )
            await owner.post(
                "/chat",
                data={"message": "private conversation", "mode": "general"},
                headers={"Origin": "http://127.0.0.1"},
            )
            owner_conversations = (
                await owner.get("/api/chat/conversations")
            ).json()["conversations"]
            conversation_id = owner_conversations[0]["id"]

            other_conversations = (
                await other.get("/api/chat/conversations")
            ).json()["conversations"]
            assert conversation_id not in {
                item["id"] for item in other_conversations
            }
            foreign_delete = await other.delete(
                f"/api/chat/conversations/{conversation_id}",
                headers={"Origin": "http://127.0.0.1"},
            )
            assert foreign_delete.status_code == 404

            deleted = await owner.delete(
                f"/api/chat/conversations/{conversation_id}",
                headers={"Origin": "http://127.0.0.1"},
            )
            assert deleted.status_code == 200
            replacement_id = deleted.json()["active_id"]
            assert replacement_id != conversation_id
            page = await owner.get(f"/chat?conversation={replacement_id}")
            remaining = (
                await owner.get("/api/chat/conversations")
            ).json()["conversations"]
            return page, remaining

    page, remaining = asyncio.run(run())
    assert "private conversation" not in page.text
    assert len(remaining) == 1
    assert remaining[0]["title"] == "New chat"


def test_provider_token_usage_is_visible_and_persists_in_performance_dashboard(
    tmp_path, monkeypatch
):
    import redloop.chat as chat
    from redloop.dashboard import create_app

    class UsageLLM(ChatLLM):
        async def acomplete(self, *_args, **_kwargs):
            return {
                "text": "Token-accounted reply",
                "provider": "ollama",
                "model": "ollama/qwen3:8b",
                "elapsed_seconds": 0.01,
                "prompt_tokens": 29,
                "completion_tokens": 6,
                "total_tokens": 35,
                "token_usage_reported": True,
            }

    monkeypatch.setattr(chat, "get_llm", UsageLLM)
    db_path = str(tmp_path / "audit.sqlite")

    async def run():
        async with make_client(create_app(db_path)) as client:
            await client.get("/chat")
            response = await client.post(
                "/chat",
                data={"message": "count tokens", "mode": "general"},
                headers={"Origin": "http://127.0.0.1"},
            )
            assert response.status_code == 200
            performance_page = await client.get("/performance")
            summary = await client.get("/api/performance/summary")
            return performance_page, summary

    page, response = asyncio.run(run())
    usage = response.json()["token_usage"]
    assert usage["total_tokens"] == 35
    assert usage["prompt_tokens"] == 29
    assert usage["completion_tokens"] == 6
    assert usage["reported_requests"] == 1
    assert usage["providers"][0]["provider"] == "ollama"
    assert usage["recent"][0]["model"] == "ollama/qwen3:8b"
    assert usage["modes"][0]["mode"] == "general"
    assert usage["modes"][0]["total_tokens"] == 35
    assert response.json()["modes"]["general"]["chat_requests"] == 1
    assert response.json()["modes"]["general"]["total_tokens"] == 35
    assert "Persisted Chat Token Usage" in page.text
    assert "29" in page.text
    assert "6" in page.text

    async def after_restart():
        async with make_client(create_app(db_path)) as client:
            return await client.get("/api/performance/summary")

    restarted_response = asyncio.run(after_restart()).json()
    restarted = restarted_response["token_usage"]
    assert restarted["total_tokens"] == 35
    assert restarted["reported_requests"] == 1
    assert restarted_response["modes"]["general"]["total_tokens"] == 35


def test_explicit_provider_selection_does_not_fallback_to_another_provider(
    tmp_path, monkeypatch
):
    import redloop.chat as chat
    from redloop.audit import AuditLogger
    from redloop.dashboard import create_app
    from redloop.llm import LLMError

    class DualProviderLLM(ChatLLM):
        def __init__(self):
            self.settings = LLMSettings(
                _env_file=None,
                llm_provider="ollama",
                openai_api_key="unit-test-key",
            )
            self.default_provider = Provider.OLLAMA
            self.calls = []

        def is_provider_configured(self, provider):
            return provider in (Provider.OLLAMA, Provider.OPENAI)

        async def acomplete(self, *_args, provider, model_override, **_kwargs):
            self.calls.append((provider.value, model_override))
            if provider == Provider.OPENAI:
                raise LLMError("test provider failure")
            return {
                "text": "Local fallback response",
                "provider": "ollama",
                "model": "ollama/qwen3:8b",
                "elapsed_seconds": 0.01,
                "prompt_tokens": 1,
                "completion_tokens": 1,
                "total_tokens": 2,
                "token_usage_reported": True,
            }

    llm = DualProviderLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)
    db_path = str(tmp_path / "audit.sqlite")

    async def run():
        async with make_client(create_app(db_path)) as client:
            await client.get("/chat")
            response = await client.post(
                "/chat",
                data={
                    "message": "explicit provider test",
                    "mode": "general",
                    "model": "openai|gpt-4o",
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            return response

    response = asyncio.run(run())

    assert response.status_code == 502
    assert llm.calls == [("openai", "gpt-4o")]
    assert any(
        row["module"] == "chat"
        and row["status"] == "failed"
        and row["details"].get("provider") == "openai"
        for row in AuditLogger(db_path).fetch(limit=20)
    )


def test_auto_provider_fallback_is_audited_with_the_actual_answering_provider(
    tmp_path, monkeypatch
):
    import redloop.chat as chat
    from redloop.audit import AuditLogger
    from redloop.dashboard import create_app

    class DualProviderLLM(ChatLLM):
        def __init__(self):
            self.settings = LLMSettings(
                _env_file=None,
                llm_provider="ollama",
                openai_api_key="unit-test-key",
            )
            self.default_provider = Provider.OLLAMA
            self.calls = []

        def is_provider_configured(self, provider):
            return provider in (Provider.OLLAMA, Provider.OPENAI)

        async def acomplete(self, *_args, provider, model_override, **_kwargs):
            self.calls.append(provider.value)
            if provider == Provider.OPENAI:
                from redloop.llm import LLMError

                raise LLMError("test provider failure")
            return {
                "text": "Local fallback response",
                "provider": "ollama",
                "model": "ollama/qwen3:8b",
                "elapsed_seconds": 0.01,
                "prompt_tokens": 1,
                "completion_tokens": 1,
                "total_tokens": 2,
                "token_usage_reported": True,
            }

    llm = DualProviderLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)
    db_path = str(tmp_path / "audit.sqlite")

    async def run():
        async with make_client(create_app(db_path)) as client:
            await client.get("/chat")
            response = await client.post(
                "/chat",
                data={"message": "auto provider test", "mode": "general"},
                headers={"Origin": "http://127.0.0.1"},
            )
            return response

    response = asyncio.run(run())

    assert response.status_code == 200
    assert llm.calls == ["openai", "ollama"]
    assert "Local fallback response" in response.text
    completion = next(
        row for row in AuditLogger(db_path).fetch(limit=20)
        if row["module"] == "chat"
        and row["status"] == "success"
        and row["action"] == "llm_completion"
    )
    assert completion["details"]["provider"] == "ollama"
    assert completion["details"]["fallback_used"] is True
    assert completion["details"]["failed_providers"] == ["openai"]


def test_single_chat_supports_extended_multi_turn_conversations(tmp_path, monkeypatch):
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = ChatLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)
    db_path = str(tmp_path / "audit.sqlite")

    async def run():
        async with make_client(create_app(db_path)) as client:
            await client.get("/chat")
            # Execute 20 conversation turns in the same single chat
            for turn in range(1, 21):
                resp = await client.post(
                    "/chat",
                    data={"message": f"turn-{turn} question", "mode": "general"},
                    headers={"Origin": "http://127.0.0.1"},
                )
                assert resp.status_code == 200

            final_page = await client.get("/chat")
            return final_page

    final_page = asyncio.run(run())

    assert final_page.status_code == 200
    # Verify that early turns, middle turns, and late turns are all present in the single conversation
    assert "turn-1 question" in final_page.text
    assert "turn-10 question" in final_page.text
    assert "turn-20 question" in final_page.text
    # Verify that the LLM call for the 20th turn contains context from earlier turns
    last_llm_call = llm.calls[-1]
    assert "turn-1 question" in last_llm_call
    assert "turn-10 question" in last_llm_call
    assert "turn-19 question" in last_llm_call

