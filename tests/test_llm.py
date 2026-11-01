import asyncio
from types import SimpleNamespace

import pytest
from litellm.exceptions import APIError

from redloop.llm import (
    LLMClient,
    LLMSettings,
    Provider,
    ProviderCallError,
    ProviderNotConfiguredError,
)
from redloop.router import SmartRouter, TaskComplexity


def settings(**overrides):
    values = {
        "openrouter_api_key": None,
        "anthropic_api_key": None,
        "groq_api_key": None,
        "openai_api_key": None,
        "gemini_api_key": None,
        "nvidia_api_key": None,
        "kimi_api_key": None,
    }
    values.update(overrides)
    return LLMSettings(_env_file=None, **values)


def test_complete_returns_text_provider_and_measured_latency(monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(
        settings(
            llm_provider="gemini",
            gemini_api_key="test-key",
        )
    )

    result = client.complete("system", "user")

    assert result["text"] == "pong"
    assert result["provider"] == "gemini"
    assert result["elapsed_seconds"] >= 0
    assert result["token_usage_reported"] is False
    assert result["total_tokens"] == 0
    assert calls[0]["model"] == "gemini/gemini-2.0-flash"
    assert calls[0]["api_key"] == "test-key"


def test_complete_returns_provider_reported_token_usage(monkeypatch):
    def completion(**kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))],
            usage=SimpleNamespace(
                prompt_tokens=17,
                completion_tokens=4,
                total_tokens=21,
            ),
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(settings())

    result = client.complete("system", "user")

    assert result["prompt_tokens"] == 17
    assert result["completion_tokens"] == 4
    assert result["total_tokens"] == 21
    assert result["token_usage_reported"] is True


def test_acomplete_extracts_openai_style_usage_from_dict_response(monkeypatch):
    async def completion(**kwargs):
        return {
            "choices": [{"message": {"content": "pong"}}],
            "usage": {"input_tokens": 10, "output_tokens": 3},
        }

    monkeypatch.setattr("redloop.llm.litellm.acompletion", completion)
    client = LLMClient(settings())

    result = asyncio.run(client.acomplete("system", "user"))

    assert result["prompt_tokens"] == 10
    assert result["completion_tokens"] == 3
    assert result["total_tokens"] == 13
    assert result["token_usage_reported"] is True


def test_kimi_uses_openai_compatible_model_and_custom_base_url(monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(settings(kimi_api_key="test-key"))

    client.complete("system", "user", provider=Provider.KIMI)

    assert calls[0]["model"] == "openai/kimi-k2"
    assert calls[0]["api_base"] == "https://api.moonshot.ai/v1"


def test_complete_uses_custom_base_url_for_apinex(monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(settings(apinex_api_key="sk-apx-test-key"))

    client.complete("system", "user", provider=Provider.APINEX)

    assert calls[0]["model"] == "openai/deepseek-reasoner"
    assert calls[0]["api_base"] == "https://api.apinex.bond/v1"
    assert calls[0]["api_key"] == "sk-apx-test-key"


@pytest.mark.parametrize(
    ("provider", "model_override", "expected"),
    [
        (
            Provider.OPENROUTER,
            "deepseek/deepseek-r1",
            "openrouter/deepseek/deepseek-r1",
        ),
        (
            Provider.NVIDIA,
            "deepseek-ai/deepseek-v4-flash",
            "nvidia_nim/deepseek-ai/deepseek-v4-flash",
        ),
        (Provider.GEMINI, "gemini-2.5-flash-lite", "gemini/gemini-2.5-flash-lite"),
    ],
)
def test_complete_uses_selected_catalog_model(
    monkeypatch, provider, model_override, expected
):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(
        settings(
            openrouter_api_key="router-key",
            nvidia_api_key="nvidia-key",
            gemini_api_key="gemini-key",
        )
    )

    client.complete(
        "system",
        "user",
        provider=provider,
        model_override=model_override,
    )

    assert calls[0]["model"] == expected


def test_missing_key_rejects_direct_provider_call_without_litellm(monkeypatch):
    def unexpected_completion(**kwargs):
        pytest.fail("litellm should not be called without provider credentials")

    monkeypatch.setattr("redloop.llm.litellm.completion", unexpected_completion)
    client = LLMClient(settings())

    with pytest.raises(ProviderNotConfiguredError, match="not configured"):
        client.complete("system", "user", provider=Provider.GEMINI)


def test_complete_sanitizes_unexpected_provider_exceptions(monkeypatch):
    def completion(**kwargs):
        raise RuntimeError("private provider response and secret")

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(settings(gemini_api_key="test-key"))

    with pytest.raises(ProviderCallError, match="RuntimeError") as error:
        client.complete("system", "user", provider=Provider.GEMINI)

    assert "private provider response" not in str(error.value)


def test_router_falls_back_after_provider_api_error(monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"].startswith("gemini/"):
            raise APIError(
                status_code=503,
                message="unavailable",
                llm_provider="gemini",
                model=kwargs["model"],
            )
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(
        settings(
            gemini_api_key="test-key",
            allow_cloud_routing=True,
        )
    )

    result = SmartRouter(client).route_and_complete(
        "system", "user", complexity=TaskComplexity.SIMPLE
    )

    assert result["provider"] == "ollama"
    assert calls == ["gemini/gemini-2.0-flash", "ollama/qwen3:8b"]


def test_router_skips_provider_without_key(monkeypatch):
    calls = []

    def completion(**kwargs):
        calls.append(kwargs["model"])
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="pong"))]
        )

    monkeypatch.setattr("redloop.llm.litellm.completion", completion)
    client = LLMClient(settings(allow_cloud_routing=True))

    result = SmartRouter(client).route_and_complete(
        "system", "user", complexity=TaskComplexity.SIMPLE
    )

    assert result["provider"] == "ollama"
    assert calls == ["ollama/qwen3:8b"]


@pytest.mark.parametrize(
    ("env_name", "expected"),
    [
        ("GEMINI_API_KEY", "gemini-key"),
        ("REDLOOP_NVIDIA_API_KEY", "nvidia-key"),
    ],
)
def test_settings_accept_conventional_and_prefixed_env_names(
    monkeypatch, env_name, expected
):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("REDLOOP_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("REDLOOP_NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv(env_name, expected)

    client_settings = LLMSettings(_env_file=None)

    if env_name.endswith("GEMINI_API_KEY"):
        assert client_settings.gemini_api_key == expected
    else:
        assert client_settings.nvidia_api_key == expected
