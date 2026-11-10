"""Provider-neutral LLM calls and runtime configuration for RedLoop."""

from __future__ import annotations

import os
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import asyncio
import time
from enum import Enum
from typing import Any, TypedDict

import litellm
litellm.suppress_debug_info = True
litellm.drop_params = True

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _env_names(field_name: str) -> AliasChoices:
    name = field_name.upper()
    return AliasChoices(f"REDLOOP_{name}", name)


class Provider(str, Enum):
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    OPENAI = "openai"
    GEMINI = "gemini"
    NVIDIA = "nvidia_nim"
    KIMI = "kimi"
    APINEX = "apinex"


class ProviderStatus(str, Enum):
    CONFIGURED = "CONFIGURED"
    AUTH_VERIFIED = "AUTH_VERIFIED"
    ENDPOINT_VERIFIED = "ENDPOINT_VERIFIED"
    MODEL_VERIFIED = "MODEL_VERIFIED"
    INFERENCE_VERIFIED = "INFERENCE_VERIFIED"
    TIMEOUT = "TIMEOUT"
    AUTH_FAILED = "AUTH_FAILED"
    QUOTA_FAILED = "QUOTA_FAILED"
    MODEL_NOT_FOUND = "MODEL_NOT_FOUND"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    DAEMON_STOPPED = "DAEMON_STOPPED"
    UNAVAILABLE = "UNAVAILABLE"


CHAT_MODEL_CATALOG: dict[Provider, tuple[tuple[str, str], ...]] = {
    Provider.NVIDIA: (
        ("meta/llama-3.2-11b-vision-instruct", "Llama 3.2 11B Vision"),
        ("deepseek-ai/deepseek-v4-flash", "DeepSeek V4 Flash"),
    ),
    Provider.OPENROUTER: (
        ("meta-llama/llama-3.3-70b-instruct", "Llama 3.3 70B Instruct"),
        ("qwen/qwen-2.5-coder-32b-instruct", "Qwen 2.5 Coder 32B Instruct"),
        ("qwen/qwen-2.5-72b-instruct", "Qwen 2.5 72B Instruct"),
        ("meta-llama/llama-3.1-70b-instruct", "Llama 3.1 70B Instruct"),
        ("meta-llama/llama-3.1-8b-instruct", "Llama 3.1 8B Instruct"),
        ("mistralai/mistral-nemo", "Mistral Nemo 12B"),
        ("google/gemma-2-27b-it", "Gemma 2 27B IT"),
        ("deepseek/deepseek-r1", "DeepSeek R1"),
    ),
    Provider.GEMINI: (
        ("gemini-3.8-flash", "Gemini 3.8 Flash"),
        ("gemini-2.5-flash", "Gemini 2.5 Flash"),
        ("gemini-2.5-pro", "Gemini 2.5 Pro"),
    ),
    Provider.KIMI: (
        ("kimi-3", "Kimi 3"),
        ("kimi-k2", "Kimi K2"),
        ("kimi-latest", "Kimi Latest"),
        ("moonshot-v1-8k", "Moonshot Kimi 8K"),
        ("moonshot-v1-32k", "Moonshot Kimi 32K"),
        ("moonshot-v1-128k", "Moonshot Kimi 128K"),
    ),
    Provider.ANTHROPIC: (
        ("claude-sonnet-4-20250514", "Claude 3.7 Sonnet"),
        ("claude-3-5-sonnet-latest", "Claude 3.5 Sonnet"),
        ("claude-3-5-haiku-latest", "Claude 3.5 Haiku"),
        ("claude-3-opus-latest", "Claude 3 Opus"),
    ),
    Provider.OPENAI: (
        ("gpt-4o", "GPT-4o"),
        ("gpt-4o-mini", "GPT-4o mini"),
        ("o1", "OpenAI o1"),
        ("o3-mini", "OpenAI o3-mini"),
    ),
    Provider.GROQ: (
        ("qwen/qwen3.8-27b", "Qwen 3.8 27B"),
        ("llama-3.3-70b-versatile", "Llama 3.3 70B Versatile"),
        ("llama-3.1-8b-instant", "Llama 3.1 8B Instant"),
        ("openai/gpt-oss-120b", "GPT-OSS 120B"),
        ("openai/gpt-oss-20b", "GPT-OSS 20B"),
        ("allam-2-7b", "Allam 2 7B"),
    ),
    Provider.OLLAMA: (
        ("xploiter/pentester:latest", "Xploiter Pentester 2.8B (Local)"),
    ),
    Provider.APINEX: (
        ("deepseek-reasoner", "DeepSeek R1 (Cybersecurity Reasoning)"),
        ("deepseek-chat", "DeepSeek V3 (Fast Pentest & Scripting)"),
        ("claude-3-7-sonnet", "Claude 3.7 Sonnet (Hybrid Reasoning)"),
        ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet v2 (AppSec & Bug Bounty)"),
        ("claude-3-5-haiku-20241022", "Claude 3.5 Haiku (High-Speed Triage)"),
        ("o3-mini", "OpenAI o3-mini (High-Reasoning Security Logic)"),
        ("gpt-4o", "OpenAI GPT-4o (Multimodal & Vulnerability Review)"),
        ("gemini-2.0-flash", "Gemini 2.0 Flash (Fast Log & PCAP Analysis)"),
        ("free/deepseek-r1", "DeepSeek R1 (Free Route)"),
        ("free/glm-5.3-flash", "GLM 5.3 Flash (Free Route)"),
    ),
}


class CompletionResult(TypedDict):
    text: str
    provider: str
    elapsed_seconds: float
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    token_usage_reported: bool


def _completion_usage(response: Any) -> dict[str, int | bool]:
    """Extract provider-reported token counts without estimating missing usage."""
    usage = (
        response.get("usage")
        if isinstance(response, dict)
        else getattr(response, "usage", None)
    )
    if usage is None:
        return {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "token_usage_reported": False,
        }

    def count(*names: str) -> int | None:
        for name in names:
            value = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
        return None

    prompt_tokens = count("prompt_tokens", "input_tokens")
    completion_tokens = count("completion_tokens", "output_tokens")
    total_tokens = count("total_tokens")
    reported = any(
        value is not None
        for value in (prompt_tokens, completion_tokens, total_tokens)
    )
    prompt_count = prompt_tokens or 0
    completion_count = completion_tokens or 0
    total_count = (
        total_tokens
        if total_tokens is not None
        else prompt_count + completion_count
    )
    return {
        "prompt_tokens": prompt_count,
        "completion_tokens": completion_count,
        "total_tokens": total_count,
        "token_usage_reported": reported,
    }


class LLMError(RuntimeError):
    """Base error for provider configuration and completion failures."""


class InsufficientMemoryError(LLMError):
    """Raised when an inference path attempts to launch a model exceeding available RAM without explicit override."""


def get_system_ram_gb() -> tuple[float, float]:
    """Return (total_ram_gb, available_ram_gb) using platform APIs without third-party dependencies."""
    try:
        import sys
        if sys.platform == "win32":
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return (
                    round(stat.ullTotalPhys / (1024 ** 3), 2),
                    round(stat.ullAvailPhys / (1024 ** 3), 2),
                )
        else:
            import os
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = (pages * page_size) / (1024 ** 3)
            avail = total * 0.5
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            avail = int(line.split()[1]) / (1024 ** 2)
                            break
            return round(total, 2), round(avail, 2)
    except Exception:
        pass
    return 8.0, 4.0


def select_resource_aware_ollama_model(
    requested_model: str,
    safe_ram_threshold_gb: float = 6.0,
    allow_insufficient_ram_override: bool = False,
    total_ram_override: float | None = None,
    avail_ram_override: float | None = None,
) -> tuple[str, str | None]:
    """Automatic model-tier selection based on resident host RAM (C.1 & Gate C).

    Heavy models (8B+ parameters, such as qwen3:8b) require resident RAM exceeding 6 GB.
    On machines with constrained physical or available RAM, auto-selects qwen3:4b (or smaller)
    to prevent OS paging, memory thrashing, and high latency.
    """
    total_gb, avail_gb = get_system_ram_gb()
    if total_ram_override is not None:
        total_gb = total_ram_override
    if avail_ram_override is not None:
        avail_gb = avail_ram_override

    model_lower = requested_model.lower()
    is_8b_plus = any(tag in model_lower for tag in (":8b", "-8b", ":7b", "-7b", ":14b", ":32b", ":70b"))
    is_4b = any(tag in model_lower for tag in (":4b", "-4b", ":3b", "-3b"))

    if (is_8b_plus or is_4b) and (avail_gb < safe_ram_threshold_gb or total_gb < 12.0):
        if not allow_insufficient_ram_override:
            # On severely constrained hosts (available RAM < 2.0GB or total RAM <= 8.0GB),
            # qwen3:4b also triggers context memory allocation timeouts; default to verified qwen2.5:0.5b.
            if avail_gb < 2.0 or total_gb <= 8.0:
                safe_model = "qwen2.5:0.5b"
            else:
                safe_model = "qwen3:4b"

            warning_msg = (
                f"RESOURCE WARNING: Model '{requested_model}' requires >= {safe_ram_threshold_gb:.1f} GB free RAM, "
                f"but only {avail_gb:.2f} GB is available (total RAM: {total_gb:.2f} GB). "
                f"Defaulting to resource-safe tier '{safe_model}' to prevent swap thrashing and OS paging. "
                f"(Set REDLOOP_ALLOW_INSUFFICIENT_RAM=1 to force override)."
            )
            return safe_model, warning_msg
        else:
            warning_msg = (
                f"OPERATOR OVERRIDE WARNING: Forcing execution of heavy model '{requested_model}' with only "
                f"{avail_gb:.2f} GB available RAM (recommended: >= 16 GB physical RAM for 8b). OS paging likely."
            )
            return requested_model, warning_msg

    return requested_model, None


class ProviderNotConfiguredError(LLMError):
    """Raised when a requested cloud provider has no API key."""


class ProviderCallError(LLMError):
    """A provider API call failed; contains no provider response or key."""

    def __init__(self, provider: Provider, error_type: str):
        self.provider = provider
        self.error_type = error_type
        super().__init__(f"{provider.value} request failed ({error_type})")


class LLMSettings(BaseSettings):
    """Runtime LLM config, sourced from prefixed or conventional env names."""

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
        case_sensitive=False,
    )

    llm_provider: str = Field(
        default="ollama", validation_alias=_env_names("llm_provider")
    )
    llm_model: str = Field(
        default="qwen3:8b",
        validation_alias=AliasChoices(
            "REDLOOP_LLM_MODEL", "LLM_MODEL", "OLLAMA_MODEL"
        ),
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias=_env_names("ollama_base_url"),
    )
    ollama_safe_ram_threshold_gb: float = Field(
        default=6.0,
        validation_alias=_env_names("ollama_safe_ram_threshold_gb"),
    )
    allow_insufficient_ram_override: bool = Field(
        default=False,
        validation_alias=_env_names("allow_insufficient_ram_override"),
    )

    openrouter_api_key: str | None = Field(
        default=None, validation_alias=_env_names("openrouter_api_key")
    )
    openrouter_model: str = Field(
        default="nvidia/nemotron-3.5-lightning:free",
        validation_alias=_env_names("openrouter_model"),
    )
    anthropic_api_key: str | None = Field(
        default=None, validation_alias=_env_names("anthropic_api_key")
    )
    anthropic_model: str = Field(
        default="claude-sonnet-4-20250514",
        validation_alias=_env_names("anthropic_model"),
    )
    groq_api_key: str | None = Field(
        default=None, validation_alias=_env_names("groq_api_key")
    )
    groq_model: str = Field(
        default="llama-3.3-70b-versatile",
        validation_alias=_env_names("groq_model"),
    )
    openai_api_key: str | None = Field(
        default=None, validation_alias=_env_names("openai_api_key")
    )
    openai_model: str = Field(
        default="gpt-4o", validation_alias=_env_names("openai_model")
    )
    gemini_api_key: str | None = Field(
        default=None, validation_alias=_env_names("gemini_api_key")
    )
    gemini_model: str = Field(
        default="gemini-2.0-flash",
        validation_alias=_env_names("gemini_model"),
    )
    nvidia_api_key: str | None = Field(
        default=None, validation_alias=_env_names("nvidia_api_key")
    )
    nvidia_model: str = Field(
        default="meta/llama-3.2-11b-vision-instruct",
        validation_alias=_env_names("nvidia_model"),
    )
    kimi_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "REDLOOP_KIMI_API_KEY",
            "KIMI_API_KEY",
            "REDLOOP_MOONSHOT_API_KEY",
            "MOONSHOT_API_KEY",
        ),
    )
    kimi_model: str = Field(
        default="kimi-k2",
        validation_alias=AliasChoices(
            "REDLOOP_KIMI_MODEL",
            "KIMI_MODEL",
            "REDLOOP_MOONSHOT_MODEL",
            "MOONSHOT_MODEL",
        ),
    )
    kimi_base_url: str = Field(
        default="https://api.moonshot.ai/v1",
        validation_alias=AliasChoices(
            "REDLOOP_KIMI_BASE_URL",
            "KIMI_BASE_URL",
            "REDLOOP_MOONSHOT_BASE_URL",
            "MOONSHOT_BASE_URL",
        ),
    )
    apinex_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "REDLOOP_APINEX_API_KEY",
            "APINEX_API_KEY",
        ),
    )
    apinex_model: str = Field(
        default="deepseek-reasoner",
        validation_alias=AliasChoices(
            "REDLOOP_APINEX_MODEL",
            "APINEX_MODEL",
        ),
    )
    apinex_base_url: str = Field(
        default="https://api.apinex.bond/v1",
        validation_alias=AliasChoices(
            "REDLOOP_APINEX_BASE_URL",
            "APINEX_BASE_URL",
        ),
    )

    allow_cloud_routing: bool = Field(
        default=False, validation_alias=_env_names("allow_cloud_routing")
    )
    temperature: float = Field(
        default=0.2, validation_alias=_env_names("temperature")
    )
    max_tokens: int = Field(
        default=4096, validation_alias=_env_names("max_tokens")
    )


class LLMClient:
    """Unified call surface over litellm with per-call provider metadata."""

    def __init__(self, settings: LLMSettings | None = None):
        self.settings = settings or LLMSettings()
        litellm.drop_params = True

    @property
    def default_provider(self) -> Provider:
        return self._coerce_provider(self.settings.llm_provider)

    def is_provider_configured(self, provider: Provider) -> bool:
        if provider == Provider.OLLAMA:
            return True
        return bool(self._api_key(provider))

    def configured_providers(self) -> list[Provider]:
        """Return local Ollama and cloud providers with non-empty API keys."""
        return [
            provider
            for provider in Provider
            if self.is_provider_configured(provider)
        ]

    def get_provider_status(self, provider: Provider) -> ProviderStatus:
        """Return detailed status state for given provider."""
        if not self.is_provider_configured(provider):
            return ProviderStatus.UNAVAILABLE
        if provider == Provider.OLLAMA:
            import urllib.request
            try:
                with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1.0) as resp:
                    if resp.status == 200:
                        return ProviderStatus.ENDPOINT_VERIFIED
            except Exception:
                return ProviderStatus.DAEMON_STOPPED
        return ProviderStatus.CONFIGURED


    def model_string(
        self,
        provider: Provider | str | None = None,
        model_override: str | None = None,
    ) -> str:
        selected = self._coerce_provider(provider or self.settings.llm_provider)
        s = self.settings
        if selected == Provider.OLLAMA:
            raw_model = model_override or s.llm_model
            chosen_model, warning = select_resource_aware_ollama_model(
                raw_model,
                safe_ram_threshold_gb=s.ollama_safe_ram_threshold_gb,
                allow_insufficient_ram_override=s.allow_insufficient_ram_override,
            )
            if warning:
                import logging
                logging.getLogger("redloop.llm").warning(warning)
            return f"ollama/{chosen_model}"
        if model_override is not None:
            if selected in (Provider.GROQ, Provider.GEMINI, Provider.NVIDIA):
                return f"{selected.value}/{model_override}"
            if selected == Provider.OPENROUTER:
                return f"openrouter/{model_override}"
            if selected in (Provider.KIMI, Provider.APINEX):
                return model_override if model_override.startswith("openai/") else f"openai/{model_override}"
            return model_override
        if selected == Provider.OPENROUTER:
            return f"openrouter/{s.openrouter_model}"
        if selected == Provider.ANTHROPIC:
            return s.anthropic_model
        if selected == Provider.GROQ:
            return f"groq/{s.groq_model}"
        if selected == Provider.OPENAI:
            return s.openai_model
        if selected == Provider.GEMINI:
            return f"gemini/{s.gemini_model}"
        if selected == Provider.NVIDIA:
            return f"nvidia_nim/{s.nvidia_model}"
        if selected == Provider.KIMI:
            return f"openai/{s.kimi_model}"
        if selected == Provider.APINEX:
            return s.apinex_model if s.apinex_model.startswith("openai/") else f"openai/{s.apinex_model}"
        raise ValueError(f"Unsupported provider: {selected}")

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: Provider | str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model_override: str | None = None,
        **kwargs: Any,
    ) -> CompletionResult:
        """Call one provider and return text, provider identity, and wall time."""
        selected = self._coerce_provider(provider or self.settings.llm_provider)
        api_key = self._api_key(selected)
        if selected != Provider.OLLAMA and not api_key:
            raise ProviderNotConfiguredError(
                f"{selected.value} is not configured with an API key"
            )

        call_kwargs: dict[str, Any] = {
            "model": self.model_string(selected, model_override),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": (
                temperature if temperature is not None else self.settings.temperature
            ),
            "max_tokens": (
                max_tokens if max_tokens is not None else self.settings.max_tokens
            ),
            "timeout": kwargs.pop("timeout", 15.0),
            **kwargs,
        }
        if selected == Provider.OLLAMA:
            call_kwargs["api_base"] = self.settings.ollama_base_url
        else:
            call_kwargs["api_key"] = api_key
        if selected in (Provider.KIMI, Provider.APINEX):
            call_kwargs["api_base"] = (
                self.settings.apinex_base_url
                if selected == Provider.APINEX
                else self.settings.kimi_base_url
            )

        from redloop.hardening import global_llm_circuit_breaker
        if not global_llm_circuit_breaker.can_execute():
            raise ProviderCallError(selected, "CircuitBreakerOpen")

        started = time.monotonic()
        last_exc = None
        response = None
        max_retries = kwargs.pop("max_retries", 2)

        for attempt in range(max_retries + 1):
            try:
                response = litellm.completion(**call_kwargs)
                global_llm_circuit_breaker.record_success()
                break
            except Exception as exc:
                last_exc = exc
                if attempt < max_retries and any(err_kw in str(exc).lower() for err_kw in ("timeout", "rate", "429", "502", "503", "504", "connection")):
                    time.sleep(0.3 * (2 ** attempt))
                    continue
                global_llm_circuit_breaker.record_failure()
                raise ProviderCallError(selected, type(exc).__name__) from exc
        elapsed = time.monotonic() - started

        choice = response.choices[0] if getattr(response, "choices", None) else None
        if choice is None and isinstance(response, dict) and "choices" in response and response["choices"]:
            choice = response["choices"][0]
        if choice is None:
            raise LLMError("Provider returned an empty response with no choices")

        msg = choice.get("message") if isinstance(choice, dict) else getattr(choice, "message", None)
        text = None
        if msg is not None:
            raw_content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if isinstance(raw_content, str):
                text = raw_content
            elif isinstance(raw_content, (list, tuple)):
                parts = []
                for item in raw_content:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        parts.append(item.get("text") or item.get("content") or "")
                    elif hasattr(item, "text"):
                        parts.append(str(getattr(item, "text", "")))
                text = "".join(parts)
            elif isinstance(raw_content, dict):
                text = raw_content.get("text") or raw_content.get("content")

            # Fallback to reasoning / thinking content if text is empty or None
            if not text or not str(text).strip():
                for attr in ("reasoning_content", "reasoning", "thinking"):
                    val = msg.get(attr) if isinstance(msg, dict) else getattr(msg, attr, None)
                    if val and isinstance(val, str) and val.strip():
                        text = val
                        break
            if not text or not str(text).strip():
                psf = msg.get("provider_specific_fields") if isinstance(msg, dict) else getattr(msg, "provider_specific_fields", None)
                if isinstance(psf, dict):
                    r_val = psf.get("reasoning") or psf.get("reasoning_content")
                    if r_val and isinstance(r_val, str) and r_val.strip():
                        text = r_val
                    elif isinstance(psf.get("reasoning_details"), list):
                        r_parts = []
                        for r_item in psf["reasoning_details"]:
                            if isinstance(r_item, dict) and r_item.get("text"):
                                r_parts.append(str(r_item["text"]))
                        if r_parts:
                            text = "".join(r_parts)

        if not text:
            choice_text = choice.get("text") if isinstance(choice, dict) else getattr(choice, "text", None)
            if isinstance(choice_text, str) and choice_text.strip():
                text = choice_text

        if not text:
            delta = choice.get("delta") if isinstance(choice, dict) else getattr(choice, "delta", None)
            if delta is not None:
                d_content = delta.get("content") if isinstance(delta, dict) else getattr(delta, "content", None)
                if isinstance(d_content, str) and d_content.strip():
                    text = d_content
                elif not text:
                    for attr in ("reasoning_content", "reasoning", "thinking"):
                        val = delta.get(attr) if isinstance(delta, dict) else getattr(delta, attr, None)
                        if val and isinstance(val, str) and val.strip():
                            text = val
                            break

        if text is None:
            raise LLMError("Provider returned a non-text completion")

        text = str(text)
        if not text.strip():
            raise LLMError("Provider returned an empty completion")
        return {
            "text": text,
            "provider": selected.value,
            "elapsed_seconds": round(elapsed, 2),
            "model": call_kwargs["model"],
            **_completion_usage(response),
        }

    async def acomplete(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: Provider | str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        model_override: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Call a provider asynchronously so cancelling a chat can close its request."""
        selected = self._coerce_provider(provider or self.settings.llm_provider)
        api_key = self._api_key(selected)
        if selected != Provider.OLLAMA and not api_key:
            raise ProviderNotConfiguredError(
                f"{selected.value} is not configured with an API key"
            )

        call_kwargs: dict[str, Any] = {
            "model": self.model_string(selected, model_override),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": (
                temperature if temperature is not None else self.settings.temperature
            ),
            "max_tokens": (
                max_tokens if max_tokens is not None else self.settings.max_tokens
            ),
            "timeout": kwargs.pop("timeout", 15.0),
            **kwargs,
        }
        if selected == Provider.OLLAMA:
            call_kwargs["api_base"] = self.settings.ollama_base_url
        else:
            call_kwargs["api_key"] = api_key
        if selected in (Provider.KIMI, Provider.APINEX):
            call_kwargs["api_base"] = (
                self.settings.apinex_base_url
                if selected == Provider.APINEX
                else self.settings.kimi_base_url
            )

        started = time.monotonic()
        try:
            response = await litellm.acompletion(**call_kwargs)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise ProviderCallError(selected, type(exc).__name__) from exc

        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, dict):
            choices = response.get("choices")
        choice = choices[0] if choices else None
        if choice is None:
            raise LLMError("Provider returned an empty response with no choices")
        message = (
            choice.get("message")
            if isinstance(choice, dict)
            else getattr(choice, "message", None)
        )
        content = (
            message.get("content")
            if isinstance(message, dict)
            else getattr(message, "content", None)
        )
        if isinstance(content, list):
            content = "".join(
                item if isinstance(item, str)
                else item.get("text", item.get("content", ""))
                if isinstance(item, dict)
                else str(getattr(item, "text", ""))
                for item in content
            )
        if not isinstance(content, str) or not content.strip():
            raise LLMError("Provider returned an empty or non-text completion")
        elapsed = time.monotonic() - started
        return {
            "text": content,
            "provider": selected.value,
            "model": call_kwargs["model"],
            "elapsed_seconds": round(elapsed, 2),
            **_completion_usage(response),
        }

    # -- Phase 3: self-healing loop helpers ---------------------------------

    SYSTEM_GENERATE = """You are RedLoop's code generator.
Write a SHORT, self-contained Python script that accomplishes the user's task.
Constraints:
- No external imports beyond stdlib unless explicitly allowed.
- No network calls unless the task explicitly requires them (the sandbox is network-isolated).
- Output ONLY the Python code, no markdown fences, no explanation.
- The script MUST print JSON to stdout: {"result": <your output>} on success,
  or {"error": "<message>"} on failure, so the orchestrator can parse it.
"""

    SYSTEM_FIX = """You are RedLoop's code fixer.
The previous script failed. You are given the task, the script that was run,
and the full stderr/stdout. Write a CORRECTED version of the script.
Constraints:
- Fix ONLY what caused the failure. Do not rewrite style or add features.
- Output ONLY the corrected Python code, no markdown, no explanation.
- The script MUST print JSON to stdout: {"result": <your output>} or {"error": "..."}.
"""

    def generate_code(
        self, task: str, allowed_imports: list[str] | None = None
    ) -> str:
        """Ask the selected LLM to write a script for `task`."""
        prompt = f"Task: {task}\n"
        if allowed_imports:
            prompt += f"Allowed imports (stdlib + these): {', '.join(allowed_imports)}\n"
        return self.complete(self.SYSTEM_GENERATE, prompt)["text"]

    def fix_code(
        self,
        task: str,
        broken_code: str,
        stdout: str,
        stderr: str,
        exit_code: int,
    ) -> str:
        """Ask the selected LLM to fix a script that failed."""
        prompt = (
            f"Task: {task}\n\n"
            f"Previous code:\n{broken_code}\n\n"
            f"Exit code: {exit_code}\n"
            f"Stdout:\n{stdout}\n\n"
            f"Stderr:\n{stderr}\n\n"
            "Write the corrected script."
        )
        return self.complete(self.SYSTEM_FIX, prompt)["text"]

    def _api_key(self, provider: Provider) -> str | None:
        setting_name = {
            Provider.OPENROUTER: "openrouter_api_key",
            Provider.ANTHROPIC: "anthropic_api_key",
            Provider.GROQ: "groq_api_key",
            Provider.OPENAI: "openai_api_key",
            Provider.GEMINI: "gemini_api_key",
            Provider.NVIDIA: "nvidia_api_key",
            Provider.KIMI: "kimi_api_key",
            Provider.APINEX: "apinex_api_key",
        }.get(provider)
        if setting_name is None:
            return None
        value = getattr(self.settings, setting_name)
        if isinstance(value, str):
            cleaned = value.strip()
            if (
                cleaned
                and not cleaned.startswith("***")
                and cleaned not in ("None", "null", "undefined", "your-key-here", "your-api-key-here", "TODO")
            ):
                return cleaned

        # Fall back to the encrypted provider vault so keys saved through the
        # gateway actually drive real LLM calls.
        try:
            from redloop.provider_gateway import get_provider_gateway

            vault_key = get_provider_gateway().key_store.get_stored_key(provider.value)
            if vault_key and vault_key.strip() and not vault_key.startswith("***"):
                return vault_key.strip()
        except Exception:
            pass
        return None

    def audit_providers(self, timeout: float = 3.0) -> list[dict[str, Any]]:
        """Safely verify connectivity and authentication of configured LLM providers without leaking keys."""
        results = []
        providers_to_test = [
            (Provider.GROQ, self.settings.groq_model),
            (Provider.OPENROUTER, self.settings.openrouter_model),
            (Provider.GEMINI, self.settings.gemini_model),
            (Provider.NVIDIA, self.settings.nvidia_model),
            (Provider.OLLAMA, self.settings.llm_model),
        ]
        if self._api_key(Provider.APINEX):
            providers_to_test.append((Provider.APINEX, self.settings.apinex_model))
        for prov, model in providers_to_test:
            entry = {
                "provider": prov.value,
                "credential": "PRESENT" if self._api_key(prov) else ("LOCAL" if prov == Provider.OLLAMA else "ABSENT"),
                "auth": "UNKNOWN",
                "endpoint": "UNKNOWN",
                "model": model,
                "status": "UNKNOWN",
            }
            if entry["credential"] == "ABSENT":
                entry["auth"] = "ABSENT"
                entry["endpoint"] = "NOT_CONFIGURED"
                entry["status"] = "UNCONFIGURED"
                results.append(entry)
                continue

            # Fast socket check for Ollama
            if prov == Provider.OLLAMA:
                import socket
                is_up = False
                try:
                    with socket.create_connection(("127.0.0.1", 11434), timeout=0.3):
                        is_up = True
                except Exception:
                    is_up = False
                if not is_up:
                    entry["auth"] = "N/A"
                    entry["endpoint"] = "UNREACHABLE"
                    entry["status"] = "LOCAL FALLBACK (OFFLINE)"
                    results.append(entry)
                    continue

            t0 = time.monotonic()
            try:
                res = self.complete("Test assistant", "Ping", provider=prov, model_override=model, timeout=timeout)
                entry["auth"] = "OK"
                entry["endpoint"] = "OK"
                entry["status"] = "AVAILABLE"
                entry["latency_s"] = round(time.monotonic() - t0, 2)
            except Exception as exc:
                err = str(exc)
                entry["endpoint"] = "OK" if any(c in err for c in ("40", "41", "42", "43", "50", "api_key", "auth")) else "FAILED"
                if any(t in err.lower() for t in ("auth", "api_key", "401", "403", "forbidden")):
                    entry["auth"] = "FAILED"
                elif any(t in err.lower() for t in ("quota", "credit", "402", "rate")):
                    entry["auth"] = "EXHAUSTED"
                else:
                    entry["auth"] = "ERROR"
                entry["status"] = f"FAILED: {type(exc).__name__}"
            results.append(entry)
        return results

    @staticmethod
    def _coerce_provider(provider: Provider | str) -> Provider:
        try:
            return provider if isinstance(provider, Provider) else Provider(provider)
        except ValueError as exc:
            supported = ", ".join(item.value for item in Provider)
            raise ValueError(
                f"Unsupported LLM provider {provider!r}; choose from {supported}"
            ) from exc


# Convenience singleton
_llm_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client
