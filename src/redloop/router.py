"""Complexity-aware provider fallback for average task completion time."""

from __future__ import annotations

from enum import Enum
from typing import Any

from redloop.llm import (
    CompletionResult,
    LLMClient,
    LLMError,
    Provider,
)


class TaskComplexity(str, Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


ROUTING_TABLE: dict[TaskComplexity, tuple[Provider, ...]] = {
    TaskComplexity.SIMPLE: (
        Provider.GEMINI,
        Provider.NVIDIA,
        Provider.OLLAMA,
    ),
    TaskComplexity.MODERATE: (
        Provider.GEMINI,
        Provider.APINEX,
        Provider.KIMI,
        Provider.OPENAI,
        Provider.OLLAMA,
    ),
    TaskComplexity.COMPLEX: (
        Provider.ANTHROPIC,
        Provider.APINEX,
        Provider.OPENAI,
        Provider.KIMI,
        Provider.OLLAMA,
    ),
}


class RoutingError(RuntimeError):
    """Base error for routing failures."""


class NoProvidersConfiguredError(RoutingError):
    """No eligible provider has the credentials/configuration to be called."""


class AllProvidersFailedError(RoutingError):
    """All eligible providers failed; records provider names and error types."""

    def __init__(self, failures: list[tuple[Provider, str]]):
        self.failures = failures
        summary = ", ".join(
            f"{provider.value}: {error_type}" for provider, error_type in failures
        )
        super().__init__(f"All eligible providers failed ({summary})")


class SmartRouter:
    """Use configured providers in a tier order; cloud fallback is opt-in."""

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def route_and_complete(
        self,
        system_prompt: str,
        user_prompt: str,
        complexity: TaskComplexity | str = TaskComplexity.MODERATE,
        **kwargs: Any,
    ) -> CompletionResult:
        try:
            tier = (
                complexity
                if isinstance(complexity, TaskComplexity)
                else TaskComplexity(complexity)
            )
        except ValueError as exc:
            choices = ", ".join(item.value for item in TaskComplexity)
            raise ValueError(f"Unknown task complexity; choose from {choices}") from exc

        cloud_enabled = self.llm.settings.allow_cloud_routing
        eligible = [
            provider
            for provider in ROUTING_TABLE[tier]
            if self.llm.is_provider_configured(provider)
            and (provider == Provider.OLLAMA or cloud_enabled)
        ]
        if not eligible:
            reason = (
                "No configured provider is eligible; configure a provider key "
                "and enable cloud routing if using cloud providers"
            )
            raise NoProvidersConfiguredError(reason)

        failures: list[tuple[Provider, str]] = []
        on_event = kwargs.pop("on_event", None)
        for provider in eligible:
            try:
                if on_event:
                    on_event(f"Trying provider {provider.value}")
                res = self.llm.complete(
                    system_prompt,
                    user_prompt,
                    provider=provider,
                    **kwargs,
                )
                if on_event:
                    on_event(f"Provider {provider.value} answered")
                return res
            except LLMError as exc:
                err_type = getattr(exc, "error_type", type(exc).__name__)
                if on_event:
                    on_event(f"Provider {provider.value} failed ({err_type}) — falling back")
                failures.append(
                    (
                        provider,
                        err_type,
                    )
                )
        raise AllProvidersFailedError(failures)
