"""Tests for Resource-Aware Model Selection (Phase C & Gate C).

Verifies:
1. System RAM detection via platform APIs (ctypes on Windows).
2. Auto-downgrade from qwen3:8b to qwen3:4b when available RAM < threshold.
3. Configurable threshold behavior.
4. Explicit operator override with warning message.
5. Gate C enforcement: no inference path launches qwen3:8b on this 7.7 GB machine
   without explicit operator override.
"""

from __future__ import annotations

import pytest
from redloop.llm import (
    get_system_ram_gb,
    select_resource_aware_ollama_model,
    LLMSettings,
    LLMClient,
    Provider,
)


def test_system_ram_detection() -> None:
    total, avail = get_system_ram_gb()
    assert total > 0.0
    assert avail >= 0.0
    # On this machine, total is ~7.70 GB
    assert 5.0 <= total <= 128.0


def test_auto_downgrade_on_constrained_memory() -> None:
    # Machine has 7.70 GB total RAM and < 2.0 GB available -> falls back to verified edge tier qwen2.5:0.5b
    model, warning = select_resource_aware_ollama_model(
        requested_model="qwen3:8b",
        safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=False,
        total_ram_override=7.70,
        avail_ram_override=0.50,
    )
    assert model == "qwen2.5:0.5b"
    assert warning is not None
    assert "RESOURCE WARNING" in warning
    assert "qwen2.5:0.5b" in warning

    # On a 10 GB machine with 3.5 GB available -> falls back to intermediate tier qwen3:4b
    model_4b, warning_4b = select_resource_aware_ollama_model(
        requested_model="qwen3:8b",
        safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=False,
        total_ram_override=10.0,
        avail_ram_override=3.5,
    )
    assert model_4b == "qwen3:4b"
    assert warning_4b is not None
    assert "qwen3:4b" in warning_4b


def test_operator_override_allowed_with_warning() -> None:
    # With override=True, model remains qwen3:8b but warning is emitted
    model, warning = select_resource_aware_ollama_model(
        requested_model="qwen3:8b",
        safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=True,
        total_ram_override=7.70,
        avail_ram_override=0.50,
    )
    assert model == "qwen3:8b"
    assert warning is not None
    assert "OPERATOR OVERRIDE WARNING" in warning


def test_headroom_machine_keeps_requested_model() -> None:
    # On a 32GB machine with 16GB free RAM
    model, warning = select_resource_aware_ollama_model(
        requested_model="qwen3:8b",
        safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=False,
        total_ram_override=32.0,
        avail_ram_override=16.0,
    )
    assert model == "qwen3:8b"
    assert warning is None


def test_gate_c_llm_client_enforcement() -> None:
    # Gate C: default LLMClient on this machine will not launch 8b without override
    settings = LLMSettings(
        llm_provider="ollama",
        llm_model="qwen3:8b",
        ollama_safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=False,
    )
    client = LLMClient(settings=settings)
    resolved = client.model_string(Provider.OLLAMA)
    assert resolved in ("ollama/qwen2.5:0.5b", "ollama/qwen3:4b")
    assert resolved != "ollama/qwen3:8b"

    # With explicit override
    settings_override = LLMSettings(
        llm_provider="ollama",
        llm_model="qwen3:8b",
        ollama_safe_ram_threshold_gb=6.0,
        allow_insufficient_ram_override=True,
    )
    client_override = LLMClient(settings=settings_override)
    resolved_override = client_override.model_string(Provider.OLLAMA)
    assert resolved_override == "ollama/qwen3:8b"

