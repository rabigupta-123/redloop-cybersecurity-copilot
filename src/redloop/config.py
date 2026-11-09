"""Runtime configuration for RedLoop.

Loaded from environment variables (optionally a `.env` file) via
``pydantic-settings``. Every knob has a safe default so the CLI works
out of the box with just Ollama running locally.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_dir() -> Path:
    """Return a writable per-user data directory.

    Uses the platform data dir on Linux/macOS and ``%LOCALAPPDATA%`` on
    Windows so the default install works without admin rights.
    """
    env = os.environ.get("REDLOOP_DATA_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "RedLoop"
    return Path(os.path.expanduser("~")) / ".local" / "share" / "redloop"


class Settings(BaseSettings):
    """All RedLoop configuration, sourced from ``REDLOOP_*`` env vars."""

    model_config = SettingsConfigDict(
        env_prefix="REDLOOP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- LLM backend ---------------------------------------------------------
    # Which provider the orchestrator talks to. litellm normalizes all of
    # these behind one ``completion()`` call.
    llm_provider: str = Field(
        default="ollama",
        validation_alias=AliasChoices("REDLOOP_LLM_PROVIDER", "LLM_PROVIDER"),
    )
    llm_model: str = Field(
        default="qwen3:8b",
        validation_alias=AliasChoices("REDLOOP_LLM_MODEL", "LLM_MODEL", "OLLAMA_MODEL"),
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias=AliasChoices("REDLOOP_OLLAMA_BASE_URL", "OLLAMA_BASE_URL"),
    )

    openrouter_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"),
    )
    openrouter_model: str = Field(
        default="qwen/qwen3-8b",
        validation_alias=AliasChoices("REDLOOP_OPENROUTER_MODEL", "OPENROUTER_MODEL"),
    )

    anthropic_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_model: str = Field(
        default="claude-sonnet-4-20250514",
        validation_alias=AliasChoices("REDLOOP_ANTHROPIC_MODEL", "ANTHROPIC_MODEL"),
    )

    groq_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_GROQ_API_KEY", "GROQ_API_KEY"),
    )
    groq_model: str = Field(
        default="llama-3.3-70b-versatile",
        validation_alias=AliasChoices("REDLOOP_GROQ_MODEL", "GROQ_MODEL"),
    )

    openai_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_OPENAI_API_KEY", "OPENAI_API_KEY"),
    )
    openai_model: str = Field(
        default="gpt-4o",
        validation_alias=AliasChoices("REDLOOP_OPENAI_MODEL", "OPENAI_MODEL"),
    )

    apinex_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_APINEX_API_KEY", "APINEX_API_KEY"),
    )
    apinex_model: str = Field(
        default="deepseek-reasoner",
        validation_alias=AliasChoices("REDLOOP_APINEX_MODEL", "APINEX_MODEL"),
    )
    apinex_base_url: str = Field(
        default="https://api.apinex.bond/v1",
        validation_alias=AliasChoices("REDLOOP_APINEX_BASE_URL", "APINEX_BASE_URL"),
    )

    shodan_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_SHODAN_API_KEY", "SHODAN_API_KEY"),
    )

    virustotal_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("REDLOOP_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
    )
    virustotal_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("REDLOOP_VIRUSTOTAL_ENABLED", "VIRUSTOTAL_ENABLED"),
    )
    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        validation_alias=AliasChoices("REDLOOP_VIRUSTOTAL_BASE_URL", "VIRUSTOTAL_BASE_URL"),
    )

    # --- Scope / audit -------------------------------------------------------
    scope_file: Path = Path("scope.yaml")
    audit_db: Path = Field(default_factory=lambda: _default_data_dir() / "audit.db")
    memory_db: Path = Field(default_factory=lambda: _default_data_dir() / "memory.sqlite")
    scope_secret: str = ""  # HMAC signing key; generated if empty

    # --- Sandbox -------------------------------------------------------------
    sandbox_image: str = "redloop-sandbox"
    sandbox_workdir: str = "/work"
    sandbox_network: str = "none"  # only "none" is permitted by DockerSandbox
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_limit: float = 1.0
    sandbox_timeout: int = 300  # per-command seconds
    sandbox_max_retries: int = 3

    # --- Misc ----------------------------------------------------------------
    data_dir: Path = Field(default_factory=_default_data_dir)
    log_level: str = "INFO"

    def ensure_dirs(self) -> None:
        """Create the data directory tree if it does not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit_db.parent.mkdir(parents=True, exist_ok=True)
        self.memory_db.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()