"""Integration Configuration & Secrets Resolver (Phase 8).

Loads provider credentials and endpoints from environment variables or local store,
enforcing precedence and secret isolation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional


class IntegrationConfig:
    """Resolves provider configuration from environment variables or file storage."""

    @staticmethod
    def get_setting(provider_id: str, key: str, default: Optional[str] = None) -> Optional[str]:
        """Resolves configuration key with priority:
        1. Specific environment variable: REDLOOP_INTEGRATION_{PROVIDER}_{KEY}
        2. Generic environment variable: {PROVIDER}_{KEY}
        3. Config file in ~/.redloop/integrations.json
        4. Default value
        """
        p_clean = provider_id.upper().replace("-", "_")
        k_clean = key.upper().replace("-", "_")

        env_specific = f"REDLOOP_INTEGRATION_{p_clean}_{k_clean}"
        if env_specific in os.environ:
            return os.environ[env_specific]

        env_generic = f"{p_clean}_{k_clean}"
        if env_generic in os.environ:
            return os.environ[env_generic]

        # File store
        file_store = IntegrationConfig._load_file_store()
        provider_section = file_store.get(provider_id.lower(), {})
        if key in provider_section:
            return str(provider_section[key])

        return default

    @staticmethod
    def get_provider_config(provider_id: str) -> dict[str, Any]:
        """Returns all resolved settings for a provider as a dictionary."""
        p_clean = provider_id.upper().replace("-", "_")
        prefix_spec = f"REDLOOP_INTEGRATION_{p_clean}_"
        prefix_short = f"REDLOOP_{p_clean}_"
        prefix_gen = f"{p_clean}_"

        cfg: dict[str, Any] = {}
        # 1. Defaults/file store
        file_store = IntegrationConfig._load_file_store()
        cfg.update(file_store.get(provider_id.lower(), {}))

        # 2. Generic env vars
        for k, v in os.environ.items():
            if k.startswith(prefix_gen):
                setting = k[len(prefix_gen):].lower()
                cfg[setting] = v
            elif k.startswith(prefix_short):
                setting = k[len(prefix_short):].lower()
                cfg[setting] = v
            elif k.startswith(prefix_spec):
                setting = k[len(prefix_spec):].lower()
                cfg[setting] = v

        return cfg

    @staticmethod
    def _load_file_store() -> dict[str, Any]:
        """Reads local integrations.json if present."""
        try:
            path = Path.home() / ".redloop" / "integrations.json"
            if path.exists():
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    return {}
        except Exception:
            return {}
        return {}


IntegrationConfigResolver = IntegrationConfig

