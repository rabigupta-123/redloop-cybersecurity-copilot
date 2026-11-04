"""Credential Management & Secret Redaction Engine (Phase 8).

Ensures API keys, tokens, and passwords are never exposed in logs, API responses, or error traces.
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

SENSITIVE_KEY_PATTERNS = {
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "auth",
    "authorization",
    "bearer",
    "private_key",
    "client_secret",
}


def mask_secret(secret: Optional[str], prefix_len: int = 2, suffix_len: int = 2) -> str:
    """Masks sensitive strings, preserving minimal identifier characters."""
    if not secret:
        return ""
    s = str(secret).strip()
    if len(s) <= 6:
        return "******"
    prefix = s[:prefix_len]
    suffix = s[-suffix_len:]
    masked_middle = "*" * (len(s) - prefix_len - suffix_len)
    return f"{prefix}{masked_middle[:8]}{suffix}"


def is_sensitive_key(key: str) -> bool:
    """Checks whether a dictionary key name suggests sensitive content."""
    k = key.lower().replace("-", "_")
    return any(pattern in k for pattern in SENSITIVE_KEY_PATTERNS)


def mask_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively masks dictionary keys matching sensitive patterns."""
    masked: dict[str, Any] = {}
    for k, v in data.items():
        if is_sensitive_key(k):
            if isinstance(v, str):
                masked[k] = mask_secret(v)
            elif v is not None:
                masked[k] = "******"
            else:
                masked[k] = None
        elif isinstance(v, dict):
            masked[k] = mask_dict(v)
        elif isinstance(v, list):
            masked[k] = [mask_dict(item) if isinstance(item, dict) else item for item in v]
        else:
            masked[k] = v
    return masked


def sanitize_error_message(msg: str) -> str:
    """Strips authorization tokens and credentials from exception messages."""
    cleaned = re.sub(r"://([^:]+):([^@]+)@", r"://\1:******@", msg)
    cleaned = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1******", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"(ApiKey\s+)[A-Za-z0-9_\-\.]{8,}", r"\1******", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"(token=)[^&\s]+", r"\1******", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"(secret=)[^&\s]+", r"\1******", cleaned, flags=re.IGNORECASE)
    return cleaned


sanitize_config = mask_dict
safe_error_message = sanitize_error_message

