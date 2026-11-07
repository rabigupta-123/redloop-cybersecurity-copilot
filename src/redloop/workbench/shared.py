"""Shared utilities, state, and security helpers for workbench routers."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from pathlib import Path
from typing import Any
from fastapi import HTTPException, Request


def is_loopback_request(request: Request) -> bool:
    """Validate that the request originates from a loopback address."""
    client_host = getattr(request.client, "host", None) if request.client else None
    if not client_host:
        return True
    try:
        ip = ipaddress.ip_address(client_host)
        return ip.is_loopback
    except ValueError:
        return client_host in ("localhost", "127.0.0.1", "::1")


def require_same_origin(request: Request) -> None:
    """Enforce same-origin header verification against CSRF."""
    host = request.headers.get("host", "").lower()
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if origin:
        origin_clean = origin.split("://")[-1].rstrip("/")
        if origin_clean != host and not origin_clean.startswith("localhost") and not origin_clean.startswith("127.0.0.1"):
            raise HTTPException(status_code=403, detail="Cross-origin request forbidden")

    if referer and not origin:
        referer_clean = referer.split("://")[-1].split("/")[0].rstrip("/")
        if referer_clean != host and not referer_clean.startswith("localhost") and not referer_clean.startswith("127.0.0.1"):
            raise HTTPException(status_code=403, detail="Cross-origin referer forbidden")


def get_active_operator_token(auth_mgr: Any = None) -> str | None:
    """Retrieve the operator token fingerprint or value from environment / config."""
    return os.environ.get("REDLOOP_OPERATOR_TOKEN")


def get_operator_identity() -> str:
    """Return verified operator identity from server configuration."""
    return os.environ.get("REDLOOP_OPERATOR_NAME", "local-sec-operator")
