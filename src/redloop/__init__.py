"""RedLoop package initialization with lazy application factory loaders."""

from __future__ import annotations

from typing import Any

__all__ = ["create_app", "create_unified_app"]


def create_app(*args: Any, **kwargs: Any) -> Any:
    from redloop.dashboard import create_app as _create_app

    return _create_app(*args, **kwargs)


def create_unified_app(*args: Any, **kwargs: Any) -> Any:
    from redloop.unified_app import create_unified_app as _create_unified_app

    return _create_unified_app(*args, **kwargs)
