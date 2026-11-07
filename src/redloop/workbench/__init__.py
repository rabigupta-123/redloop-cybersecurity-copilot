"""Workbench package exposing modular routers and legacy registration facade."""
from __future__ import annotations

from typing import Any
from fastapi import FastAPI

# Re-export all historical workbench functionality for backward compatibility
from redloop.workbench.legacy_workbench import *

# Modular routers extracted under Phase 7.1
from redloop.workbench.router_assets import router as router_assets
from redloop.workbench.router_copilot import router as router_copilot
from redloop.workbench.router_ctf import router as router_ctf
from redloop.workbench.router_diagnostics import router as router_diagnostics
from redloop.workbench.router_integrations import router as router_integrations
from redloop.workbench.router_investigations import router as router_investigations
from redloop.workbench.router_reporting import router as router_reporting
from redloop.workbench.router_soc import router as router_soc

ALL_ROUTERS = [
    router_assets,
    router_copilot,
    router_ctf,
    router_diagnostics,
    router_integrations,
    router_investigations,
    router_reporting,
    router_soc,
]


def register_workbench_routers(app: FastAPI) -> None:
    """Register extracted modular workbench routers into FastAPI app."""
    for r in ALL_ROUTERS:
        app.include_router(r)
