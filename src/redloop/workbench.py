"""Backwards-compatible facade for redloop.workbench package.

In Phase 7, routes were modularized into:
- redloop.workbench.router_investigations
- redloop.workbench.router_ctf
- redloop.workbench.router_copilot
- redloop.workbench.router_integrations
- redloop.workbench.router_soc
- redloop.workbench.router_reporting
- redloop.workbench.router_assets
- redloop.workbench.router_diagnostics
- redloop.workbench.shared

This module re-exports all symbols from the redloop.workbench package to preserve
100% backward compatibility with existing tests and imports.
"""
from __future__ import annotations

from redloop.workbench import *
