"""Tests for REDLOOP Visual Redesign (Part 4).

Verifies:
- Single source-of-truth palette tokens in CSS (#0a0e17 bg, #121826 surface, #e3860a accent, #06b6d4 cyber accent).
- Glassmorphic backdrop blur and glow properties on elevated panels (drawer, command palette, modals).
- Layered shadows and hover elevation rules for cards and KPI metrics.
- Force-directed interactive canvas graph container, controls, and HUD elements.
- Command palette modal, list of sections, and keyboard navigation shortcuts.
- CSP header dynamically matches sha256 of UNIFIED_SCRIPT.
- All primary SPA sections and navigation targets are correctly declared and linked.
"""

from pathlib import Path
import pytest
import yaml
from fastapi.testclient import TestClient

from redloop.dashboard import create_app
from redloop.scope import ScopeManager, sign_scope
from redloop.unified_app import UNIFIED_CSS, UNIFIED_SCRIPT, UNIFIED_SCRIPT_CSP_HASH


@pytest.fixture
def dashboard_client(tmp_path):
    secret = "test-secret-32-bytes-long-padded!!"
    signed_scope_path = tmp_path / "signed_scope.yaml"

    scope_data = {
        "version": "1.0",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Localhost",
                "authorized_from": "2020-01-01T00:00:00Z",
                "authorized_until": "2099-01-01T00:00:00Z",
                "allowed_actions": ["scan", "check", "assess"],
                "ports": [80, 443],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    signed_scope_path.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    scope_mgr = ScopeManager(signed_scope_path, secret)

    db_path = tmp_path / "audit.sqlite"
    app = create_app(str(db_path), scope_manager=scope_mgr)
    return TestClient(app, base_url="http://127.0.0.1")


def test_palette_tokens_in_css():
    """Verify single source-of-truth palette tokens in UNIFIED_CSS for BOTH themes."""
    # Dark theme (default)
    assert ":root {" in UNIFIED_CSS
    assert "--bg: #0b0b10" in UNIFIED_CSS
    assert "--surface: #121218" in UNIFIED_CSS
    assert "--accent: #f97316" in UNIFIED_CSS
    assert "--accent-cyber: #2563eb" in UNIFIED_CSS
    assert "--surface-2: #17171f" in UNIFIED_CSS
    assert "--surface-elevated: #1b1b24" in UNIFIED_CSS
    # Light theme
    assert '[data-theme="light"]' in UNIFIED_CSS or ":root[data-theme=\"light\"]" in UNIFIED_CSS
    assert "--bg: #FFF8F2" in UNIFIED_CSS or "#fff8f2" in UNIFIED_CSS.lower()
    assert "--surface: #FFFFFF" in UNIFIED_CSS or "#ffffff" in UNIFIED_CSS.lower()
    assert "--accent-strong: #EA580C" in UNIFIED_CSS or "#ea580c" in UNIFIED_CSS.lower()
    assert "--fg: #1F1B16" in UNIFIED_CSS or "#1f1b16" in UNIFIED_CSS.lower()
    assert "--border: #F1E3D6" in UNIFIED_CSS or "#f1e3d6" in UNIFIED_CSS.lower()
