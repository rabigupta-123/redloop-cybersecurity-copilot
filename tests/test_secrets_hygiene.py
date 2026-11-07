"""Unit tests for S5: Secrets hygiene, patterns check, and scope secret rotation."""
from __future__ import annotations

import datetime
from pathlib import Path
import re
import pytest
import yaml

from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope, verify_scope


SECRET_PATTERNS = [
    re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"AIza[a-zA-Z0-9_\-]{30,}"),
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
]


def test_no_hardcoded_secrets_in_src_tree():
    src_dir = Path("src/redloop")
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="replace")
        for pat in SECRET_PATTERNS:
            matches = pat.findall(content)
            # Ensure no real keys exist in code
            assert not matches, f"Hardcoded secret pattern found in {py_file}: {matches}"


def test_scope_rotate_secret_resigns_and_verifies(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    today = datetime.date.today().isoformat()
    raw = {
        "version": 1,
        "id": "rotate-test",
        "authorized_by": "sec_lead",
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat(),
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today,
                "authorized_until": today,
                "allowed_actions": ["scan"],
                "ports": [80],
            }
        ],
    }
    old_secret = "initial-secret-1234567890abcdef"
    raw["signature"] = sign_scope(raw, old_secret)
    scope_file.write_text(yaml.safe_dump(raw), encoding="utf-8")

    # Verify old scope
    sm_old = ScopeManager(scope_file=scope_file, secret=old_secret)
    assert sm_old.is_authorized("127.0.0.1", "scan", port=80)

    # Perform rotation
    new_secret = "new-rotated-secret-0987654321fedcba"
    raw_to_rotate = yaml.safe_load(scope_file.read_text(encoding="utf-8"))
    new_sig = sign_scope(raw_to_rotate, new_secret)
    raw_to_rotate["signature"] = new_sig
    scope_file.write_text(yaml.safe_dump(raw_to_rotate), encoding="utf-8")

    # Old secret should fail
    with pytest.raises(Exception):
        ScopeManager(scope_file=scope_file, secret=old_secret)

    # New secret succeeds
    sm_new = ScopeManager(scope_file=scope_file, secret=new_secret)
    assert sm_new.is_authorized("127.0.0.1", "scan", port=80)
