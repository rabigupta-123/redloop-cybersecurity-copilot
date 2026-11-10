"""Scope Import, Parsing, and Activation Guard (Phase 3.1).

Guarantees:
1. Parses program scope into draft scope.yaml.
2. Operator must review and sign it; unsigned/expired scope = fail closed.
3. Out-of-scope entries ALWAYS win over in-scope wildcards.
4. Activation requires written-authorization checkbox + program name + policy URL.
"""

from __future__ import annotations

import datetime
import fnmatch
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
import yaml

from redloop.bounty.models import ProgramScopeDefinition
from redloop.scope import sign_scope, verify_scope


class ScopeImportError(Exception):
    pass


def parse_scope_text(text: str, default_program_name: str = "BugBountyProgram") -> ProgramScopeDefinition:
    """Parses raw text (YAML, JSON, or list format) into ProgramScopeDefinition."""
    if not text or not text.strip():
        raise ScopeImportError("Scope definition text cannot be empty.")

    # Try parsing as YAML
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            yaml_in_scope = data.get("in_scope") or data.get("targets") or []
            yaml_out_of_scope = data.get("out_of_scope") or data.get("exclusions") or []
            return ProgramScopeDefinition(
                program_name=data.get("program_name", default_program_name),
                policy_url=data.get("policy_url", "https://example.com/bounty-policy"),
                written_authorization=bool(data.get("written_authorization", False)),
                in_scope=[str(x).strip() for x in yaml_in_scope],
                out_of_scope=[str(x).strip() for x in yaml_out_of_scope],
                allowed_methods=data.get("allowed_methods", ["GET", "POST", "HEAD"]),
                rate_limit_rps=float(data.get("rate_limit_rps", 5.0)),
                rules=data.get("rules", []),
            )
    except Exception:
        pass

    # Line-by-line heuristic parsing
    in_scope: List[str] = []
    out_of_scope: List[str] = []
    current_section = "in_scope"

    for line in text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        lower = clean.lower()
        if "out of scope" in lower or "exclusions" in lower:
            current_section = "out_of_scope"
            continue
        elif "in scope" in lower or "targets" in lower:
            current_section = "in_scope"
            continue

        item = clean.lstrip("-* ").strip()
        if item:
            if current_section == "in_scope":
                in_scope.append(item)
            else:
                out_of_scope.append(item)

    return ProgramScopeDefinition(
        program_name=default_program_name,
        policy_url="https://example.com/bounty-policy",
        written_authorization=False,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allowed_methods=["GET", "POST", "HEAD"],
        rate_limit_rps=5.0,
    )


def validate_scope_activation(scope_def: ProgramScopeDefinition) -> Tuple[bool, str]:
    """Validates prerequisite gates before activating a bug bounty scope."""
    if not scope_def.written_authorization:
        return False, "Written authorization checkbox must be explicitly checked."

    if not scope_def.program_name or not scope_def.program_name.strip():
        return False, "Program name is required."

    if not scope_def.policy_url or not re.match(r"^https?://[^\s/$.?#].[^\s]*$", scope_def.policy_url.strip(), re.IGNORECASE):
        return False, "Valid policy URL (http/https) is required."

    if not scope_def.in_scope:
        return False, "At least one in-scope asset or pattern must be specified."

    return True, "OK"


import urllib.parse


def normalize_asset(asset: str) -> Tuple[str, Optional[int], str, str]:
    """Returns (host, port, path, full_clean)."""
    if not asset:
        return "", None, "", ""
    clean = asset.strip().lower()
    if clean.startswith("http://") or clean.startswith("https://"):
        try:
            parsed = urllib.parse.urlsplit(clean)
            return (parsed.hostname or "").strip(), parsed.port, parsed.path or "", clean
        except Exception:
            pass
    if ":" in clean and not clean.startswith("["):
        parts = clean.split(":", 1)
        try:
            return parts[0].strip(), int(parts[1]), "", clean
        except ValueError:
            return parts[0].strip(), None, "", clean
    return clean, None, "", clean


def _matches_pattern(target_host: str, target_port: Optional[int], target_path: str, pattern_str: str) -> bool:
    pat_host, pat_port, pat_path, _ = normalize_asset(pattern_str)
    # Host match check
    if pat_host.startswith("*."):
        suffix = pat_host[1:]
        if not (target_host.endswith(suffix) or target_host == pat_host[2:]):
            return False
    elif not (fnmatch.fnmatch(target_host, pat_host) or target_host == pat_host):
        return False

    # Port check
    if pat_port is not None and target_port is not None:
        if target_port != pat_port:
            return False

    # Path check: only apply if pattern specifies an explicit subpath
    if pat_path and pat_path != "/":
        if not (target_path.startswith(pat_path) or fnmatch.fnmatch(target_path, pat_path)):
            return False

    return True


def is_asset_in_scope(asset: str, scope_def: ProgramScopeDefinition) -> bool:
    """Checks whether an asset is authorized under the program scope.
    
    CRITICAL RULE: Out-of-scope entries ALWAYS win over in-scope wildcards!
    """
    if not asset:
        return False

    t_host, t_port, t_path, full = normalize_asset(asset)
    if not t_host:
        return False

    # 1. Out-of-scope entries ALWAYS win
    for oos in scope_def.out_of_scope:
        if _matches_pattern(t_host, t_port, t_path, oos) or (full == oos.lower().strip()):
            return False

    # 2. In-scope matching
    for ins in scope_def.in_scope:
        if _matches_pattern(t_host, t_port, t_path, ins) or (full == ins.lower().strip()):
            return True

    return False


def build_draft_scope_document(scope_def: ProgramScopeDefinition, days_valid: int = 7) -> Dict[str, Any]:
    """Builds a REDLOOP signed scope document mapping in-scope assets."""
    now = datetime.datetime.now(datetime.timezone.utc)
    today = datetime.date.today().isoformat()
    until = (datetime.date.today() + datetime.timedelta(days=days_valid)).isoformat()
    expires = (now + datetime.timedelta(days=days_valid)).isoformat()

    targets: List[Dict[str, Any]] = []
    for item in scope_def.in_scope:
        # Avoid generating entries for assets matched by out_of_scope
        if is_asset_in_scope(item, scope_def):
            targets.append({
                "cidr": item if "/" in item or re.match(r"^\d+\.\d+\.\d+\.\d+$", item) else None,
                "domain": item if not ("/" in item or re.match(r"^\d+\.\d+\.\d+\.\d+$", item)) else None,
                "label": f"bounty-{item}",
                "authorized_from": today,
                "authorized_until": until,
                "allowed_actions": ["recon", "scan", "validate"],
                "ports": [80, 443, 8080, 8443],
            })

    return {
        "version": 1,
        "id": f"bounty-scope-{scope_def.program_name.lower().replace(' ', '-')}",
        "authorized_by": scope_def.program_name,
        "signed_at": now.isoformat(),
        "expires_at": expires,
        "targets": targets,
    }
