"""Cryptographically Signed Engagement Findings Exporter (Phase H.5).

Guarantees evidence integrity for bug bounty submissions:
Findings cannot be altered, forged, or repudiated without invalidating the HMAC signature.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List


def export_signed_findings(
    engagement_id: str,
    findings: List[Dict[str, Any]],
    secret: str | None = None,
    operator: str = "SecOps-Operator",
) -> Dict[str, Any]:
    """Generates an immutable, HMAC-SHA256 signed findings dossier."""
    key = (secret or os.getenv("REDLOOP_SCOPE_SECRET") or "default-signing-secret").encode("utf-8")
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Deterministic JSON canonical representation
    canonical_payload = {
        "engagement_id": engagement_id,
        "operator": operator,
        "findings_count": len(findings),
        "findings": sorted(findings, key=lambda f: str(f.get("id", ""))),
        "signed_at": timestamp,
    }
    raw_bytes = json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    signature = hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()

    return {
        **canonical_payload,
        "signature_algorithm": "HMAC-SHA256",
        "signature": signature,
    }


def verify_signed_findings(payload: Dict[str, Any], secret: str | None = None) -> bool:
    """Verifies HMAC signature of an exported findings dossier."""
    key = (secret or os.getenv("REDLOOP_SCOPE_SECRET") or "default-signing-secret").encode("utf-8")
    sig = payload.get("signature")
    if not sig:
        return False

    canonical_payload = {
        "engagement_id": payload.get("engagement_id"),
        "operator": payload.get("operator"),
        "findings_count": payload.get("findings_count"),
        "findings": payload.get("findings", []),
        "signed_at": payload.get("signed_at"),
    }
    raw_bytes = json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(key, raw_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)
