"""Engagement-Scoped Profiles Architecture (Phase B).

Enforces machine-verifiable, signed engagement scopes.
Replaces any notion of 'no scope' with configurable, signed engagements:
- B.1: EngagementScope data model with HMAC-SHA256 signing and fail-closed validation.
- B.2: Scope import and parsing flow with mandatory operator review and signature.
- B.3: Self-authorized flow with required ownership confirmation and identical audit logging.
- B.4: Wildcard (*.target.com) and CIDR (ipaddress module containment) matching with out-of-scope priority.
- B.5: Fast single-call active engagement switching with audit logging and mid-flight immutability.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from redloop.audit import AuditLogger


class UnauthorizedEngagementError(Exception):
    """Raised when an engagement is missing, unsigned, expired, tampered, or inactive."""


class EngagementTarget(BaseModel):
    """An authorized in-scope target specification."""

    model_config = ConfigDict(extra="allow")

    pattern: str  # host, IP, CIDR (e.g. 192.0.2.0/24), or wildcard (*.example.com)
    ports: list[int] | None = None
    allowed_methods: list[str] = Field(
        default_factory=lambda: [
            "scan", "assess", "recon", "web_test", "web_check",
            "tls_check", "api_check", "network_discovery", "tool_ports",
            "tool_nikto", "tool_gobuster", "tool_tls", "tool_web", "tool_api",
        ]
    )
    description: str = ""

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is not None and any(
            isinstance(port, bool) or not 1 <= port <= 65_535 for port in value
        ):
            raise ValueError("ports must be between 1 and 65535")
        return value


class EngagementOutOfScope(BaseModel):
    """An explicitly excluded out-of-scope target range or domain."""

    model_config = ConfigDict(extra="allow")

    pattern: str  # host, IP, CIDR, or wildcard
    description: str = ""


def pattern_matches_target(pattern: str, target: str) -> bool:
    """Efficiently check whether a target falls under a CIDR, wildcard, or host pattern.

    Uses ipaddress module for CIDR containment (never string prefix matching).
    Wildcard subdomain (*.domain.com or .domain.com) matches domain.com and any subdomains.
    Out-of-scope patterns always use this same matcher.
    """
    pattern = pattern.strip()
    target = target.strip()
    if not pattern or not target:
        return False

    # 1. CIDR / IP Containment Check
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            try:
                tgt_ip = ipaddress.ip_address(target)
                return tgt_ip in net
            except ValueError:
                # Target is not an IP literal
                return False
        except ValueError:
            return False

    # Bare IP check
    try:
        pat_ip = ipaddress.ip_address(pattern)
        try:
            tgt_ip = ipaddress.ip_address(target)
            return tgt_ip == pat_ip
        except ValueError:
            return False
    except ValueError:
        pass

    # 2. Domain / Wildcard matching
    tgt_clean = target.lower().strip(".")
    pat_clean = pattern.lower().strip(".")

    # Remove port or schema if accidentally passed in target
    if "://" in tgt_clean:
        from urllib.parse import urlsplit
        parts = urlsplit(tgt_clean)
        tgt_clean = (parts.hostname or tgt_clean).lower().strip(".")
    if ":" in tgt_clean and not tgt_clean.count(":") > 1:  # ignore IPv6
        tgt_clean = tgt_clean.split(":")[0]

    # Wildcard prefix
    if pat_clean.startswith("*."):
        base = pat_clean[2:]
        return tgt_clean == base or tgt_clean.endswith(f".{base}")

    if pat_clean.startswith("."):
        base = pat_clean.lstrip(".")
        return tgt_clean == base or tgt_clean.endswith(f".{base}")

    # Exact or sub-domain
    if tgt_clean == pat_clean or tgt_clean.endswith(f".{pat_clean}"):
        return True

    return False


class EngagementScope(BaseModel):
    """Engagement-scoped authorization profile (B.1)."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: f"eng-{uuid.uuid4().hex[:10]}")
    name: str = "Engagement"
    source: Literal["imported", "self_authorized"] = "imported"
    program_url: str | None = None
    targets: list[EngagementTarget] = Field(default_factory=list)
    out_of_scope: list[EngagementOutOfScope] = Field(default_factory=list)
    rate_limit: int | None = None  # Requests per second
    rules_text: str = ""
    signed_by: str = ""
    signed_at: str = ""
    expires_at: datetime
    active: bool = False
    signature: str = ""

    @field_validator("expires_at")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value

    def is_within_window(self) -> bool:
        """Verify engagement has not expired."""
        return datetime.now(timezone.utc) <= self.expires_at.astimezone(timezone.utc)

    def is_validly_signed(self, secret: str) -> bool:
        """Verify the HMAC signature of this engagement document."""
        if not secret or not self.signature:
            return False
        return verify_engagement_scope(self, secret, self.signature)

    def check_target(
        self,
        target: str,
        port: int | None = None,
        action: str | None = None,
        require_port: bool = True,
    ) -> tuple[bool, str, EngagementTarget | None]:
        """Check target against this engagement's in-scope and out-of-scope rules.

        Strict Fail-Closed Precedence:
        1. Window expiry check
        2. Out-of-scope entries STRICTLY override in-scope wildcards / CIDRs.
        3. In-scope target matching (pattern, port restriction, allowed methods).
        """
        if not self.is_within_window():
            return False, f"Engagement scope '{self.name}' ({self.id}) is expired", None

        # 1. Out-of-scope check (Strict Override)
        for oos in self.out_of_scope:
            if pattern_matches_target(oos.pattern, target):
                return (
                    False,
                    f"Target '{target}' matches out-of-scope entry '{oos.pattern}' ({oos.description or 'explicitly excluded'})",
                    None,
                )

        # 2. In-scope matching
        matched_target: EngagementTarget | None = None
        for entry in self.targets:
            if pattern_matches_target(entry.pattern, target):
                matched_target = entry
                break

        if not matched_target:
            return False, f"Target '{target}' is not present in engagement scope '{self.name}'", None

        # 3. Port check
        if matched_target.ports is not None:
            if port is None and require_port:
                return (
                    False,
                    f"Target '{target}' restricts access to ports {matched_target.ports} but no port was specified",
                    matched_target,
                )
            if port is not None and port not in matched_target.ports:
                return (
                    False,
                    f"Port {port} is not authorized for target '{target}' (authorized: {matched_target.ports})",
                    matched_target,
                )

        # 4. Method / Action check
        if action is not None and matched_target.allowed_methods:
            if action not in matched_target.allowed_methods:
                return (
                    False,
                    f"Action '{action}' is not authorized on target '{target}' (authorized: {matched_target.allowed_methods})",
                    matched_target,
                )

        return True, "AUTHORIZED", matched_target


def sign_engagement_scope(document: EngagementScope | dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 signature over canonical JSON representation."""
    if not secret:
        raise ValueError("Engagement scope signing secret must not be empty")

    if isinstance(document, EngagementScope):
        doc_dict = document.model_dump(mode="json", exclude={"signature", "active"})
    else:
        doc_dict = EngagementScope(**document).model_dump(mode="json", exclude={"signature", "active"})

    canonical = json.dumps(doc_dict, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_engagement_scope(document: EngagementScope | dict[str, Any], secret: str, signature: str) -> bool:
    """Verify HMAC signature for engagement scope."""
    if not secret or not signature:
        return False
    expected = sign_engagement_scope(document, secret)
    return hmac.compare_digest(expected, signature)


def parse_engagement_scope_text(
    text: str,
    name: str = "Imported Program Scope",
    program_url: str | None = None,
    expires_in_days: int = 30,
) -> dict[str, Any]:
    """Parse raw scope text or URL scope section into structured engagement data (B.2)."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]

    targets: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    rate_limit: int | None = None

    is_out_of_scope_section = False

    for line in lines:
        lower = line.lower()

        # Section header detection
        if any(h in lower for h in ("out of scope", "out-of-scope", "excluded targets", "not in scope")):
            is_out_of_scope_section = True
            continue
        elif any(h in lower for h in ("in scope", "in-scope", "authorized targets", "target list", "scope:")):
            is_out_of_scope_section = False
            continue

        # Rate limit detection
        rate_m = re.search(r"\b(?:rate\s*limit|limit:?)\s*[:=]?\s*(\d+)\s*(?:req|rps|requests)?", lower)
        if rate_m:
            try:
                rate_limit = int(rate_m.group(1))
            except ValueError:
                pass
            continue

        # Clean markdown table or list artifacts
        clean = re.sub(r"^\s*(?:[-*#|>]|\d+\.)\s+", "", line).strip().strip("| \t")

        # Extract tokens matching CIDRs, IPs, wildcards, or domains
        tokens = re.findall(
            r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?:\*\.)?[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+",
            clean,
        )

        for tok in tokens:
            # Check port specifiers e.g. :80, :443 or (80, 443)
            ports: list[int] | None = None
            port_match = re.search(r":(\d{1,5})", clean)
            if port_match:
                p_val = int(port_match.group(1))
                if 1 <= p_val <= 65535:
                    ports = [p_val]

            if is_out_of_scope_section:
                out_of_scope.append({"pattern": tok, "description": clean})
            else:
                targets.append({"pattern": tok, "ports": ports, "description": clean})

    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    return {
        "id": f"eng-{uuid.uuid4().hex[:10]}",
        "name": name,
        "source": "imported",
        "program_url": program_url,
        "targets": targets,
        "out_of_scope": out_of_scope,
        "rate_limit": rate_limit,
        "rules_text": text[:2000],
        "signed_by": "",
        "signed_at": "",
        "expires_at": expires_at.isoformat(),
        "active": False,
        "signature": "",
    }


def create_self_authorized_scope(
    name: str,
    targets: list[dict[str, Any] | EngagementTarget],
    out_of_scope: list[dict[str, Any] | EngagementOutOfScope] | None = None,
    rate_limit: int | None = None,
    rules_text: str = "",
    secret: str = "",
    signer_identity: str = "operator",
    i_own_or_authorized: bool = False,
    audit: AuditLogger | None = None,
    expires_in_days: int = 30,
) -> EngagementScope:
    """Create and HMAC-sign a self-authorized engagement scope (B.3).

    Requires explicit ownership/authorization confirmation checkbox.
    Logged identically to imported scope with HMAC signature.
    """
    if not i_own_or_authorized:
        raise UnauthorizedEngagementError(
            "Self-authorization requires confirming asset ownership or explicit authorization checkbox"
        )
    if not secret:
        raise ValueError("Operator secret required to sign self-authorized engagement")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=expires_in_days)

    target_objs = [
        t if isinstance(t, EngagementTarget) else EngagementTarget(**t) for t in targets
    ]
    oos_objs = [
        o if isinstance(o, EngagementOutOfScope) else EngagementOutOfScope(**o)
        for o in (out_of_scope or [])
    ]

    eng = EngagementScope(
        id=f"eng-self-{uuid.uuid4().hex[:8]}",
        name=name,
        source="self_authorized",
        program_url=None,
        targets=target_objs,
        out_of_scope=oos_objs,
        rate_limit=rate_limit,
        rules_text=rules_text or "Self-authorized operator scope",
        signed_by=signer_identity,
        signed_at=now.isoformat(),
        expires_at=expires_at,
        active=False,
    )

    sig = sign_engagement_scope(eng, secret)
    eng.signature = sig

    if audit:
        audit.log(
            eng.id,
            "engagement_created",
            "engagement",
            "success",
            {
                "name": eng.name,
                "source": "self_authorized",
                "target_count": len(eng.targets),
                "out_of_scope_count": len(eng.out_of_scope),
                "expires_at": eng.expires_at.isoformat(),
                "signature": sig,
            },
        )

    return eng


class EngagementManager:
    """Manages active and registered engagement profiles (B.1, B.5).

    Only one engagement active per operator session at a time.
    Enforces HMAC verification, expiration checks, and mid-flight immutability.
    """

    def __init__(self, secret: str | None = None, audit: AuditLogger | None = None):
        self.secret = secret or ""
        self.audit = audit
        self._engagements: dict[str, EngagementScope] = {}
        self._active_id: str | None = None

    @property
    def active_id(self) -> str | None:
        return self._active_id

    def get_active_engagement(self) -> EngagementScope | None:
        if not self._active_id:
            return None
        eng = self._engagements.get(self._active_id)
        if eng and eng.is_validly_signed(self.secret) and eng.is_within_window():
            return eng
        return None

    def register_engagement(self, engagement: EngagementScope) -> None:
        """Register an engagement into memory. Must be validly signed before activation."""
        self._engagements[engagement.id] = engagement

    def set_active_engagement(
        self,
        engagement_id: str,
        operator: str = "operator",
    ) -> EngagementScope:
        """Fast switch active engagement profile in one call (B.5).

        Logs audit ledger entry.
        Prior mid-flight operations retain their original approved scope and are NOT widened.
        """
        if engagement_id not in self._engagements:
            raise UnauthorizedEngagementError(f"Engagement '{engagement_id}' not found")

        eng = self._engagements[engagement_id]

        # Signature verification is mandatory
        if not self.secret or not eng.signature:
            raise UnauthorizedEngagementError(
                f"Engagement '{engagement_id}' is unsigned or no signing key was provided — fail closed"
            )

        if not eng.is_validly_signed(self.secret):
            raise UnauthorizedEngagementError(
                f"Engagement '{engagement_id}' signature is invalid — tampered or corrupted"
            )

        if not eng.is_within_window():
            raise UnauthorizedEngagementError(
                f"Engagement '{engagement_id}' has expired ({eng.expires_at.isoformat()}) — refusing to activate"
            )

        prev_id = self._active_id
        # Deactivate previous
        if prev_id and prev_id in self._engagements:
            self._engagements[prev_id].active = False

        eng.active = True
        self._active_id = eng.id

        if self.audit:
            self.audit.log(
                eng.id,
                "engagement_switched",
                "engagement",
                "success",
                {
                    "previous_active": prev_id,
                    "new_active": eng.id,
                    "name": eng.name,
                    "source": eng.source,
                    "signature": eng.signature,
                    "operator": operator,
                },
            )

        return eng

    def list_engagements(self) -> list[dict[str, Any]]:
        """List all registered engagements with activation and validation status."""
        out = []
        for eng in self._engagements.values():
            valid_sig = eng.is_validly_signed(self.secret) if self.secret else False
            in_window = eng.is_within_window()
            out.append({
                "id": eng.id,
                "name": eng.name,
                "source": eng.source,
                "program_url": eng.program_url,
                "target_count": len(eng.targets),
                "out_of_scope_count": len(eng.out_of_scope),
                "rate_limit": eng.rate_limit,
                "signed_by": eng.signed_by,
                "signed_at": eng.signed_at,
                "expires_at": eng.expires_at.isoformat(),
                "active": eng.id == self._active_id,
                "valid_signature": valid_sig,
                "is_expired": not in_window,
            })
        return out

