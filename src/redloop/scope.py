"""ScopeManager: the authorization gate for every RedLoop action.

Design rules (fail-closed):
  * A target is only authorized if it matches an entry in scope.yaml AND the
    current date falls inside that entry's authorized window.
  * Any parse error, missing file, or non-match raises UnauthorizedTargetError.
  * Scope is HMAC-signed so a stale or tampered scope.yaml is rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class UnauthorizedTargetError(Exception):
    """Raised when a target/action is not covered by the signed scope."""


class ScopeEntry(BaseModel):
    """One authorized target range and the actions permitted on it."""

    model_config = ConfigDict(extra="allow")

    cidr: str | None = None
    domain: str | None = None
    label: str = "unlabeled"
    authorized_from: date
    authorized_until: date
    allowed_actions: list[str] = Field(default_factory=list)
    ports: list[int] | None = None
    notes: str = ""

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, v: str | None) -> str | None:
        if v is None:
            return v
        ipaddress.ip_network(v, strict=False)  # raises ValueError if malformed
        return v

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is not None and any(
            isinstance(port, bool) or not 1 <= port <= 65_535 for port in value
        ):
            raise ValueError("ports must be between 1 and 65535")
        return value

    def matches(self, target: str) -> bool:
        """Return True if `target` (IP literal or hostname) falls under this entry."""
        if self.cidr:
            try:
                network = ipaddress.ip_network(self.cidr, strict=False)
                return ipaddress.ip_address(target) in network
            except ValueError:
                return False
        if self.domain:
            return target == self.domain or target.endswith(f".{self.domain}")
        return False

    def action_allowed(self, action: str) -> bool:
        return action in self.allowed_actions


class ScopeFile(BaseModel):
    """Top-level scope.yaml schema."""

    model_config = ConfigDict(extra="allow")

    version: int = 1
    id: str = "default"
    authorized_by: str = ""
    signed_at: str = ""
    expires_at: datetime
    targets: list[ScopeEntry] = Field(default_factory=list)
    notes: str = ""
    signature: str = ""

    @field_validator("expires_at")
    @classmethod
    def _require_expiry_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value


def sign_scope(raw: dict[str, Any], secret: str) -> str:
    """Compute the HMAC-SHA256 signature for a scope document."""
    if not secret:
        raise ValueError("scope signing secret must not be empty")
    document = ScopeFile(**raw).model_dump(mode="json", exclude={"signature"})
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_scope(raw: dict[str, Any], secret: str, signature: str) -> bool:
    if not secret or not signature:
        return False
    expected = sign_scope(raw, secret)
    return hmac.compare_digest(expected, signature)


class ScopeManager:
    """Loads, verifies, and enforces the signed scope.yaml."""

    def __init__(self, scope_file: str | Path = "scope.yaml", secret: str | None = None):
        self.scope_file = Path(scope_file)
        self.secret = secret or ""
        if not self.scope_file.exists():
            raise FileNotFoundError(
                f"scope file not found at {self.scope_file} — refusing to run"
            )
        raw = yaml.safe_load(self.scope_file.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("scope.yaml must contain a mapping at the top level")
        self.raw = raw
        self.scope = ScopeFile(**raw)

        # Signature verification is mandatory; an unsigned scope is not trusted.
        if not self.secret or not self.scope.signature:
            raise UnauthorizedTargetError(
                "scope.yaml signature is missing or no signing secret was provided"
            )
        if not verify_scope(raw, self.secret, self.scope.signature):
            raise UnauthorizedTargetError(
                "scope.yaml signature is invalid — file may be tampered or stale"
            )

    # -- public API -----------------------------------------------------------
    def check(
        self,
        target: str,
        action: str,
        port: int | None = None,
        *,
        require_port: bool = True,
    ) -> ScopeEntry:
        """Authorize `action` against `target`. Raises if not permitted.

        Fail-closed port semantics: when the matched entry restricts ports and
        `require_port` is true, omitting `port` is denied instead of treated as
        "all ports allowed". Callers performing non-network checks must opt out
        explicitly with `require_port=False`.
        """
        if not self.is_within_window():
            raise UnauthorizedTargetError(
                "scope.yaml is expired — refusing to act"
            )
        today = date.today()
        for entry in self.scope.targets:
            if not entry.matches(target):
                continue
            if not (entry.authorized_from <= today <= entry.authorized_until):
                raise UnauthorizedTargetError(
                    f"{target} matched scope entry '{entry.label}' but is outside the "
                    f"authorized window ({entry.authorized_from} .. {entry.authorized_until})"
                )
            if not entry.action_allowed(action):
                raise UnauthorizedTargetError(
                    f"'{action}' is not permitted on {target} "
                    f"(allowed: {entry.allowed_actions or 'none'})"
                )
            if port is not None and (
                entry.ports is None or port not in entry.ports
            ):
                raise UnauthorizedTargetError(
                    f"port {port} is not explicitly authorized for {target}"
                )
            if (
                port is None
                and entry.ports is not None
                and require_port
            ):
                raise UnauthorizedTargetError(
                    f"no port was specified for {target} but scope entry "
                    f"'{entry.label}' restricts operations to ports "
                    f"{entry.ports} — refusing port-agnostic access"
                )
            return entry
        raise UnauthorizedTargetError(
            f"{target} is not present in scope.yaml — refusing to act"
        )

    def require(self, target: str, action: str) -> ScopeEntry:
        """Alias for check(); reads like a precondition guard."""
        return self.check(target, action)

    def is_target_in_scope(self, target: str) -> bool:
        """Return True if target matches an active entry, ignoring action/port."""
        if not self.is_within_window():
            return False
        today = date.today()
        return any(
            entry.matches(target)
            and entry.authorized_from <= today <= entry.authorized_until
            for entry in self.scope.targets
        )

    def is_authorized(self, target: str, action: str = "assess", port: int | None = None) -> bool:
        """Return True if target and action are explicitly authorized under active scope."""
        try:
            self.check(target, action, port=port, require_port=False)
            return True
        except Exception:
            return False

    def is_within_window(self) -> bool:
        return datetime.now(timezone.utc) <= self.scope.expires_at.astimezone(
            timezone.utc
        )