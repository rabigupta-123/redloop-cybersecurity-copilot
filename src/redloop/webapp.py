"""Non-invasive HTTP metadata inspection restricted to explicitly scoped loopback."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord
from redloop.scope import ScopeManager, UnauthorizedTargetError

MAX_TIMEOUT_SECONDS = 10
SECURITY_HEADERS = (
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
)


class WebAppCheckError(Exception):
    """Base error for the restricted web inspection."""


class UnsafeWebTargetError(WebAppCheckError):
    """Raised when the URL is outside the supported loopback-only boundary."""


class WebAppRequestError(WebAppCheckError):
    """Raised when the local HTTP request fails."""


class WebAppFinding(BaseModel):
    check: str
    severity: Literal["info", "low"]
    description: str


class WebAppReport(BaseModel):
    url: str
    status_code: int
    findings: list[WebAppFinding]


@dataclass(slots=True)
class _Target:
    host: str
    port: int
    url: str


class WebAppChecker:
    """Fetches only the root page of an explicitly scoped loopback service.

    It does not follow redirects, download response bodies, submit payloads, or
    make requests to non-loopback hosts.
    """

    def __init__(
        self,
        scope: ScopeManager,
        audit: AuditLogger,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        memory: EpisodicMemory | None = None,
    ):
        if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT_SECONDS}")
        self.scope = scope
        self.audit = audit
        self.timeout = timeout
        self.transport = transport
        self.memory = memory

    def inspect(self, url: str) -> WebAppReport:
        target = self._parse_target(url)
        try:
            address = ipaddress.ip_address(target.host)
        except ValueError:
            self.audit.log(
                target.host, "web_test", "webapp", "blocked",
                {"reason": "target must be a loopback IP literal"},
            )
            raise UnsafeWebTargetError(
                "Only literal loopback IP addresses (127.0.0.0/8 or ::1) are allowed"
            )
        if not address.is_loopback:
            self.audit.log(
                target.host, "web_test", "webapp", "blocked",
                {"reason": "target is not loopback"},
            )
            raise UnsafeWebTargetError(
                "Only literal loopback IP addresses (127.0.0.0/8 or ::1) are allowed"
            )

        try:
            scope_entry = self.scope.check(
                target.host, "web_test", port=target.port
            )
        except UnauthorizedTargetError as exc:
            self.audit.log(
                target.host,
                "web_test",
                "webapp",
                "blocked",
                {"reason": str(exc)},
            )
            raise

        self.audit.log(
            target.host,
            "web_test",
            "webapp",
            "started",
            {"port": target.port},
            scope_entry=scope_entry.label,
        )
        try:
            client_options = {
                "timeout": self.timeout,
                "follow_redirects": False,
                "trust_env": False,
            }
            if self.transport is not None:
                client_options["transport"] = self.transport
            with httpx.Client(**client_options) as client:
                with client.stream("GET", target.url) as response:
                    status_code = response.status_code
                    headers = response.headers
                    set_cookies = response.headers.get_list("set-cookie")
        except httpx.HTTPError as exc:
            self.audit.log(
                target.host,
                "web_test",
                "webapp",
                "failed",
                {"error_type": type(exc).__name__, "reason": str(exc)[:500]},
                scope_entry=scope_entry.label,
            )
            raise WebAppRequestError(
                f"Local HTTP request failed: {type(exc).__name__}"
            ) from exc

        findings = [
            WebAppFinding(
                check=header_key,
                severity="low",
                description=f"Response does not include {header_name}.",
            )
            for header_key, header_name in SECURITY_HEADERS
            if header_key not in headers
        ]
        if target.url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(
                WebAppFinding(
                    check="strict-transport-security",
                    severity="low",
                    description="HTTPS response does not include Strict-Transport-Security.",
                )
            )
        if 300 <= status_code < 400:
            findings.append(
                WebAppFinding(
                    check="redirect-not-followed",
                    severity="info",
                    description="Redirect was not followed; inspect its destination separately.",
                )
            )
        for cookie in set_cookies:
            attributes = {
                part.strip().partition("=")[0].casefold()
                for part in cookie.split(";")[1:]
            }
            cookie_name = cookie.partition("=")[0].strip()
            missing_attributes = [
                attribute
                for attribute in ("secure", "httponly", "samesite")
                if attribute not in attributes
            ]
            if missing_attributes:
                findings.append(
                    WebAppFinding(
                        check="cookie-attributes",
                        severity="low",
                        description=(
                            f"A cookie ({cookie_name or 'unnamed'}) is missing "
                            f"attributes: {', '.join(missing_attributes)}."
                        ),
                    )
                )
        if "server" in headers or "x-powered-by" in headers:
            findings.append(
                WebAppFinding(
                    check="technology-disclosure",
                    severity="info",
                    description=(
                        "Response includes Server or X-Powered-By metadata; "
                        "review whether technology details need to be exposed."
                    ),
                )
            )

        report = WebAppReport(
            url=target.url,
            status_code=status_code,
            findings=findings,
        )
        self.audit.log(
            target.host,
            "web_test",
            "webapp",
            "success",
            {
                "status_code": status_code,
                "findings_count": len(findings),
                "findings": [
                    finding.model_dump(mode="json") for finding in findings
                ],
            },
            scope_entry=scope_entry.label,
        )
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description="loopback web response metadata inspection",
                    approach="single scoped GET without redirects or body download",
                    outcome="success",
                    module="webapp",
                    details=(
                        f"status={status_code}; findings={len(findings)}"
                    ),
                )
            )
        return report

    @staticmethod
    def _parse_target(url: str) -> _Target:
        if not url or len(url) > 2_048:
            raise UnsafeWebTargetError("URL must contain 1-2048 characters")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise UnsafeWebTargetError("Malformed target URL") from exc

        if (
            parsed.scheme not in ("http", "https")
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise UnsafeWebTargetError(
                "Use an http(s) origin URL only; paths, credentials, queries, and fragments are not allowed"
            )

        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        if not 1 <= port <= 65_535:
            raise UnsafeWebTargetError("Target port must be between 1 and 65535")
        display_host = f"[{host}]" if ":" in host else host
        origin = urlunsplit((parsed.scheme, f"{display_host}:{port}", "/", "", ""))
        return _Target(host=host, port=port, url=origin)
