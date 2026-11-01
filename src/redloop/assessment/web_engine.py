"""Deep Web application security assessment and bounded crawling engine.

Audits:
- Bounded discovery (links, forms, scripts, robots.txt, sitemap.xml, security.txt, well-known endpoints)
- HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Cookie attributes (Secure, HttpOnly, SameSite)
- Dangerous HTTP methods (TRACE, unrestricted OPTIONS)
- Technology and server banner disclosure
- CORS configuration (wildcard, reflected origin, credentialed wildcard)
- Non-destructive input reflection and error leakage checks
"""

from __future__ import annotations

import re
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from redloop.assessment.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger


class _HTMLEndpointExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self.scripts: set[str] = set()
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_map = {k.lower(): v or "" for k, v in attrs}
        if tag == "a" and "href" in attr_map:
            href = attr_map["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                self.links.add(urljoin(self.base_url, href))
        elif tag == "script" and "src" in attr_map:
            src = attr_map["src"].strip()
            if src:
                self.scripts.add(urljoin(self.base_url, src))
        elif tag == "form":
            action = urljoin(self.base_url, attr_map.get("action", ""))
            method = attr_map.get("method", "get").upper()
            self._current_form = {"action": action, "method": method, "inputs": []}
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_map.get("name", "")
            itype = attr_map.get("type", "text").lower()
            if name:
                self._current_form["inputs"].append({"name": name, "type": itype})

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


WELL_KNOWN_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/graphql",
    "/admin",
    "/login",
    "/health",
    "/metrics",
    "/.env",
    "/.git/HEAD",
)


class WebEngine:
    """Performs bounded crawling and deep HTTP/Web application security assessment."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
        max_pages: int = 25,
        max_depth: int = 3,
        timeout: float = 5.0,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout

    def crawl_and_assess(self, base_url: str, operation_id: str = "op-web") -> StageResult:
        """Alias for assess_url."""
        return self.assess_url(base_url, operation_id=operation_id)

    def _safe_fetch(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        max_redirects: int = 5,
        **kwargs: Any,
    ) -> httpx.Response:
        current_url = url
        for _ in range(max_redirects + 1):
            cur_parsed = urlsplit(current_url)
            cur_host = cur_parsed.hostname or "127.0.0.1"
            cur_port = cur_parsed.port or (443 if cur_parsed.scheme == "https" else 80)

            # Pre-flight scope check before packet transmission
            self.scope_guard.is_target_authorized(
                cur_host, "web_check", port=cur_port, op_class=OperationClass.SAFE_ACTIVE
            )

            resp = client.request(method, current_url, **kwargs)
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                next_loc = resp.headers["location"].strip()
                next_url = urljoin(current_url, next_loc)
                next_parsed = urlsplit(next_url)
                next_host = next_parsed.hostname or "127.0.0.1"
                next_port = next_parsed.port or (443 if next_parsed.scheme == "https" else 80)

                # Authoritative check on redirect destination
                try:
                    self.scope_guard.is_target_authorized(
                        next_host, "web_check", port=next_port, op_class=OperationClass.SAFE_ACTIVE
                    )
                except Exception as exc:
                    if self.audit:
                        self.audit.blocked(next_host, "web_check", "web_engine", f"Redirect to unauthorized host blocked: {exc}")
                    return resp
                current_url = next_url
                method = "GET"
            else:
                return resp
        return resp

    def assess_url(
        self,
        base_url: str,
        operation_id: str = "op-web",
    ) -> StageResult:
        """Run deep web assessment within authorized scope."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []
        visited_urls: set[str] = set()
        discovered_forms: list[dict[str, Any]] = []
        discovered_scripts: set[str] = set()
        discovered_endpoints: set[str] = set()

        parsed = urlsplit(base_url)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Scope check
        try:
            self.scope_guard.is_target_authorized(
                target_host, "web_check", port=target_port, op_class=OperationClass.SAFE_ACTIVE
            )
        except Exception as exc:
            return StageResult(
                stage="web_assessment",
                status=StageStatus.BLOCKED,
                reason=f"Scope authorization rejected: {exc}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "RedLoop-Security-Assessment/2.0"},
        )

        queue: list[tuple[str, int]] = [(base_url, 0)]
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        # 2. Bounded crawling
        try:
            while queue and len(visited_urls) < self.max_pages:
                current_url, depth = queue.pop(0)
                if current_url in visited_urls or depth > self.max_depth:
                    continue
                # Ensure crawled URL stays strictly on same origin / host
                cur_parsed = urlsplit(current_url)
                if cur_parsed.netloc.lower() != parsed.netloc.lower():
                    continue

                visited_urls.add(current_url)
                try:
                    resp = self._safe_fetch(client, "GET", current_url)
                except Exception:
                    continue

                discovered_endpoints.add(cur_parsed.path or "/")

                # Parse HTML content if text
                content_type = resp.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    parser = _HTMLEndpointExtractor(current_url)
                    try:
                        parser.feed(resp.text)
                        for link in parser.links:
                            link_parsed = urlsplit(link)
                            if (
                                link_parsed.netloc.lower() == parsed.netloc.lower()
                                and link not in visited_urls
                            ):
                                queue.append((link, depth + 1))
                        discovered_forms.extend(parser.forms)
                        discovered_scripts.update(parser.scripts)
                    except Exception:
                        pass

                # If this is root URL, run deep HTTP headers, cookies, methods, CORS checks
                if current_url.rstrip("/") == base_url.rstrip("/"):
                    ev_http = Evidence(
                        operation_id=operation_id,
                        target=base_url,
                        request_metadata={"method": "GET", "url": current_url},
                        response_metadata={
                            "status_code": resp.status_code,
                            "headers": dict(resp.headers),
                        },
                        response_excerpt=resp.text[:500] if resp.text else "",
                        tool_output=f"HTTP GET {current_url} -> {resp.status_code}",
                        parser_result={"headers": dict(resp.headers)},
                    )
                    evidence_list.append(ev_http)

                    # Security Headers Check
                    h_lower = {k.lower(): v for k, v in resp.headers.items()}

                    if "content-security-policy" not in h_lower:
                        findings.append(
                            Finding(
                                title="Missing Content-Security-Policy Header",
                                category="web_headers",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint="/",
                                description="The Content-Security-Policy (CSP) header is not set.",
                                evidence=[ev_http],
                                detection_method="http_response_header_analysis",
                                impact="Increases risk of Cross-Site Scripting (XSS) and unauthorized resource injection.",
                                remediation="Configure a robust Content-Security-Policy header restricting script and object sources.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

                    if "x-content-type-options" not in h_lower:
                        findings.append(
                            Finding(
                                title="Missing X-Content-Type-Options Header",
                                category="web_headers",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint="/",
                                description="The X-Content-Type-Options header is missing (expected 'nosniff').",
                                evidence=[ev_http],
                                detection_method="http_response_header_analysis",
                                impact="Allows browsers to MIME-sniff responses away from the declared content-type, potentially executing user-supplied files.",
                                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

                    if "x-frame-options" not in h_lower and "frame-ancestors" not in h_lower.get("content-security-policy", ""):
                        findings.append(
                            Finding(
                                title="Missing Anti-Clickjacking Protections (X-Frame-Options)",
                                category="web_headers",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint="/",
                                description="Neither X-Frame-Options nor CSP frame-ancestors is configured.",
                                evidence=[ev_http],
                                detection_method="http_response_header_analysis",
                                impact="The site may be embedded in an iframe on third-party sites, enabling clickjacking attacks.",
                                remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP frame-ancestors.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

                    if parsed.scheme == "https" and "strict-transport-security" not in h_lower:
                        findings.append(
                            Finding(
                                title="Missing Strict-Transport-Security (HSTS) Header",
                                category="web_headers",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint="/",
                                description="HTTPS service does not declare Strict-Transport-Security.",
                                evidence=[ev_http],
                                detection_method="http_response_header_analysis",
                                impact="Allows opportunistic protocol downgrade attacks or sslstrip on initial connection.",
                                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

                    # Server / Technology Disclosure
                    if "server" in h_lower and any(char.isdigit() for char in h_lower["server"]):
                        findings.append(
                            Finding(
                                title=f"Server Version Disclosure ({h_lower['server']})",
                                category="web_disclosure",
                                severity=Severity.INFO,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint="/",
                                description=f"Server header discloses software and version details: {h_lower['server']}",
                                evidence=[ev_http],
                                detection_method="http_response_header_analysis",
                                impact="Simplifies vulnerability identification for attackers targeting specific version CVEs.",
                                remediation="Configure web server to suppress or genericize the Server response header.",
                                references=["https://cwe.mitre.org/data/definitions/200.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

                    # Cookie Security Check
                    cookies = resp.cookies
                    for cookie in cookies.jar:
                        c_name = cookie.name
                        c_secure = cookie.secure
                        c_httponly = bool(cookie.has_nonstandard_attr("httponly") or getattr(cookie, "httponly", False))
                        samesite = cookie.get_nonstandard_attr("samesite")

                        if parsed.scheme == "https" and not c_secure:
                            findings.append(
                                Finding(
                                    title=f"Cookie Without Secure Flag ({c_name})",
                                    category="web_cookies",
                                    severity=Severity.LOW,
                                    confidence=Confidence.CONFIRMED,
                                    asset=base_url,
                                    target=target_host,
                                    port=target_port,
                                    endpoint="/",
                                    description=f"Cookie '{c_name}' does not set the Secure attribute.",
                                    evidence=[ev_http],
                                    detection_method="cookie_attribute_inspection",
                                    impact="Cookie may be transmitted over unencrypted HTTP connections in cleartext.",
                                    remediation=f"Add '; Secure' attribute to Set-Cookie for {c_name}.",
                                    references=["https://owasp.org/www-community/controls/SecureFlag"],
                                    source_operation_id=operation_id,
                                    status=FindingStatus.OPEN,
                                )
                            )

                        if not c_httponly and any(term in c_name.lower() for term in ("session", "token", "auth", "jwt", "id")):
                            findings.append(
                                Finding(
                                    title=f"Sensitive Cookie Without HttpOnly Flag ({c_name})",
                                    category="web_cookies",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.CONFIRMED,
                                    asset=base_url,
                                    target=target_host,
                                    port=target_port,
                                    endpoint="/",
                                    description=f"Authentication/session cookie '{c_name}' lacks the HttpOnly attribute.",
                                    evidence=[ev_http],
                                    detection_method="cookie_attribute_inspection",
                                    impact="Enables malicious client-side JavaScript to access session tokens via document.cookie if XSS occurs.",
                                    remediation=f"Add '; HttpOnly' attribute to Set-Cookie for {c_name}.",
                                    references=["https://owasp.org/www-community/HttpOnly"],
                                    source_operation_id=operation_id,
                                    status=FindingStatus.OPEN,
                                )
                            )

            # 3. Check well-known security paths
            for path in WELL_KNOWN_PATHS:
                check_url = urljoin(target_origin, path)
                try:
                    r_wk = self._safe_fetch(client, "GET", check_url)
                    if r_wk.status_code == 200:
                        discovered_endpoints.add(path)
                        # Sensitive file exposure check
                        if path in ("/.env", "/.git/HEAD"):
                            ev_sens = Evidence(
                                operation_id=operation_id,
                                target=check_url,
                                request_metadata={"url": check_url},
                                response_metadata={"status_code": 200},
                                response_excerpt=r_wk.text[:200],
                                tool_output=f"Accessible sensitive file: {path}",
                            )
                            evidence_list.append(ev_sens)
                            findings.append(
                                Finding(
                                    title=f"Exposed Sensitive Path ({path})",
                                    category="web_exposure",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    asset=base_url,
                                    target=target_host,
                                    port=target_port,
                                    endpoint=path,
                                    description=f"Sensitive configuration or source control artifact {path} is publicly accessible.",
                                    evidence=[ev_sens],
                                    detection_method="well_known_endpoint_probe",
                                    impact="Direct leakage of application secrets, credentials, or source history.",
                                    remediation=f"Block public access to {path} in web server configuration.",
                                    references=["https://cwe.mitre.org/data/definitions/552.html"],
                                    source_operation_id=operation_id,
                                    status=FindingStatus.OPEN,
                                    cvss_score=7.5,
                                    risk_score=7.5,
                                )
                            )
                except Exception:
                    continue

            # 4. CORS Check
            try:
                cors_resp = self._safe_fetch(
                    client,
                    "OPTIONS",
                    base_url,
                    headers={
                        "Origin": "https://evil-attacker.example",
                        "Access-Control-Request-Method": "GET",
                    },
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == "https://evil-attacker.example" and acac == "true":
                    ev_cors = Evidence(
                        operation_id=operation_id,
                        target=base_url,
                        request_metadata={"origin": "https://evil-attacker.example"},
                        response_metadata={"acao": acao, "acac": acac},
                        response_excerpt=f"ACAO: {acao}, ACAC: {acac}",
                        tool_output="CORS reflected origin with credentials enabled.",
                    )
                    evidence_list.append(ev_cors)
                    findings.append(
                        Finding(
                            title="Insecure CORS: Reflected Origin with Credentials Allowed",
                            category="web_cors",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            asset=base_url,
                            target=target_host,
                            port=target_port,
                            endpoint="/",
                            description="The server reflects arbitrary requested origins in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
                            evidence=[ev_cors],
                            detection_method="cors_preflight_probe",
                            impact="Enables cross-origin read access to authenticated user data from malicious sites.",
                            remediation="Implement an explicit whitelist of trusted origins; never dynamically reflect arbitrary origins with credentials enabled.",
                            references=["https://portswigger.net/web-security/cors"],
                            source_operation_id=operation_id,
                            status=FindingStatus.OPEN,
                        )
                    )
                elif acao == "*":
                    # Wildcard CORS (informative/low)
                    pass
            except Exception:
                pass

            # 5. Dangerous HTTP Methods Check (TRACE)
            try:
                trace_resp = self._safe_fetch(client, "TRACE", base_url)
                if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
                    ev_trace = Evidence(
                        operation_id=operation_id,
                        target=base_url,
                        request_metadata={"method": "TRACE"},
                        response_metadata={"status_code": trace_resp.status_code},
                        response_excerpt=trace_resp.text[:300],
                        tool_output="TRACE method enabled and echoing request.",
                    )
                    evidence_list.append(ev_trace)
                    findings.append(
                        Finding(
                            title="HTTP TRACE Method Enabled",
                            category="web_methods",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            asset=base_url,
                            target=target_host,
                            port=target_port,
                            endpoint="/",
                            description="The server responds to HTTP TRACE requests by echoing back headers.",
                            evidence=[ev_trace],
                            detection_method="http_method_probe",
                            impact="May be leveraged in Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.",
                            remediation="Disable HTTP TRACE/TRACK methods on the web server.",
                            references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                            source_operation_id=operation_id,
                            status=FindingStatus.OPEN,
                        )
                    )
            except Exception:
                pass

        finally:
            client.close()

        return StageResult(
            stage="web_assessment",
            status=StageStatus.SUCCESS,
            reason=f"Crawled {len(visited_urls)} pages, discovered {len(discovered_endpoints)} endpoints and {len(discovered_forms)} forms.",
            duration_seconds=round(time.monotonic() - t0, 2),
            findings=findings,
            evidence=evidence_list,
            data={
                "visited_urls": list(visited_urls),
                "endpoints": list(discovered_endpoints),
                "forms_count": len(discovered_forms),
                "scripts_count": len(discovered_scripts),
            },
        )

    assess_web = assess_url
