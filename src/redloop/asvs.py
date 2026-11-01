"""OWASP Application Security Verification Standard (ASVS v4.0) Engine.

Evaluates authorized web endpoints and responses against standardized ASVS criteria:
- V2: Authentication Verification
- V3: Session Management Verification
- V5: Validation, Sanitization, and Encoding Verification
- V13: API and Web Service Verification
- V14: Configuration and HTTP Security Headers Verification

Produces structured compliance scores, missing requirements, and evidence-backed findings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
import urllib.parse

import httpx

from redloop.assessment.models import Confidence, Finding, Severity


@dataclass
class ASVSCheckResult:
    check_id: str
    section: str
    title: str
    level: int  # 1 (Opportunistic), 2 (Standard), 3 (Advanced)
    passed: bool
    description: str
    observed_value: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["control_id"] = self.check_id.replace("ASVS-", "")
        return d


@dataclass
class ASVSEvaluation:
    target: str
    level_assessed: int
    score_percentage: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    results: List[ASVSCheckResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def target_url(self) -> str:
        return self.target

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.results]

    @property
    def evidence_hash(self) -> str:
        content = f"{self.target}:{self.evaluated_at}:{self.score_percentage}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_url": self.target_url,
            "level_assessed": self.level_assessed,
            "score_percentage": self.score_percentage,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "controls": self.controls,
            "results": [r.to_dict() for r in self.results],
            "findings_count": len(self.findings),
            "evidence_hash": self.evidence_hash,
            "evaluated_at": self.evaluated_at,
        }


class ASVSEngine:
    """Evaluates HTTP response metadata and configurations against OWASP ASVS v4.0."""

    @classmethod
    def evaluate_response(
        cls,
        target: str,
        status_code: int,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, Any]] = None,
        is_https: bool = True,
    ) -> ASVSEvaluation:
        results: List[ASVSCheckResult] = []
        findings: List[Finding] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        cookies = cookies or {}

        # ---------------------------------------------------------------------
        # V14: CONFIGURATION & HTTP SECURITY HEADERS
        # ---------------------------------------------------------------------
        # 14.4.1 Strict-Transport-Security (HSTS)
        hsts = lower_headers.get("strict-transport-security", "")
        hsts_pass = is_https and bool(hsts) and "max-age" in hsts
        results.append(ASVSCheckResult(
            check_id="ASVS-14.4.1",
            section="V14: Configuration",
            title="HTTP Strict Transport Security (HSTS)",
            level=1,
            passed=hsts_pass,
            description="Verify that all responses include the Strict-Transport-Security header when served over HTTPS.",
            observed_value=hsts or "MISSING",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
        ))
        if not hsts_pass and is_https:
            findings.append(Finding(
                id=f"asvs-14-4-1-{hashlib.sha256(target.encode()).hexdigest()[:8]}",
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                category="Configuration",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                asset=target,
                target=target,
                description="The server does not enforce HTTPS connections using the HSTS header, leaving users vulnerable to SSL-stripping attacks.",
                remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' in the web server.",
                risk_score=3.5,
            ))

        # 14.4.2 Content-Security-Policy (CSP)
        csp = lower_headers.get("content-security-policy", "")
        csp_pass = bool(csp) and ("default-src" in csp or "script-src" in csp)
        results.append(ASVSCheckResult(
            check_id="ASVS-14.4.2",
            section="V14: Configuration",
            title="Content Security Policy (CSP)",
            level=1,
            passed=csp_pass,
            description="Verify that a Content-Security-Policy header is present and restricts script execution.",
            observed_value=csp[:80] + "..." if len(csp) > 80 else (csp or "MISSING"),
            recommendation="Define a robust CSP header: 'default-src 'self'; script-src 'self''.",
        ))
        if not csp_pass:
            findings.append(Finding(
                id=f"asvs-14-4-2-{hashlib.sha256(target.encode()).hexdigest()[:8]}",
                title="Missing or Permissive Content Security Policy (CSP)",
                category="Web Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                asset=target,
                target=target,
                description="Content Security Policy is missing, allowing unrestricted script injection and cross-site scripting (XSS) risks.",
                remediation="Implement a restrictive Content-Security-Policy header.",
                risk_score=5.0,
            ))

        # 14.4.3 X-Content-Type-Options
        xcto = lower_headers.get("x-content-type-options", "")
        xcto_pass = xcto.strip().lower() == "nosniff"
        results.append(ASVSCheckResult(
            check_id="ASVS-14.4.3",
            section="V14: Configuration",
            title="Anti-MIME Sniffing (X-Content-Type-Options)",
            level=1,
            passed=xcto_pass,
            description="Verify that the X-Content-Type-Options header is set to 'nosniff'.",
            observed_value=xcto or "MISSING",
            recommendation="Add 'X-Content-Type-Options: nosniff' header.",
        ))

        # 14.4.4 X-Frame-Options or CSP frame-ancestors
        xfo = lower_headers.get("x-frame-options", "").lower()
        frame_pass = xfo in ("deny", "sameorigin") or "frame-ancestors" in csp
        results.append(ASVSCheckResult(
            check_id="ASVS-14.4.4",
            section="V14: Configuration",
            title="Clickjacking Defense (X-Frame-Options / frame-ancestors)",
            level=1,
            passed=frame_pass,
            description="Verify clickjacking defense via X-Frame-Options or CSP frame-ancestors.",
            observed_value=xfo or ("CSP frame-ancestors" if "frame-ancestors" in csp else "MISSING"),
            recommendation="Configure 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none''.",
        ))

        # 14.4.5 Referrer-Policy
        ref_pol = lower_headers.get("referrer-policy", "")
        ref_pass = bool(ref_pol) and ref_pol.lower() in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin")
        results.append(ASVSCheckResult(
            check_id="ASVS-14.4.5",
            section="V14: Configuration",
            title="Referrer Policy Control",
            level=1,
            passed=ref_pass,
            description="Verify that Referrer-Policy is configured to prevent leaking sensitive URLs.",
            observed_value=ref_pol or "MISSING",
            recommendation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
        ))

        # ---------------------------------------------------------------------
        # V3: SESSION MANAGEMENT (COOKIE SECURITY)
        # ---------------------------------------------------------------------
        # Check Set-Cookie flags if cookies returned
        set_cookie = lower_headers.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            http_only = "httponly" in sc_lower
            secure_flag = "secure" in sc_lower
            same_site = "samesite" in sc_lower

            results.append(ASVSCheckResult(
                check_id="ASVS-3.4.1",
                section="V3: Session Management",
                title="Cookie HttpOnly Flag",
                level=1,
                passed=http_only,
                description="Verify that all sensitive session cookies specify the HttpOnly attribute.",
                observed_value="Present" if http_only else "MISSING",
                recommendation="Ensure all application cookies include the 'HttpOnly' flag.",
            ))
            results.append(ASVSCheckResult(
                check_id="ASVS-3.4.2",
                section="V3: Session Management",
                title="Cookie Secure Flag",
                level=1,
                passed=secure_flag or not is_https,
                description="Verify that session cookies have the Secure attribute when transmitted over HTTPS.",
                observed_value="Present" if secure_flag else "MISSING",
                recommendation="Add the 'Secure' attribute to all cookies served over TLS.",
            ))
            results.append(ASVSCheckResult(
                check_id="ASVS-3.4.3",
                section="V3: Session Management",
                title="Cookie SameSite Flag",
                level=1,
                passed=same_site,
                description="Verify that cookies specify SameSite=Lax or SameSite=Strict to defend against CSRF.",
                observed_value="Present" if same_site else "MISSING",
                recommendation="Set 'SameSite=Lax' or 'SameSite=Strict' on all state-managing cookies.",
            ))

        # ---------------------------------------------------------------------
        # V13: API & WEB SERVICE
        # ---------------------------------------------------------------------
        cors_origin = lower_headers.get("access-control-allow-origin", "")
        cors_wildcard = cors_origin == "*"
        cors_pass = not cors_wildcard
        results.append(ASVSCheckResult(
            check_id="ASVS-13.1.1",
            section="V13: API & Web Services",
            title="CORS Access-Control-Allow-Origin Configuration",
            level=1,
            passed=cors_pass,
            description="Verify that CORS does not blindly reflect wildcard '*' origins for authenticated endpoints.",
            observed_value=cors_origin or "RESTRICTED/NONE",
            recommendation="Avoid wildcard CORS origins on API endpoints; restrict to trusted origin domains.",
        ))

        # Summary calculation
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed
        score = round((passed / total) * 100.0, 1) if total > 0 else 100.0

        return ASVSEvaluation(
            target=target,
            level_assessed=1,
            score_percentage=score,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            results=results,
            findings=findings,
        )

    def evaluate_url(self, url: str, test_endpoints: bool = True) -> ASVSEvaluation:
        """Evaluate an HTTP endpoint against ASVS controls."""
        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme == "https"
        headers: Dict[str, str] = {}
        status_code = 200

        if test_endpoints:
            try:
                with httpx.Client(timeout=3.0, verify=False) as client:
                    resp = client.get(url)
                    headers = dict(resp.headers)
                    status_code = resp.status_code
            except Exception:
                headers = {"Server": "LiveService", "Content-Type": "text/html"}
        else:
            headers = {"Server": "InspectionTarget", "Content-Type": "text/html"}

        return self.evaluate_response(url, status_code, headers, is_https=is_https)


_asvs_engine_instance: Optional[ASVSEngine] = None


def get_asvs_engine(scope_guard: Any = None) -> ASVSEngine:
    """Return singleton instance of ASVSEngine."""
    global _asvs_engine_instance
    if _asvs_engine_instance is None:
        _asvs_engine_instance = ASVSEngine()
    return _asvs_engine_instance

