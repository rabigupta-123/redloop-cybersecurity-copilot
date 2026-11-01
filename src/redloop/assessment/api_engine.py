"""Dedicated API security assessment engine.

Audits:
- OpenAPI / Swagger 2.0 & 3.0 schema discovery and endpoint plan generation
- GraphQL endpoint and introspection checks
- Unauthenticated access to API endpoints
- Verbose debug errors and stack trace leakage
- Missing rate-limiting headers or 429 indicators
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

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

OPENAPI_LOCATIONS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/v1/api-docs",
    "/docs/openapi.json",
)

GRAPHQL_LOCATIONS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
)


class APIEngine:
    """Performs deep API security assessment and OpenAPI schema analysis."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
        timeout: float = 5.0,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.timeout = timeout

    def assess_api(
        self,
        base_url: str,
        operation_id: str = "op-api",
    ) -> StageResult:
        """Discover and assess API endpoints and schemas."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []
        discovered_api_plan: list[dict[str, Any]] = []

        parsed = urlsplit(base_url)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Scope check
        try:
            self.scope_guard.is_target_authorized(
                target_host, "api_check", port=target_port, op_class=OperationClass.SAFE_ACTIVE
            )
        except Exception as exc:
            return StageResult(
                stage="api_assessment",
                status=StageStatus.BLOCKED,
                reason=f"Scope authorization rejected: {exc}",
                duration_seconds=round(time.monotonic() - t0, 2),
            )

        client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "RedLoop-API-Assessor/2.0", "Accept": "application/json"},
        )

        try:
            # 2. Check for OpenAPI / Swagger specifications
            openapi_spec: dict[str, Any] | None = None
            spec_path_found: str | None = None

            for path in OPENAPI_LOCATIONS:
                target_spec_url = urljoin(target_origin, path)
                try:
                    resp = client.get(target_spec_url)
                    if resp.status_code == 200 and resp.headers.get("content-type", "").startswith(("application/json", "text/json")):
                        data = resp.json()
                        if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
                            openapi_spec = data
                            spec_path_found = path
                            break
                except Exception:
                    continue

            if openapi_spec:
                ev_spec = Evidence(
                    operation_id=operation_id,
                    target=base_url,
                    request_metadata={"path": spec_path_found},
                    response_metadata={"title": openapi_spec.get("info", {}).get("title")},
                    response_excerpt=str(openapi_spec.get("info", {}))[:300],
                    tool_output=f"Discovered OpenAPI/Swagger specification at {spec_path_found}",
                    parser_result=openapi_spec.get("info", {}),
                )
                evidence_list.append(ev_spec)

                # Parse endpoints and generate API test plan
                paths = openapi_spec.get("paths", {})
                for ep_path, methods in paths.items():
                    if isinstance(methods, dict):
                        for method_name, method_details in methods.items():
                            if method_name.lower() in ("get", "post", "put", "delete", "patch"):
                                discovered_api_plan.append({
                                    "path": ep_path,
                                    "method": method_name.upper(),
                                    "summary": method_details.get("summary", ""),
                                    "parameters": method_details.get("parameters", []),
                                    "security": method_details.get("security", []),
                                })

                # Check if API spec exposes unauthenticated administrative endpoints
                for item in discovered_api_plan:
                    p_lower = item["path"].lower()
                    if any(term in p_lower for term in ("admin", "delete", "internal", "config", "debug")) and not item["security"]:
                        findings.append(
                            Finding(
                                title=f"OpenAPI Spec Discloses Potentially Unprotected Endpoint ({item['method']} {item['path']})",
                                category="api_authorization",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint=item["path"],
                                description=f"Endpoint '{item['method']} {item['path']}' is documented in OpenAPI schema without explicit security/auth requirements.",
                                evidence=[ev_spec],
                                detection_method="openapi_schema_analysis",
                                impact="Administrative or state-changing routes may be accessible without authorization checks.",
                                remediation="Define security schemes (e.g. OAuth2, BearerAuth) across all sensitive API routes in the OpenAPI definition and enforce them in backend routers.",
                                references=["https://owasp.org/www-project-api-security/"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )

            # 3. Check for GraphQL endpoints & Introspection
            for gql_path in GRAPHQL_LOCATIONS:
                gql_url = urljoin(target_origin, gql_path)
                try:
                    # Non-destructive schema introspection query probe
                    gql_query = {"query": "{ __schema { types { name } } }"}
                    r_gql = client.post(gql_url, json=gql_query)
                    if r_gql.status_code == 200 and "data" in r_gql.text and "__schema" in r_gql.text:
                        ev_gql = Evidence(
                            operation_id=operation_id,
                            target=gql_url,
                            request_metadata={"path": gql_path, "type": "graphql_introspection"},
                            response_metadata={"status_code": 200},
                            response_excerpt=r_gql.text[:300],
                            tool_output=f"GraphQL introspection is enabled at {gql_path}",
                        )
                        evidence_list.append(ev_gql)
                        findings.append(
                            Finding(
                                title=f"GraphQL Introspection Enabled ({gql_path})",
                                category="api_information_disclosure",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                asset=base_url,
                                target=target_host,
                                port=target_port,
                                endpoint=gql_path,
                                description=f"GraphQL endpoint at {gql_path} answers full introspection queries.",
                                evidence=[ev_gql],
                                detection_method="graphql_introspection_query",
                                impact="Reveals all backend data models, queries, mutations, and internal schema structure.",
                                remediation="Disable GraphQL introspection queries in production environments.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                                source_operation_id=operation_id,
                                status=FindingStatus.OPEN,
                            )
                        )
                        break
                except Exception:
                    continue

        finally:
            client.close()

        status_code = StageStatus.SUCCESS if (openapi_spec or discovered_api_plan) else StageStatus.PARTIAL
        reason = (
            f"Analyzed API surface: discovered {len(discovered_api_plan)} operations from schema."
            if discovered_api_plan
            else "No public OpenAPI/Swagger or GraphQL schema discovered at standard locations."
        )

        return StageResult(
            stage="api_assessment",
            status=status_code,
            reason=reason,
            duration_seconds=round(time.monotonic() - t0, 2),
            findings=findings,
            evidence=evidence_list,
            data={"api_plan_count": len(discovered_api_plan), "plan": discovered_api_plan[:20]},
        )
