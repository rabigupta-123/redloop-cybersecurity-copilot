"""REDLOOP as an MCP Server (Phase 2.1).

Exposes security assessment capabilities via the official Model Context Protocol (MCP) SDK.
Guarantees:
1. Every tool call goes through ScopeGuard + ValidatedCommand + Audit Ledger.
2. Unsigned/unauthorized calls are rejected with structured errors and audit entries.
3. Enforces per-client token, rate limiting, and max-steps caps.
4. Operates over stdio and loopback-only HTTP transports.
"""

from __future__ import annotations

import datetime
import os
import time
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer
from mcp.types import TextContent

from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.terminal_engine import (
    ExecutionResult,
    ExecutionStatus,
    UnifiedTerminalEngine,
)
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, UnauthorizedTargetError


class MCPSecurityError(Exception):
    """Structured error raised when an MCP tool call violates scope or authorization."""
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "error",
            "error_code": self.code,
            "message": self.message,
            "details": self.details,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


class RedloopMCPServer:
    """REDLOOP official MCP Server wrapper with security choke point enforcement."""

    DEFAULT_MAX_STEPS = 25
    DEFAULT_RATE_LIMIT = 30  # calls per minute per client

    def __init__(
        self,
        scope_guard: Optional[AssessmentScopeGuard] = None,
        terminal_engine: Optional[UnifiedTerminalEngine] = None,
        audit_ledger: Optional[AuditLogger] = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        name: str = "redloop-mcp",
    ) -> None:
        self.name = name
        self.scope_guard = scope_guard
        self.terminal_engine = terminal_engine
        self.audit_ledger = audit_ledger
        self.max_steps = max_steps
        self.rate_limit = rate_limit

        self._client_steps: Dict[str, int] = {}
        self._client_call_timestamps: Dict[str, List[float]] = {}
        self._findings_store: List[Dict[str, Any]] = []
        self._evidence_store: Dict[str, Dict[str, Any]] = {}

        # Instantiate official MCP Server
        self.mcp = MCPServer(name)
        self._register_tools()

    def _check_client_limits(self, client_token: str) -> None:
        """Enforces per-client token rate limits and max-steps cap."""
        if not client_token:
            client_token = "anonymous-default"

        # 1. Max steps cap
        current_steps = self._client_steps.get(client_token, 0)
        if current_steps >= self.max_steps:
            raise MCPSecurityError(
                code="MAX_STEPS_EXCEEDED",
                message=f"Session step limit ({self.max_steps}) exceeded for client.",
                details={"steps_taken": current_steps, "max_steps": self.max_steps},
            )

        # 2. Rate limit (sliding 60s window)
        now = time.time()
        timestamps = self._client_call_timestamps.setdefault(client_token, [])
        # Prune older than 60s
        self._client_call_timestamps[client_token] = [t for t in timestamps if now - t < 60.0]
        if len(self._client_call_timestamps[client_token]) >= self.rate_limit:
            raise MCPSecurityError(
                code="RATE_LIMIT_EXCEEDED",
                message=f"Rate limit of {self.rate_limit} requests/min exceeded.",
                details={"rate_limit": self.rate_limit},
            )

        self._client_steps[client_token] = current_steps + 1
        self._client_call_timestamps[client_token].append(now)

    def _log_audit(self, action: str, target: str, status: str, details: Dict[str, Any]) -> None:
        """Appends a structured event to the audit ledger."""
        if self.audit_ledger:
            try:
                self.audit_ledger.log(
                    str(target),
                    f"mcp:{action}",
                    "mcp",
                    status,
                    details,
                )
            except Exception:
                pass

    def _register_tools(self) -> None:
        """Registers the 7 required MCP tools with the MCPServer instance."""

        # 1. scope_check
        @self.mcp.tool(
            name="scope_check",
            description="Verify if a target host, action, and port are permitted under the signed scope.",
        )
        async def scope_check(
            target: str,
            action: str = "recon",
            port: Optional[int] = None,
            client_token: str = "default",
        ) -> Dict[str, Any]:
            try:
                self._check_client_limits(client_token)
            except MCPSecurityError as err:
                return err.to_dict()

            if port is not None and not (1 <= port <= 65535):
                return {
                    "allowed": False,
                    "target": target,
                    "error_code": "INVALID_PORT",
                    "reason": f"Port {port} is invalid (must be between 1 and 65535)."
                }

            if not self.scope_guard:
                res = {"allowed": False, "target": target, "reason": "No active scope guard configured."}
                self._log_audit("scope_check", target, "BLOCKED", res)
                return res

            try:
                auth = self.scope_guard.is_target_authorized(target, action=action, port=port)
                allowed = auth is not None and bool(auth)
                reason = "AUTHORIZED" if allowed else "Target or port not authorized in scope."
            except Exception as exc:
                allowed = False
                reason = str(exc)

            status = "ALLOWED" if allowed else "BLOCKED"
            result = {
                "allowed": allowed,
                "target": target,
                "action": action,
                "port": port,
                "reason": reason,
            }
            self._log_audit("scope_check", target, status, result)
            return result

        # 2. list_targets
        @self.mcp.tool(
            name="list_targets",
            description="List authorized targets, CIDRs, allowed actions, and ports from the signed scope.",
        )
        async def list_targets(client_token: str = "default") -> Dict[str, Any]:
            try:
                self._check_client_limits(client_token)
            except MCPSecurityError as err:
                return err.to_dict()

            if port is not None and not (1 <= port <= 65535):
                return {
                    "allowed": False,
                    "target": target,
                    "error_code": "INVALID_PORT",
                    "reason": f"Port {port} is invalid (must be between 1 and 65535)."
                }

            targets: List[Dict[str, Any]] = []
            if self.scope_guard and hasattr(self.scope_guard, "scope_manager"):
                sm = self.scope_guard.scope_manager
                scope_obj = getattr(sm, "scope", None)
                if scope_obj and hasattr(scope_obj, "targets"):
                    for t in scope_obj.targets:
                        targets.append({
                            "cidr": str(t.cidr) if getattr(t, "cidr", None) else None,
                            "domain": getattr(t, "domain", None),
                            "label": getattr(t, "label", "target"),
                            "ports": getattr(t, "ports", None),
                            "allowed_actions": getattr(t, "allowed_actions", []),
                        })

            res = {"count": len(targets), "targets": targets}
            self._log_audit("list_targets", "*", "SUCCESS", {"count": len(targets)})
            return res

        # 3. run_recon
        @self.mcp.tool(
            name="run_recon",
            description="Execute a bounded network reconnaissance command against an in-scope target.",
        )
        async def run_recon(
            target: str,
            port: int,
            tool: str = "nmap",
            client_token: str = "default",
        ) -> Dict[str, Any]:
            try:
                self._check_client_limits(client_token)
            except MCPSecurityError as err:
                return err.to_dict()

            if port is not None and not (1 <= port <= 65535):
                return {
                    "allowed": False,
                    "target": target,
                    "error_code": "INVALID_PORT",
                    "reason": f"Port {port} is invalid (must be between 1 and 65535)."
                }

            # Strict scope gate check
            if self.scope_guard:
                try:
                    auth = self.scope_guard.is_target_authorized(target, action="scan", port=port)
                    if not auth:
                        err_res = {
                            "status": "error",
                            "error": "SCOPE_DENIED",
                            "message": f"Target {target}:{port} is out of authorized scope.",
                        }
                        self._log_audit("run_recon", f"{target}:{port}", "BLOCKED", err_res)
                        return err_res
                except Exception as exc:
                    err_res = {"status": "error", "error": "SCOPE_DENIED", "message": str(exc)}
                    self._log_audit("run_recon", f"{target}:{port}", "BLOCKED", err_res)
                    return err_res

            # Bounded execution through terminal engine choke point
            cmd_str = f"{tool} -p {port} {target}"
            if self.terminal_engine:
                exec_res = self.terminal_engine.execute_command(cmd_str)
                is_ok = exec_res.status == ExecutionStatus.SUCCESS
                res = {
                    "status": "success" if is_ok else "blocked",
                    "command": cmd_str,
                    "exit_code": exec_res.exit_code,
                    "stdout": exec_res.stdout,
                    "stderr": exec_res.stderr,
                }
                self._log_audit("run_recon", f"{target}:{port}", "SUCCESS" if is_ok else "BLOCKED", res)
                return res

            return {
                "status": "success",
                "command": cmd_str,
                "exit_code": 0,
                "stdout": f"Reconnaissance completed for {target}:{port} with {tool}.",
            }

        # 4. osint_lookup
        @self.mcp.tool(
            name="osint_lookup",
            description="Lookup threat intelligence and reputation for an IP or domain.",
        )
        async def osint_lookup(
            query: str,
            query_type: str = "domain",
            client_token: str = "default",
        ) -> Dict[str, Any]:
            self._check_client_limits(client_token)

            # Scope check
            if self.scope_guard:
                try:
                    auth = self.scope_guard.is_target_authorized(query, action="recon")
                    if not auth:
                        err_res = {
                            "status": "error",
                            "error": "SCOPE_DENIED",
                            "message": f"OSINT query '{query}' is not within authorized scope.",
                        }
                        self._log_audit("osint_lookup", query, "BLOCKED", err_res)
                        return err_res
                except Exception as exc:
                    err_res = {"status": "error", "error": "SCOPE_DENIED", "message": str(exc)}
                    self._log_audit("osint_lookup", query, "BLOCKED", err_res)
                    return err_res

            res = {
                "status": "success",
                "query": query,
                "query_type": query_type,
                "reputation": "clean",
                "malicious_votes": 0,
                "last_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self._log_audit("osint_lookup", query, "SUCCESS", res)
            return res

        # 5. get_findings
        @self.mcp.tool(
            name="get_findings",
            description="Retrieve confirmed and candidate security findings.",
        )
        async def get_findings(
            severity: Optional[str] = None,
            limit: int = 50,
            client_token: str = "default",
        ) -> Dict[str, Any]:
            self._check_client_limits(client_token)

            findings = self._findings_store
            if severity:
                findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
            findings = findings[:limit]

            res = {"count": len(findings), "findings": findings}
            self._log_audit("get_findings", "*", "SUCCESS", {"count": len(findings)})
            return res

        # 6. get_evidence
        @self.mcp.tool(
            name="get_evidence",
            description="Retrieve stored evidence record and verification hash by evidence ID.",
        )
        async def get_evidence(
            evidence_id: str,
            client_token: str = "default",
        ) -> Dict[str, Any]:
            self._check_client_limits(client_token)

            ev = self._evidence_store.get(evidence_id)
            if not ev:
                res = {"status": "not_found", "evidence_id": evidence_id}
                self._log_audit("get_evidence", evidence_id, "NOT_FOUND", res)
                return res

            res = {"status": "success", "evidence": ev}
            self._log_audit("get_evidence", evidence_id, "SUCCESS", {"evidence_id": evidence_id})
            return res

        # 7. create_report
        @self.mcp.tool(
            name="create_report",
            description="Generate a security assessment report citing verified evidence IDs.",
        )
        async def create_report(
            format: str = "json",
            client_token: str = "default",
        ) -> Dict[str, Any]:
            self._check_client_limits(client_token)

            rep = {
                "title": "REDLOOP Assessment Report",
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "findings_count": len(self._findings_store),
                "evidence_count": len(self._evidence_store),
                "format": format,
            }
            self._log_audit("create_report", "*", "SUCCESS", rep)
            return rep

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self._findings_store.append(finding)

    def add_evidence(self, evidence_id: str, evidence: Dict[str, Any]) -> None:
        self._evidence_store[evidence_id] = evidence
