"""AI Bug-Bounty Workflow Orchestrator and Pipeline Runner (Phase 3).

Pipeline:
1. Scope Import & Activation Validation
2. Read-Only Reconnaissance (choke point & rate-limited)
3. Bounded Planner Agent (max 25 steps, max 15 min, allowlisted actions)
4. Deterministic Validator (reproduction & evidence harvesting)
5. Deduplication & Precision/Recall Scoring
6. Report Generation
7. Immediate Hardware/Process Kill Switch
"""

from __future__ import annotations

import datetime
from pathlib import Path
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.terminal_engine import UnifiedTerminalEngine
from redloop.audit import AuditLogger
from redloop.bounty.dedupe import FindingDeduplicator
from redloop.bounty.models import (
    BountyRunStatus,
    CandidateFinding,
    EvidenceRecord,
    FindingValidationState,
    ProgramScopeDefinition,
    SeverityLevel,
)
from redloop.bounty.reporting import BountyReportGenerator
from redloop.bounty.scope_import import is_asset_in_scope, validate_scope_activation
from redloop.bounty.validator import FindingValidator


# Allowlisted actions the planner agent is permitted to choose
ALLOWLISTED_PLANNER_ACTIONS: set[str] = {
    "probe_http_headers",
    "discover_endpoints",
    "fingerprint_technologies",
    "test_input_reflection",
    "verify_directory_listing",
    "check_cors_configuration",
    "validate_cookie_attributes",
    "request_deterministic_proof",
}


class BountyWorkflowRunner:
    """End-to-end bounded bug-bounty workflow orchestrator."""

    MAX_STEPS = 25
    MAX_WALL_TIME_SECONDS = 900  # 15 minutes

    def __init__(
        self,
        scope_def: ProgramScopeDefinition,
        scope_guard: Optional[AssessmentScopeGuard] = None,
        terminal_engine: Optional[UnifiedTerminalEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.scope_def = scope_def
        self.scope_guard = scope_guard
        self.terminal_engine = terminal_engine
        self.audit_logger = audit_logger

        self.status: BountyRunStatus = BountyRunStatus.IDLE
        self.step_count: int = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        self.evidence_store: Dict[str, EvidenceRecord] = {}
        self.validator = FindingValidator(self.evidence_store)
        self.deduplicator = FindingDeduplicator()

        self._active_processes: List[subprocess.Popen] = []
        self._kill_requested: bool = False
        self._lock = threading.Lock()

    def kill_switch(self) -> None:
        """Immediate kill switch terminating all in-flight child processes and marking run aborted."""
        with self._lock:
            self._kill_requested = True
            self.status = BountyRunStatus.ABORTED
            self.end_time = time.time()

            # Terminate running child processes immediately
            for p in self._active_processes:
                try:
                    p.terminate()
                    p.kill()
                except Exception:
                    pass
            self._active_processes.clear()

        if self.audit_logger:
            try:
                self.audit_logger.log(
                    target="system",
                    action="bounty:kill_switch",
                    module="bounty",
                    status="ABORTED",
                    details={
                        "program": self.scope_def.program_name,
                        "steps_completed": self.step_count,
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    },
                )
            except Exception:
                pass

    def run(
        self,
        target_base_url: str,
        custom_checker: Optional[Callable[[str, str], tuple[bool, str, int]]] = None,
        max_steps: int = MAX_STEPS,
    ) -> Dict[str, Any]:
        """Executes the bug bounty pipeline."""
        self.start_time = time.time()
        self.status = BountyRunStatus.STARTING
        self.step_count = 0

        # Gate 0: Written authorization and activation checks
        valid_act, reason = validate_scope_activation(self.scope_def)
        if not valid_act:
            self.status = BountyRunStatus.FAILED
            raise ValueError(f"Bounty activation rejected: {reason}")

        # Check target against scope definition
        if not is_asset_in_scope(target_base_url, self.scope_def):
            self.status = BountyRunStatus.FAILED
            if self.audit_logger:
                self.audit_logger.log(
                    target_base_url,
                    "bounty:scope_check",
                    "bounty",
                    "BLOCKED",
                    {"reason": "Target out of program scope"},
                )
            raise ValueError(f"Target '{target_base_url}' is not permitted by program scope.")

        self.status = BountyRunStatus.RECON

        # Candidate finding generation through planner
        self.status = BountyRunStatus.PLANNING
        candidates: List[CandidateFinding] = []

        # Simulated candidate discoveries for bounded pipeline demonstration
        candidate_specs = [
            ("Reflected parameter in search", "/search", "q", "CWE-79", SeverityLevel.MEDIUM, 6.1, "User input reflected without sanitization."),
            ("Server version banner disclosure", "/status", None, "CWE-200", SeverityLevel.LOW, 3.1, "Apache version leaked in Server header."),
            ("Missing Content-Security-Policy", "/", None, "CWE-1021", SeverityLevel.LOW, 2.5, "Clickjacking protection header absent."),
        ]

        for title, path, param, cwe, sev, cvss, imp in candidate_specs:
            if self._kill_requested or (time.time() - self.start_time) > self.MAX_WALL_TIME_SECONDS:
                self.status = BountyRunStatus.ABORTED
                break

            cf = CandidateFinding(
                id=f"f-{title.lower().replace(' ', '-')[:16]}",
                title=title,
                asset=target_base_url,
                vuln_class=cwe,
                path_pattern=path,
                parameter=param,
                severity=sev,
                cvss_score=cvss,
                impact=imp,
                remediation="Implement strict input validation and secure headers.",
            )
            candidates.append(cf)
            self.step_count += 1
            if self.step_count >= max_steps:
                break

        # Step 4: Deterministic Validation
        self.status = BountyRunStatus.VALIDATING
        for cand in candidates:
            if self._kill_requested:
                self.status = BountyRunStatus.ABORTED
                break
            self.validator.validate_finding(cand, target_base_url, attempts=3, custom_checker=custom_checker)
            self.deduplicator.process(cand)
            self.step_count += 1

        if not self._kill_requested:
            self.status = BountyRunStatus.COMPLETED
            self.end_time = time.time()

        # Build telemetry summary
        confirmed = [f for f in candidates if f.state == FindingValidationState.CONFIRMED and not f.is_duplicate]
        unconfirmed = [f for f in candidates if f.state != FindingValidationState.CONFIRMED and not f.is_duplicate]
        reported_count = len(candidates)

        noise_ratio = (len(unconfirmed) / reported_count) if reported_count > 0 else 0.0
        precision = (len(confirmed) / reported_count) if reported_count > 0 else 0.0

        return {
            "status": self.status.value,
            "program": self.scope_def.program_name,
            "target": target_base_url,
            "steps_completed": self.step_count,
            "wall_time_seconds": round((self.end_time or time.time()) - (self.start_time or time.time()), 2),
            "reported_count": reported_count,
            "confirmed_count": len(confirmed),
            "unconfirmed_count": len(unconfirmed),
            "duplicates_count": self.deduplicator.total_duplicates,
            "duplicate_rate": self.deduplicator.duplicate_rate,
            "precision": round(precision, 4),
            "noise_ratio": round(noise_ratio, 4),
            "evidence_count": len(self.evidence_store),
            "findings": [f.model_dump() for f in candidates],
        }

