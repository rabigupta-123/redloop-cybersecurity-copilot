"""Central Assessment Orchestrator Engine for RedLoop.

Strictly adheres to:
- Sections 4, 27, 29, 30, 31, 37, 38:
  - Bounded multi-stage pipeline: Scope -> Discovery -> Fingerprinting -> Web/API -> Deep Checks -> Correlation -> Risk -> AI -> Reports.
  - No conversational friction: Signed scope is the machine contract.
  - Every stage verifies scope, has timeouts, logs audit events, preserves verifiable evidence, and reports structured status (SUCCESS, FAILED, BLOCKED, TIMEOUT, UNAVAILABLE, PARTIAL).
  - Multi-depth levels: QUICK, STANDARD, DEEP, COMPREHENSIVE.
  - Checkpointing & Resume using SQLite persistence (data/assessments.sqlite).
  - Attack-surface graph correlation and deterministic CVSS-aligned risk scoring.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from redloop.assessment.analyst import AISecurityAnalyst
from redloop.assessment.api_engine import APIEngine
from redloop.assessment.capability import CapabilityMatrix, get_capabilities
from redloop.assessment.config_engine import ConfigEngine
from redloop.assessment.correlation import AttackSurfaceCorrelator
from redloop.assessment.dns_engine import DNSEngine
from redloop.assessment.file_engine import FileTriageEngine
from redloop.assessment.host_engine import HostEngine
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    Evidence,
    Finding,
    OperationClass,
    StageResult,
    StageStatus,
)
from redloop.assessment.network import NetworkEngine
from redloop.assessment.reporting import ReportingEngine
from redloop.assessment.risk import calculate_risk
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.software_engine import SoftwareEngine
from redloop.assessment.tls_engine import TLSEngine
from redloop.assessment.web_engine import WebEngine
from redloop.audit import AuditLogger


class AssessmentStore:
    """Persistent SQLite backing store for assessment state and checkpoint resume."""

    def __init__(self, db_path: str | Path = "data/assessments.sqlite"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save(self, state: AssessmentState) -> None:
        state_json = state.model_dump_json()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO assessments (id, target, depth, status, current_stage, state_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    current_stage=excluded.current_stage,
                    state_json=excluded.state_json,
                    updated_at=excluded.updated_at
                """,
                (
                    state.id,
                    state.target,
                    state.depth.value,
                    state.status,
                    state.current_stage,
                    state_json,
                    state.created_at,
                    state.updated_at,
                ),
            )
            conn.commit()

    @staticmethod
    def _verify_evidence_integrity(state: AssessmentState) -> None:
        """Recompute evidence digests on load and surface tampering.

        Historical records without a digest are reported as unhashed legacy
        evidence, not silently trusted as verified. Tampered records are
        flagged in ``state.errors`` without discarding the persisted data.
        """
        evidence_items = list(state.evidence)
        for finding in state.findings:
            evidence_items.extend(finding.evidence)

        def add_once(error: dict[str, Any]) -> None:
            if any(
                existing.get("error_type") == error["error_type"]
                and existing.get("evidence_id") == error["evidence_id"]
                for existing in state.errors
            ):
                return
            state.errors.append(error)

        for ev in evidence_items:
            if not ev.sha256_hash:
                add_once(
                    {
                        "stage": "evidence_integrity",
                        "error_type": "legacy_unhashed_evidence",
                        "evidence_id": ev.id,
                        "message": "Evidence has no stored digest; integrity cannot be proven.",
                    }
                )
            elif not ev.verify_integrity():
                add_once(
                    {
                        "stage": "evidence_integrity",
                        "error_type": "evidence_integrity_failed",
                        "evidence_id": ev.id,
                        "target": ev.target,
                        "message": "Evidence digest mismatch: record was modified after capture.",
                    }
                )

    def load(self, assessment_id: str) -> AssessmentState | None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json FROM assessments WHERE id = ?", (assessment_id,)
            )
            row = cursor.fetchone()
            if row:
                state = AssessmentState.model_validate_json(row[0])
                self._verify_evidence_integrity(state)
                return state
        return None

    def list_all(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT id, target, depth, status, current_stage, created_at, updated_at FROM assessments ORDER BY updated_at DESC"
            )
            return [
                {
                    "id": r[0],
                    "target": r[1],
                    "depth": r[2],
                    "status": r[3],
                    "current_stage": r[4],
                    "created_at": r[5],
                    "updated_at": r[6],
                }
                for r in cursor.fetchall()
            ]

    def find_by_target(self, target: str) -> list[AssessmentState]:
        """Retrieve historical assessment states for a given target."""
        clean = target.strip().lower()
        states: list[AssessmentState] = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json FROM assessments WHERE LOWER(target) = ? ORDER BY updated_at DESC",
                (clean,),
            )
            for row in cursor.fetchall():
                try:
                    state = AssessmentState.model_validate_json(row[0])
                except Exception:
                    continue
                self._verify_evidence_integrity(state)
                states.append(state)
        return states


class AssessmentEngine:
    """Master orchestrator for deep, multi-domain security assessments."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
        store: AssessmentStore | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit
        self.store = store or AssessmentStore()
        self.capabilities = get_capabilities()
        self.reporting = ReportingEngine()
        self.correlator = AttackSurfaceCorrelator()
        self.analyst = AISecurityAnalyst()

    def start_assessment(
        self,
        target: str,
        depth: AssessmentDepth = AssessmentDepth.STANDARD,
        progress_callback: Callable[[str, str, StageResult | None], None] | None = None,
        config_artifact_paths: list[str] | None = None,
        file_artifact_paths: list[str] | None = None,
    ) -> AssessmentState:
        """Initiate a brand new security assessment workflow."""
        state = AssessmentState(
            id=f"asmt-{uuid.uuid4().hex[:12]}",
            target=target,
            depth=depth,
            status="RUNNING",
            current_stage="INIT",
        )
        self.store.save(state)

        if self.audit:
            self.audit.log(
                "assessment_started",
                assessment_id=state.id,
                target=target,
                depth=depth.value,
            )

        return self._run_stages(
            state=state,
            progress_callback=progress_callback,
            config_artifact_paths=config_artifact_paths or [],
            file_artifact_paths=file_artifact_paths or [],
        )

    def resume_assessment(
        self,
        assessment_id: str,
        progress_callback: Callable[[str, str, StageResult | None], None] | None = None,
    ) -> AssessmentState:
        """Resume an interrupted assessment from its latest persistent checkpoint (Section 30)."""
        state = self.store.load(assessment_id)
        if not state:
            raise ValueError(f"No checkpoint found for assessment ID: {assessment_id}")

        if state.status == "COMPLETED":
            return state

        state.status = "RUNNING"
        self.store.save(state)

        if self.audit:
            self.audit.log(
                "assessment_resumed",
                assessment_id=state.id,
                target=state.target,
                last_completed_stage=list(state.completed_stages.keys()),
            )

        return self._run_stages(
            state=state,
            progress_callback=progress_callback,
        )

    def _run_stages(
        self,
        state: AssessmentState,
        progress_callback: Callable[[str, str, StageResult | None], None] | None = None,
        config_artifact_paths: list[str] | None = None,
        file_artifact_paths: list[str] | None = None,
    ) -> AssessmentState:
        """Execute assessment stages sequentially with error isolation and checkpointing."""
        target = state.target
        op_prefix = state.id

        stages = self._plan_stages(state.depth)

        # Build engines
        net_engine = NetworkEngine(self.scope_guard, self.audit)
        tls_engine = TLSEngine(self.scope_guard, self.audit)
        dns_engine = DNSEngine(self.scope_guard, self.audit)
        web_engine = WebEngine(self.scope_guard, self.audit)
        api_engine = APIEngine(self.scope_guard, self.audit)
        host_engine = HostEngine(self.scope_guard, self.audit)
        file_engine = FileTriageEngine(self.scope_guard, self.audit)
        cfg_engine = ConfigEngine(self.scope_guard, self.audit)

        disclosed_ports: list[int] = []

        for stage_name in stages:
            if stage_name in state.completed_stages:
                # Stage already executed in previous checkpoint run
                continue

            state.current_stage = stage_name
            self.store.save(state)

            if progress_callback:
                progress_callback(state.id, stage_name, None)

            stage_result: StageResult | None = None

            try:
                if stage_name == "scope_validation":
                    stage_result = self._stage_scope_validation(target, op_prefix)

                elif stage_name == "dns_discovery":
                    stage_result = dns_engine.assess_dns(target, f"{op_prefix}-dns")

                elif stage_name == "network_discovery":
                    # Include scope-authorized ports and depth-appropriate candidates
                    candidate_ports = [80, 443, 8080, 8443, 8765, 22, 21, 25, 3306, 5432, 6379, 8000]
                    for entry in self.scope_guard.scope_manager.scope.targets:
                        if entry.matches(target) and entry.ports:
                            candidate_ports.extend(entry.ports)
                    ports = list(dict.fromkeys(candidate_ports))

                    stage_result = net_engine.scan_tcp_ports(
                        target,
                        ports=ports,
                        operation_id=f"{op_prefix}-net",
                    )
                    # Track open ports
                    if stage_result and "open_ports" in stage_result.data:
                        disclosed_ports = stage_result.data["open_ports"]

                elif stage_name == "tls_assessment":
                    # Safe automatic planning: only probe TLS on open HTTPS/TLS ports
                    tls_port = None
                    if 443 in disclosed_ports:
                        tls_port = 443
                    elif 8443 in disclosed_ports:
                        tls_port = 8443
                    elif disclosed_ports and any(p in (443, 8443) for p in ports):
                        tls_port = 443

                    if tls_port is None:
                        stage_result = StageResult(
                            stage="tls_assessment",
                            status=StageStatus.UNAVAILABLE,
                            reason="No open TLS/HTTPS services discovered on authorized ports.",
                        )
                    else:
                        stage_result = tls_engine.assess_tls(target, port=tls_port, operation_id=f"{op_prefix}-tls")

                elif stage_name == "web_assessment":
                    # Safe automatic planning: route web assessment to discovered open web ports
                    target_url = None
                    if 8765 in disclosed_ports:
                        target_url = f"http://{target}:8765"
                    elif 443 in disclosed_ports:
                        target_url = f"https://{target}"
                    elif 80 in disclosed_ports:
                        target_url = f"http://{target}:80"
                    elif 8080 in disclosed_ports:
                        target_url = f"http://{target}:8080"
                    elif disclosed_ports:
                        target_url = f"http://{target}:{disclosed_ports[0]}"

                    if target_url is None:
                        stage_result = StageResult(
                            stage="web_assessment",
                            status=StageStatus.UNAVAILABLE,
                            reason="No open HTTP/web services were detected on authorized ports.",
                        )
                    else:
                        max_p = 10 if state.depth == AssessmentDepth.QUICK else (50 if state.depth == AssessmentDepth.COMPREHENSIVE else 25)
                        web_engine.max_pages = max_p
                        stage_result = web_engine.assess_web(target_url, f"{op_prefix}-web")

                elif stage_name == "api_assessment":
                    target_url = f"http://{target}"
                    if 443 in disclosed_ports:
                        target_url = f"https://{target}"
                    elif 8765 in disclosed_ports:
                        target_url = f"http://{target}:8765"

                    stage_result = api_engine.assess_api(target_url, f"{op_prefix}-api")

                elif stage_name == "host_assessment":
                    stage_result = host_engine.assess_host(target, f"{op_prefix}-host")

                elif stage_name == "config_assessment":
                    stage_result = self._stage_config_assessment(cfg_engine, config_artifact_paths or [], target, op_prefix)

                elif stage_name == "file_triage":
                    stage_result = self._stage_file_triage(file_engine, file_artifact_paths or [], target, op_prefix)

                elif stage_name == "correlation_and_risk":
                    stage_result = self._stage_correlation_and_risk(state)

                elif stage_name == "ai_analysis":
                    stage_result = self._stage_ai_analysis(state)

            except ScopeBlockedError as sbe:
                stage_result = StageResult(
                    stage=stage_name,
                    status=StageStatus.BLOCKED,
                    reason=f"Operation technically blocked by machine-enforced scope contract: {sbe}",
                )
            except Exception as exc:
                stage_result = StageResult(
                    stage=stage_name,
                    status=StageStatus.FAILED,
                    reason=f"Stage encountered unexpected execution error: {exc}",
                )
                state.errors.append({"stage": stage_name, "error": str(exc), "timestamp": time.time()})

            if stage_result:
                # Merge findings and evidence
                state.findings.extend(stage_result.findings)
                state.evidence.extend(stage_result.evidence)
                state.completed_stages[stage_name] = {
                    "status": stage_result.status.value,
                    "reason": stage_result.reason,
                    "duration": stage_result.duration_seconds,
                    "findings_count": len(stage_result.findings),
                }

                if progress_callback:
                    progress_callback(state.id, stage_name, stage_result)

            # Checkpoint progress after every stage
            state.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.store.save(state)

        # Determine overall state status distinctly
        blocked_stages = [
            name for name, st in state.completed_stages.items()
            if (isinstance(st, dict) and st.get("status") == StageStatus.BLOCKED.value)
            or (hasattr(st, "status") and st.status == StageStatus.BLOCKED)
        ]
        success_stages = [
            name for name, st in state.completed_stages.items()
            if (isinstance(st, dict) and st.get("status") == StageStatus.SUCCESS.value)
            or (hasattr(st, "status") and st.status == StageStatus.SUCCESS)
        ]

        if blocked_stages and success_stages:
            state.status = "PARTIALLY_BLOCKED"
        elif blocked_stages and not success_stages:
            state.status = "BLOCKED"
        else:
            state.status = "COMPLETED"

        state.current_stage = "DONE"
        state.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.store.save(state)

        if self.audit:
            self.audit.log(
                "assessment_completed",
                assessment_id=state.id,
                target=state.target,
                total_findings=len(state.findings),
                total_evidence=len(state.evidence),
            )

        return state

    def _plan_stages(self, depth: AssessmentDepth) -> list[str]:
        """Construct deterministic execution pipeline according to depth."""
        if depth == AssessmentDepth.QUICK:
            return [
                "scope_validation",
                "dns_discovery",
                "network_discovery",
                "tls_assessment",
                "web_assessment",
                "correlation_and_risk",
            ]
        elif depth == AssessmentDepth.STANDARD:
            return [
                "scope_validation",
                "dns_discovery",
                "network_discovery",
                "tls_assessment",
                "web_assessment",
                "api_assessment",
                "host_assessment",
                "correlation_and_risk",
                "ai_analysis",
            ]
        elif depth in (AssessmentDepth.DEEP, AssessmentDepth.COMPREHENSIVE):
            return [
                "scope_validation",
                "dns_discovery",
                "network_discovery",
                "tls_assessment",
                "web_assessment",
                "api_assessment",
                "host_assessment",
                "config_assessment",
                "file_triage",
                "correlation_and_risk",
                "ai_analysis",
            ]
        return ["scope_validation", "network_discovery", "correlation_and_risk"]

    def _stage_scope_validation(self, target: str, op_prefix: str) -> StageResult:
        """Verify machine-enforced signed scope contract."""
        start = time.time()
        self.scope_guard.verify_operation(
            target=target,
            operation_class=OperationClass.READ_ONLY,
            category="assess",
        )
        return StageResult(
            stage="scope_validation",
            status=StageStatus.SUCCESS,
            reason="Signed scope contract is cryptographically valid, active, and authorizes requested targets.",
            duration_seconds=round(time.time() - start, 3),
        )

    def _stage_config_assessment(
        self,
        engine: ConfigEngine,
        artifacts: list[str],
        target: str,
        op_prefix: str,
    ) -> StageResult:
        """Static audit of supplied configuration artifacts."""
        start = time.time()
        if not artifacts:
            return StageResult(
                stage="config_assessment",
                status=StageStatus.UNAVAILABLE,
                reason="No configuration or container artifacts were supplied in assessment parameters.",
                duration_seconds=round(time.time() - start, 3),
            )

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for path in artifacts:
            res = engine.audit_config_file(path, target_label=target, operation_id=f"{op_prefix}-cfg")
            findings.extend(res.findings)
            evidence.extend(res.evidence)

        return StageResult(
            stage="config_assessment",
            status=StageStatus.SUCCESS,
            reason=f"Audited {len(artifacts)} configuration artifacts ({len(findings)} findings).",
            duration_seconds=round(time.time() - start, 3),
            findings=findings,
            evidence=evidence,
        )

    def _stage_file_triage(
        self,
        engine: FileTriageEngine,
        artifacts: list[str],
        target: str,
        op_prefix: str,
    ) -> StageResult:
        """Static triage of supplied file artifacts."""
        start = time.time()
        if not artifacts:
            return StageResult(
                stage="file_triage",
                status=StageStatus.UNAVAILABLE,
                reason="No binary or upload artifacts were supplied for static triage.",
                duration_seconds=round(time.time() - start, 3),
            )

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for path in artifacts:
            res = engine.triage_file(path, target_label=target, operation_id=f"{op_prefix}-file")
            findings.extend(res.findings)
            evidence.extend(res.evidence)

        return StageResult(
            stage="file_triage",
            status=StageStatus.SUCCESS,
            reason=f"Triaged {len(artifacts)} file artifacts ({len(findings)} findings).",
            duration_seconds=round(time.time() - start, 3),
            findings=findings,
            evidence=evidence,
        )

    def _stage_correlation_and_risk(self, state: AssessmentState) -> StageResult:
        """Build attack surface graph, detect compound attack chains, and compute deterministic CVSS risk scores."""
        start = time.time()

        # 1. Build Attack Surface Graph
        state.graph = self.correlator.build_graph(state.target, state.findings)

        # 2. Correlate Multi-Finding Attack Chains
        chains = self.correlator.detect_attack_chains(state.findings)
        chained_finding_ids = set()
        for ch in chains:
            for fid in ch.get("finding_ids", []):
                chained_finding_ids.add(fid)

        # 3. Calculate Deterministic Risk Score for Every Finding (Section 24)
        is_internet = not (state.target in ("localhost", "127.0.0.1", "::1") or state.target.startswith("192.168."))
        for f in state.findings:
            score, assigned_sev, explanation = calculate_risk(
                finding=f,
                is_internet_facing=is_internet,
                asset_criticality=1.0,
                is_chained=f.id in chained_finding_ids,
            )
            f.risk_score = score
            f.risk_explanation = explanation

        return StageResult(
            stage="correlation_and_risk",
            status=StageStatus.SUCCESS,
            reason=f"Constructed attack-surface graph ({len(state.graph.nodes)} nodes), detected {len(chains)} chains, calculated deterministic risk scores.",
            duration_seconds=round(time.time() - start, 3),
            data={"chains": chains},
        )

    def _stage_ai_analysis(self, state: AssessmentState) -> StageResult:
        """Execute AI analyst layer over structured evidence strictly without inventing data."""
        start = time.time()
        chains = state.completed_stages.get("correlation_and_risk", {}).get("data", {}).get("chains", [])
        ai_res = self.analyst.analyze_assessment(
            target=state.target,
            findings=state.findings,
            graph=state.graph,
            chains=chains,
        )

        return StageResult(
            stage="ai_analysis",
            status=StageStatus.SUCCESS,
            reason=f"AI security analysis completed with confidence: {ai_res.ai_confidence.value} (Fallback: {ai_res.is_fallback})",
            duration_seconds=round(time.time() - start, 3),
            data=ai_res.model_dump(),
        )
