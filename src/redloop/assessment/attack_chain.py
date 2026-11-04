"""REDLOOP Unified Attack-Chain Reconstruction & Kill-Chain Correlation Engine (Phase 6).

Provides:
1. Chronological correlation of multi-source telemetry events, SOC alerts, and ATT&CK mappings.
2. 13-stage kill-chain progression mapping from Reconnaissance to Impact.
3. Rigorous distinction between OBSERVED evidence and INFERRED steps.
4. Explicit flagging of telemetry gaps and unobserved intermediate steps.
5. Dwell-time calculation, entry-point candidate identification, and crown jewel impact blast radius.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from redloop.assessment.attack_mapping import AttackCatalog, AttackMappingEngine, TechniqueMapping


class StepObservationType(str, Enum):
    OBSERVED = "OBSERVED"  # Direct concrete telemetry/alert match
    INFERRED = "INFERRED"  # Heuristic gap fill between observed stages


@dataclass
class AttackChainStep:
    """Individual step in the reconstructed attack chain."""
    step_id: str
    stage_index: int
    stage_name: str
    tactic_id: str
    technique_id: str
    technique_name: str
    observation_type: StepObservationType
    timestamp: str
    entity_host: str | None = None
    entity_user: str | None = None
    entity_ip: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 1.0
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["observation_type"] = self.observation_type.value
        return d


@dataclass
class AttackChain:
    """Reconstructed end-to-end attack progression."""
    chain_id: str
    title: str
    steps: list[AttackChainStep]
    entry_point_candidate: str | None
    crown_jewel_target: str | None
    dwell_time_seconds: float
    overall_confidence: float
    telemetry_gaps: list[str]
    observed_stages: list[str]
    inferred_stages: list[str]
    contradictory_evidence: list[str] = field(default_factory=list)
    framework_model: str = "REDLOOP Integrated ATT&CK Progression"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["steps"] = [s.to_dict() for s in self.steps]
        return d


class AttackChainReconstructor:
    """Reconstructs and validates directed attack chains from security telemetry and alerts."""

    # Standard Kill-Chain Stages in canonical sequence
    STAGE_ORDER: list[tuple[str, str]] = [
        ("TA0043", "Reconnaissance"),
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Defense Evasion"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0011", "Command and Control"),
        ("TA0010", "Exfiltration"),
        ("TA0040", "Impact"),
    ]

    TACTIC_TO_STAGE_INDEX: dict[str, int] = {tac_id: idx for idx, (tac_id, _) in enumerate(STAGE_ORDER)}

    @classmethod
    def reconstruct_chain(
        cls,
        events: list[Any] | None = None,
        alerts: list[Any] | None = None,
        chain_title: str | None = None,
    ) -> AttackChain:
        """Constructs an explainable AttackChain from events and alerts with gap analysis."""
        events = events or []
        alerts = alerts or []
        chain_id = f"chn-{uuid.uuid4().hex[:10]}"

        # 1. Map all events and alerts to ATT&CK technique mappings
        raw_mappings: list[tuple[TechniqueMapping, Any]] = []

        for alt in alerts:
            maps = AttackMappingEngine.map_alert(alt)
            for m in maps:
                raw_mappings.append((m, alt))

        for ev in events:
            maps = AttackMappingEngine.map_event(ev)
            for m in maps:
                raw_mappings.append((m, ev))

        if not raw_mappings:
            return AttackChain(
                chain_id=chain_id,
                title=chain_title or "Empty Investigation Chain",
                steps=[],
                entry_point_candidate=None,
                crown_jewel_target=None,
                dwell_time_seconds=0.0,
                overall_confidence=0.0,
                telemetry_gaps=["No observed events or alerts could be mapped to ATT&CK techniques."],
                observed_stages=[],
                inferred_stages=[],
                contradictory_evidence=[],
            )

        # 2. Convert mappings into candidate chain steps
        candidate_steps: list[AttackChainStep] = []
        for m, source_obj in raw_mappings:
            stage_idx = cls.TACTIC_TO_STAGE_INDEX.get(m.tactic_id, 99)
            ts = getattr(source_obj, "timestamp", m.timestamp)
            ip = getattr(source_obj, "source_ip", None) or getattr(source_obj, "target_ip", None)
            host = getattr(source_obj, "hostname", None) or getattr(source_obj, "target_host", None)
            user = getattr(source_obj, "username", None) or getattr(source_obj, "target_user", None)

            step = AttackChainStep(
                step_id=f"stp-{uuid.uuid4().hex[:8]}",
                stage_index=stage_idx,
                stage_name=m.tactic_name,
                tactic_id=m.tactic_id,
                technique_id=m.technique_id,
                technique_name=m.technique_name,
                observation_type=StepObservationType.OBSERVED,
                timestamp=ts,
                entity_host=host,
                entity_user=user,
                entity_ip=ip,
                evidence_ids=m.evidence_ids,
                confidence=m.confidence,
                details=m.match_reason,
            )
            candidate_steps.append(step)

        # 3. Sort steps chronologically and by stage index
        candidate_steps.sort(key=lambda s: (s.timestamp, s.stage_index))

        # 4. Analyze progression and identify telemetry gaps
        observed_stage_indices = sorted(list({s.stage_index for s in candidate_steps if s.stage_index < 99}))
        telemetry_gaps: list[str] = []
        inferred_steps: list[AttackChainStep] = []

        if observed_stage_indices:
            min_idx = observed_stage_indices[0]
            max_idx = observed_stage_indices[-1]

            # If execution/persistence was observed but initial access was unobserved
            if min_idx > 1:
                telemetry_gaps.append(
                    f"Telemetry Gap: Attack initiated at Stage {min_idx} ({cls.STAGE_ORDER[min_idx][1]}) "
                    f"without observed Initial Access telemetry (perimeter log blind spot)."
                )

            # Check gaps between observed intermediate stages
            for i in range(len(observed_stage_indices) - 1):
                cur_idx = observed_stage_indices[i]
                next_idx = observed_stage_indices[i + 1]
                if next_idx - cur_idx > 1:
                    missing_stages = [cls.STAGE_ORDER[j][1] for j in range(cur_idx + 1, next_idx)]
                    telemetry_gaps.append(
                        f"Unobserved Progression: Adversary moved from {cls.STAGE_ORDER[cur_idx][1]} to "
                        f"{cls.STAGE_ORDER[next_idx][1]} with unobserved stages: {', '.join(missing_stages)}."
                    )
                    # Add an inferred step for the primary missing stage
                    missing_tac, missing_name = cls.STAGE_ORDER[cur_idx + 1]
                    inferred_steps.append(
                        AttackChainStep(
                            step_id=f"inf-{uuid.uuid4().hex[:8]}",
                            stage_index=cur_idx + 1,
                            stage_name=missing_name,
                            tactic_id=missing_tac,
                            technique_id="T-INFERRED",
                            technique_name=f"Inferred {missing_name} Transition",
                            observation_type=StepObservationType.INFERRED,
                            timestamp=candidate_steps[i].timestamp,
                            confidence=0.50,
                            details=f"Heuristically inferred stage between {cls.STAGE_ORDER[cur_idx][1]} and {cls.STAGE_ORDER[next_idx][1]}.",
                        )
                    )

        # Combine observed and inferred steps
        all_steps = sorted(candidate_steps + inferred_steps, key=lambda s: (s.timestamp, s.stage_index))

        # 5. Contradictory Evidence & Dwell Time Calculation
        contradictory_evidence: list[str] = []
        dwell_seconds = 0.0

        # Check chronological consistency across candidate steps
        for i in range(len(candidate_steps) - 1):
            s_curr = candidate_steps[i]
            s_next = candidate_steps[i + 1]
            try:
                t_c = datetime.fromisoformat(s_curr.timestamp.replace("Z", "+00:00"))
                t_n = datetime.fromisoformat(s_next.timestamp.replace("Z", "+00:00"))
                if s_curr.stage_index > s_next.stage_index and t_c <= t_n:
                    contradictory_evidence.append(
                        f"Temporal Anomaly / Contradiction: Later kill-chain stage '{s_curr.stage_name}' (stage {s_curr.stage_index}) "
                        f"occurred at {s_curr.timestamp}, prior to earlier stage '{s_next.stage_name}' (stage {s_next.stage_index}) at {s_next.timestamp}."
                    )
                elif s_curr.stage_index < s_next.stage_index and t_c > t_n:
                    contradictory_evidence.append(
                        f"Temporal Anomaly: Earlier kill-chain stage '{s_curr.stage_name}' has timestamp ({s_curr.timestamp}) "
                        f"later than subsequent stage '{s_next.stage_name}' ({s_next.timestamp})."
                    )
            except Exception:
                pass

        if candidate_steps:
            try:
                t_first = datetime.fromisoformat(candidate_steps[0].timestamp.replace("Z", "+00:00"))
                t_last = datetime.fromisoformat(candidate_steps[-1].timestamp.replace("Z", "+00:00"))
                if t_last >= t_first:
                    dwell_seconds = (t_last - t_first).total_seconds()
                else:
                    contradictory_evidence.append("Reversed timestamps detected: Latest event timestamp is earlier than initial event.")
            except Exception:
                dwell_seconds = 0.0

        # 6. Entry point and crown jewel candidates (strictly grounded in evidence)
        observed_tactics = {s.tactic_id for s in candidate_steps}
        entry_point = None
        if "TA0001" in observed_tactics or "TA0043" in observed_tactics:
            for st in candidate_steps:
                if st.tactic_id in ("TA0001", "TA0043"):
                    entry_point = st.entity_ip or st.entity_host
                    if entry_point:
                        break
        else:
            entry_point = None

        crown_jewel = None
        has_impact_evidence = any(t in observed_tactics for t in ("TA0040", "TA0010", "TA0009"))
        has_dc_target = any(
            st.entity_host and ("dc" in st.entity_host.lower() or "prod" in st.entity_host.lower())
            for st in candidate_steps
        )
        if has_impact_evidence or has_dc_target:
            for st in reversed(candidate_steps):
                if st.entity_host and ("dc" in st.entity_host.lower() or "prod" in st.entity_host.lower()):
                    crown_jewel = st.entity_host
                    break
            if not crown_jewel and has_impact_evidence:
                crown_jewel = candidate_steps[-1].entity_host or candidate_steps[-1].entity_ip
        else:
            crown_jewel = None

        # Overall confidence: mean of observed steps
        observed_steps = [s for s in all_steps if s.observation_type == StepObservationType.OBSERVED]
        overall_conf = round(sum(s.confidence for s in observed_steps) / len(observed_steps), 3) if observed_steps else 0.5

        observed_stage_names = sorted(list({s.stage_name for s in observed_steps}))
        inferred_stage_names = sorted(list({s.stage_name for s in all_steps if s.observation_type == StepObservationType.INFERRED}))

        return AttackChain(
            chain_id=chain_id,
            title=chain_title or f"Correlated Attack Chain ({len(observed_stage_names)} Stages Observed)",
            steps=all_steps,
            entry_point_candidate=entry_point,
            crown_jewel_target=crown_jewel,
            dwell_time_seconds=dwell_seconds,
            overall_confidence=overall_conf,
            telemetry_gaps=telemetry_gaps,
            observed_stages=observed_stage_names,
            inferred_stages=inferred_stage_names,
            contradictory_evidence=contradictory_evidence,
        )
