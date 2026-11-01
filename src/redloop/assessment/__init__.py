"""RedLoop Modular Security Assessment Engine.

Exports:
- AssessmentEngine
- AssessmentScopeGuard, ScopeBlockedError
- AssessmentState, Finding, Evidence, Severity, Confidence, AssessmentDepth, OperationClass
- ReportingEngine
- AISecurityAnalyst
- CapabilityMatrix, get_capabilities
"""

from redloop.assessment.analyst import AISecurityAnalyst
from redloop.assessment.capability import CapabilityMatrix, get_capabilities
from redloop.assessment.engine import AssessmentEngine, AssessmentStore
from redloop.assessment.models import (
    AssessmentDepth,
    AssessmentState,
    AttackSurfaceGraph,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.reporting import ReportingEngine
from redloop.assessment.risk import calculate_risk
from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

__all__ = [
    "AssessmentEngine",
    "AssessmentStore",
    "AssessmentScopeGuard",
    "ScopeBlockedError",
    "AssessmentState",
    "Finding",
    "Evidence",
    "Severity",
    "Confidence",
    "AssessmentDepth",
    "OperationClass",
    "StageResult",
    "StageStatus",
    "FindingStatus",
    "AttackSurfaceGraph",
    "ReportingEngine",
    "AISecurityAnalyst",
    "CapabilityMatrix",
    "get_capabilities",
    "calculate_risk",
    "Task",
    "TaskStore",
    "TaskOrchestrator",
    "ExploitSimulator",
    "ShodanEngine",
    "CTFCodec",
]

from redloop.assessment.orchestrator import Task, TaskStore, TaskOrchestrator
from redloop.assessment.exploit_simulator import ExploitSimulator
from redloop.assessment.shodan_engine import ShodanEngine
from redloop.assessment.ctf_toolkit import CTFCodec
