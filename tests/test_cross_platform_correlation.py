"""Tests for Cross-Platform Event Correlation & End-to-End Incident Workflow (Phase 8).

Verifies:
- Telemetry from external providers (Wazuh, Defender) normalizing into UniversalSecurityEvents
- Correlation with MITRE ATT&CK mapping engine
- Case creation, evidence linking, and SHA-256 hash-chain integrity verification
- Approval-gated EDR containment tied into case timeline
"""

import json
from io import BytesIO
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from redloop.assessment.attack_mapping import AttackMappingEngine
from redloop.assessment.case_management import CaseManager, CaseSeverity, CaseStatus
from redloop.assessment.soc_events import EventCategory, EventSeverity, UniversalSecurityEvent
from redloop.integrations.adapters.edr_defender import DefenderForEndpointAdapter
from redloop.integrations.adapters.wazuh import WazuhAdapter
from redloop.integrations.normalizers import normalize_defender_alert, normalize_wazuh_alert
from redloop.integrations.registry import IntegrationRegistry


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestCrossPlatformCorrelation:
    def test_wazuh_alert_to_attack_mapping(self):
        raw_wazuh = {
            "id": "wz-99881",
            "timestamp": "2026-11-04T12:00:00Z",
            "rule": {
                "id": "100200",
                "level": 12,
                "description": "Obfuscated PowerShell Execution Detected",
                "groups": ["sysmon_process_create", "process"],
            },
            "agent": {"name": "fin-dc01", "ip": "10.0.5.15"},
            "data": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgA... -ExecutionPolicy Bypass",
            },
        }

        event = normalize_wazuh_alert(raw_wazuh, provider_id="wazuh")
        assert event.source_type == "wazuh"
        assert event.severity == EventSeverity.CRITICAL
        assert event.event_category == EventCategory.PROCESS

        # Correlate with ATT&CK Engine
        mappings = AttackMappingEngine.map_event(event)
        assert len(mappings) >= 1
        technique_ids = [m.technique_id for m in mappings]
        assert "T1059.001" in technique_ids

    def test_end_to_end_case_workflow_with_containment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_test.db"
            cm = CaseManager(db_path=db_path)

            # 1. Create incident case from correlated alert
            case = cm.create_case(
                title="Credential Dumping on Domain Controller",
                description="Mimikatz executed on fin-dc01. Multiple service account hashes dumped.",
                severity=CaseSeverity.CRITICAL,
                creator="soc_correlator",
            )
            assert case.case_id.startswith("case-")
            assert case.status == CaseStatus.OPEN

            # 2. Attach evidence
            evidence_ids = ["ev-wazuh-wz-99881", "ev-sysmon-proc-dump"]
            cm.attach_evidence(case.case_id, evidence_ids=evidence_ids, actor="analyst")

            # 3. Add investigative note
            cm.add_note(case.case_id, author="analyst", content="Host confirmed compromised. Requesting Defender containment.")

            # Move status to INVESTIGATING
            cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING, actor="analyst")

            # 4. Perform approval-gated containment via EDR adapter
            defender = DefenderForEndpointAdapter(
                tenant_id="test-tenant",
                client_id="test-client",
                client_secret="test-secret",
            )
            with patch("urllib.request.urlopen") as mock_urlopen:
                token_resp = make_mock_response({"access_token": "token-123", "expires_in": 3600})
                isolate_resp = make_mock_response({"id": "action-443", "status": "Succeeded"}, status=201)
                mock_urlopen.side_effect = [token_resp, isolate_resp]

                containment_res = defender.isolate_endpoint(
                    machine_id="mach-fin-dc01",
                    comment="Automated response: credential dumping containment",
                    capability_token="valid-approved-token-123",
                )
                assert containment_res["status"] == "SUCCEEDED"

            # 5. Record containment in case timeline
            cm.update_case(
                case.case_id,
                status=CaseStatus.CONTAINMENT_IN_PROGRESS,
                actor="soc_operator",
            )

            # 6. Verify cryptographic hash chain integrity of the case
            integ = cm.verify_case_integrity(case.case_id)
            assert integ["status"] == "INTACT"
            assert integ["is_valid"] is True
            assert integ["broken_index"] is None
            assert integ["timeline_events_verified"] >= 4  # CREATE, ATTACH_EVIDENCE, ADD_NOTE, UPDATE_STATUS

            # 7. Export tamper-evident audit report
            audit = cm.export_case_audit_report(case.case_id)
            assert audit["case_id"] == case.case_id
            assert audit["integrity_verification"]["status"] == "INTACT"
            assert len(audit["timeline"]) >= 4
            for ev in audit["timeline"]:
                assert "entry_hash" in ev
                assert "prev_hash" in ev
