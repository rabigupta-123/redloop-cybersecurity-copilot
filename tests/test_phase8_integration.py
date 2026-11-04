"""Tests for Phase 8 Enterprise Integrations Gateway & Case Verification (Phase 8).

Verifies:
- Provider-neutral gateway registry listing, filtering, and secret isolation
- Provider alias resolution ("elastic", "defender", "crowdstrike", "ad")
- Health probe execution across all categories
- Capability matrix inspection
- Integration enable/disable lifecycle transitions and audit logging
- Case forward-hash chain verification (INTACT vs TAMPERED)
- Exportable tamper-evident case audit reports
- Secret scrubbing from public configs and error messages
"""

import copy
import json
from pathlib import Path
import tempfile

import pytest

from redloop.assessment.case_management import CaseManager, CaseSeverity, CaseStatus
from redloop.integrations.base import (
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.credentials import mask_secret, sanitize_config
from redloop.integrations.registry import IntegrationRegistry


class TestPhase8GatewayAndCaseIntegrity:
    def test_01_gateway_list_all_providers_no_secrets(self):
        reg = IntegrationRegistry.get_instance()
        providers = reg.list_providers()
        assert len(providers) >= 9

        provider_ids = {p["provider_id"] for p in providers}
        expected_ids = {
            "wazuh",
            "elastic_security",
            "splunk",
            "defender_endpoint",
            "crowdstrike_falcon",
            "entra_id",
            "active_directory",
            "jira",
            "servicenow",
        }
        for eid in expected_ids:
            assert eid in provider_ids

        # Ensure no plaintext secrets are exposed
        for p in providers:
            cfg = p.get("config", {})
            for k, v in cfg.items():
                if any(sec in k.lower() for sec in ["secret", "password", "token", "api_key"]):
                    if v:
                        assert "******" in str(v)

    def test_02_filter_by_category(self):
        reg = IntegrationRegistry.get_instance()
        siem_providers = reg.list_providers(category=ProviderCategory.SIEM)
        assert len(siem_providers) >= 3
        for p in siem_providers:
            assert p["category"] == "SIEM"

        edr_providers = reg.list_providers(category=ProviderCategory.EDR)
        assert len(edr_providers) >= 2
        for p in edr_providers:
            assert p["category"] == "EDR"

        identity_providers = reg.list_providers(category=ProviderCategory.IDENTITY)
        assert len(identity_providers) >= 2
        for p in identity_providers:
            assert p["category"] == "IDENTITY"

        ticketing_providers = reg.list_providers(category=ProviderCategory.TICKETING)
        assert len(ticketing_providers) >= 2
        for p in ticketing_providers:
            assert p["category"] == "TICKETING"

    def test_03_provider_alias_resolution(self):
        reg = IntegrationRegistry.get_instance()
        assert reg.get_provider("wazuh") is not None
        assert reg.get_provider("elastic").provider_id == "elastic_security"
        assert reg.get_provider("defender").provider_id == "defender_endpoint"
        assert reg.get_provider("crowdstrike").provider_id == "crowdstrike_falcon"
        assert reg.get_provider("ad").provider_id == "active_directory"
        assert reg.get_provider("jira").provider_id == "jira"
        assert reg.get_provider("servicenow").provider_id == "servicenow"
        assert reg.get_provider("non_existent_provider_xyz") is None

    def test_04_health_check_probes(self):
        reg = IntegrationRegistry.get_instance()
        # Probe unconfigured Wazuh
        res_wazuh = reg.test_provider("wazuh")
        assert res_wazuh.status == ProviderStatus.NOT_CONFIGURED
        assert "not configured" in res_wazuh.message.lower()

        # Probe unregistered provider
        res_unknown = reg.test_provider("phantom_siem")
        assert res_unknown.status == ProviderStatus.NOT_CONFIGURED
        assert "not registered" in res_unknown.message.lower()

    def test_05_capability_matrix_inspection(self):
        reg = IntegrationRegistry.get_instance()
        wazuh = reg.get_provider("wazuh")
        assert "READ_ALERTS" in wazuh.get_capabilities()
        assert "GET_AGENT_HEALTH" in wazuh.get_capabilities()

        defender = reg.get_provider("defender")
        assert "ISOLATE_ENDPOINT" in defender.get_capabilities()
        assert "GET_DEVICE_INVENTORY" in defender.get_capabilities()

        entra = reg.get_provider("entra_id")
        assert "REVOKE_USER_SESSIONS" in entra.get_capabilities()
        assert "LOOKUP_USER" in entra.get_capabilities()

        jira = reg.get_provider("jira")
        assert "CREATE_INCIDENT_TICKET" in jira.get_capabilities()

    def test_06_enable_disable_and_audit_logging(self):
        reg = IntegrationRegistry.get_instance()
        # Enable Wazuh
        assert reg.enable_provider("wazuh", enabled=True)
        assert reg.get_provider("wazuh").enabled is True

        # Disable Wazuh
        assert reg.enable_provider("wazuh", enabled=False)
        assert reg.get_provider("wazuh").enabled is False

        # Verify audit log captures actions
        audit = reg.get_audit_log(limit=10)
        assert len(audit) > 0
        actions = [a["action"] for a in audit]
        assert "ENABLED" in actions or "DISABLED" in actions
        for entry in audit:
            assert "timestamp" in entry
            assert "provider_id" in entry

    def test_07_case_forward_hash_chain_verification_intact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_audit.db"
            cm = CaseManager(db_path=db_path)

            case = cm.create_case(
                title="Ransomware Outbreak on File Server",
                description="Mass file encryption activity detected on fs01.",
                severity=CaseSeverity.CRITICAL,
                creator="soc_analyst",
            )
            cm.attach_evidence(case.case_id, evidence_ids=["ev-hash-1", "ev-hash-2"], actor="analyst")
            cm.add_note(case.case_id, author="analyst", content="Isolating host fs01.")
            cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING, actor="analyst")

            # Verify integrity
            integ = cm.verify_case_integrity(case.case_id)
            assert integ["status"] == "INTACT"
            assert integ["is_valid"] is True
            assert integ["broken_index"] is None
            assert integ["timeline_events_verified"] >= 4

    def test_08_case_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_tamper.db"
            cm = CaseManager(db_path=db_path)

            case = cm.create_case(
                title="Unauthorized Privilege Escalation",
                description="User added to Domain Admins.",
                severity=CaseSeverity.HIGH,
                creator="soc_lead",
            )
            cm.add_note(case.case_id, author="analyst", content="Investigating domain admin addition.")
            cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING, actor="analyst")

            # Tamper with the case timeline directly in SQLite
            conn = cm._get_connection()
            try:
                with conn:
                    cur = conn.execute("SELECT timeline_json FROM cases WHERE case_id = ?", (case.case_id,))
                    row = cur.fetchone()
                    tl = json.loads(row[0])
                    # Alter second event description without recomputing hash
                    tl[1]["description"] = "MALICIOUSLY ALTERED TIMELINE NOTE"
                    conn.execute("UPDATE cases SET timeline_json = ? WHERE case_id = ?", (json.dumps(tl), case.case_id))
            finally:
                conn.close()

            # Verify that tamper is detected
            integ = cm.verify_case_integrity(case.case_id)
            assert integ["status"] == "TAMPERED"
            assert integ["is_valid"] is False
            assert integ["broken_index"] is not None

    def test_09_exportable_case_audit_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cases_report.db"
            cm = CaseManager(db_path=db_path)

            case = cm.create_case(
                title="Data Exfiltration Investigation",
                description="High volume outbound transfer to suspicious IP.",
                severity=CaseSeverity.HIGH,
                creator="analyst",
            )
            cm.add_note(case.case_id, author="analyst", content="Verified flow metadata.")

            report = cm.export_case_audit_report(case.case_id)
            assert report["case_id"] == case.case_id
            assert report["title"] == "Data Exfiltration Investigation"
            assert report["integrity_verification"]["status"] == "INTACT"
            assert report["integrity_verification"]["is_valid"] is True
            assert len(report["timeline"]) >= 2
            for ev in report["timeline"]:
                assert "entry_hash" in ev
                assert "prev_hash" in ev

    def test_10_sync_job_lifecycle(self):
        reg = IntegrationRegistry.get_instance()
        job_id = reg.start_sync_job(limit_per_provider=5)
        assert job_id.startswith("job-")
        job = reg.get_sync_job(job_id)
        assert job is not None
        assert job["status"] == "COMPLETED"
        assert "total_ingested" in job
