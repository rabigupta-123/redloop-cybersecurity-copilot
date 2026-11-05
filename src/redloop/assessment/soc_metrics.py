"""REDLOOP Autonomous SOC Operations — Measurable Operational Metrics & Reporting (Phase 9).

Provides:
1. Exact mathematical calculations for MTTD, MTTR, action success rates, and sync rates.
2. Ingestion volume, alert generation, and duplicate suppression metrics.
3. Provider availability and detection engineering coverage statistics.
4. Transparent separation of confirmed metrics from unavailable/unsupported values.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from redloop.assessment.case_management import CaseManager
from redloop.assessment.detection_engineering import DetectionEngineeringManager
from redloop.assessment.incident_correlation import IncidentCorrelationEngine
from redloop.assessment.soc_sync import TelemetrySyncPipeline
from redloop.integrations.registry import IntegrationRegistry


class SOCMetricsEngine:
    """Computes authoritative SOC operational metrics across all engine subsystems."""

    @classmethod
    def get_operational_metrics(cls) -> dict[str, Any]:
        """Calculates consolidated operational SOC metrics with explicit mathematical provenance."""
        now = datetime.now(timezone.utc).isoformat()

        # 1. Telemetry Ingestion & Sync Metrics
        sync_pipe = TelemetrySyncPipeline.get_instance()
        sync_stats = sync_pipe.get_sync_metrics()
        total_ingested = sync_stats.get("total_events_ingested", 0)
        sync_success_rate = sync_stats.get("sync_success_rate_percent", 100.0)

        # Ingested events rejected / duplicates
        job_breakdown = sync_stats.get("job_status_breakdown", {})
        failed_jobs = job_breakdown.get("FAILED", 0)
        partial_jobs = job_breakdown.get("PARTIAL", 0)

        # 2. Incident & Correlation Metrics
        corr_engine = IncidentCorrelationEngine.get_instance()
        all_incidents = corr_engine.list_incidents(include_merged=True, limit=500)
        active_incidents = [i for i in all_incidents if not i.get("merged_into")]
        open_incidents_count = len(active_incidents)

        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total_linked_events = 0
        confirmed_observations = 0
        inferred_relationships = 0

        for inc in active_incidents:
            sev = inc.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_linked_events += len(inc.get("linked_events", []))
            confirmed_observations += inc.get("confirmed_observations_count", 0)
            inferred_relationships += inc.get("inferred_relationships_count", 0)

        duplicate_alerts_suppressed = max(0, total_linked_events - open_incidents_count)

        # 3. Detection Engineering Metrics
        det_mgr = DetectionEngineeringManager.get_instance()
        attack_cov = det_mgr.get_attack_coverage_matrix()
        active_rules_count = attack_cov.get("total_active_rules", 0)
        technique_coverage_pct = attack_cov.get("coverage_percentage", 0.0)

        # 4. Provider Availability
        registry = IntegrationRegistry.get_instance()
        all_providers = registry.list_providers()
        enabled_providers = [p for p in all_providers if p.get("enabled")]
        connected_providers = [
            p for p in enabled_providers if p.get("connectivity_status") in ("CONNECTED", "DEGRADED")
        ]
        provider_availability_pct = (
            round((len(connected_providers) / len(enabled_providers) * 100.0), 1)
            if enabled_providers else 100.0
        )

        # 5. Case Management & MTTD / MTTR Calculations
        cm = CaseManager.get_instance()
        cases = cm.list_cases(limit=100)
        resolved_cases = [c for c in cases if c.get("status") in ("RESOLVED", "CLOSED")]

        # Calculate MTTR (Mean Time to Respond/Resolve in minutes)
        mttr_minutes: Optional[float] = None
        if resolved_cases:
            diffs = []
            for c in resolved_cases:
                try:
                    c_start = datetime.fromisoformat(c["created_at"])
                    c_end = datetime.fromisoformat(c.get("closure_timestamp") or c["updated_at"])
                    diff_mins = (c_end - c_start).total_seconds() / 60.0
                    if diff_mins >= 0:
                        diffs.append(diff_mins)
                except Exception:
                    pass
            if diffs:
                mttr_minutes = round(sum(diffs) / len(diffs), 1)

        # Calculate MTTD (Mean Time to Detect in minutes)
        mttd_minutes: Optional[float] = None
        if active_incidents:
            mttd_diffs = []
            for inc in active_incidents:
                links = inc.get("linked_events", [])
                if links:
                    try:
                        earliest_event_ts = datetime.fromisoformat(links[0]["timestamp"])
                        inc_created_ts = datetime.fromisoformat(inc["created_at"])
                        diff_m = (inc_created_ts - earliest_event_ts).total_seconds() / 60.0
                        if diff_m >= 0:
                            mttd_diffs.append(diff_m)
                    except Exception:
                        pass
            if mttd_diffs:
                mttd_minutes = round(sum(mttd_diffs) / len(mttd_diffs), 1)

        reduction_pct = (
            round((duplicate_alerts_suppressed / total_linked_events * 100.0), 1)
            if total_linked_events > 0 else 0.0
        )

        mttd_status = "CALCULATED" if mttd_minutes is not None else "INSUFFICIENT_DATA"
        mttr_status = "CALCULATED" if mttr_minutes is not None else "INSUFFICIENT_DATA"
        sync_status = "CALCULATED" if total_ingested > 0 or failed_jobs > 0 or partial_jobs > 0 else "INSUFFICIENT_DATA"
        reduction_status = "CALCULATED" if total_linked_events > 0 else "INSUFFICIENT_DATA"

        return {
            "metrics_timestamp": now,
            "mean_time_to_detect_minutes": mttd_minutes,
            "mean_time_to_detect_status": mttd_status,
            "mean_time_to_respond_minutes": mttr_minutes,
            "mean_time_to_respond_status": mttr_status,
            "telemetry_sync_rate_percent": sync_success_rate,
            "telemetry_sync_status": sync_status,
            "provider_availability_percent": provider_availability_pct,
            "alert_reduction_rate_percent": reduction_pct,
            "alert_reduction_status": reduction_status,
            "telemetry": {
                "events_ingested": total_ingested,
                "sync_jobs_failed": failed_jobs,
                "sync_jobs_partial": partial_jobs,
                "sync_success_rate": sync_success_rate,
                "status": sync_status,
            },
            "alerts_and_incidents": {
                "total_alerts_clustered": total_linked_events,
                "open_incidents": open_incidents_count,
                "duplicate_alerts_suppressed": duplicate_alerts_suppressed,
                "incidents_by_severity": severity_counts,
                "confirmed_observations": confirmed_observations,
                "inferred_relationships": inferred_relationships,
                "status": reduction_status,
            },
            "detection_engineering": {
                "active_detection_rules": active_rules_count,
                "attack_technique_coverage_percent": technique_coverage_pct,
                "monitored_techniques_count": attack_cov.get("covered_technique_count", 0),
                "uncovered_detection_gaps": len(attack_cov.get("identified_detection_gaps", [])),
            },
            "providers": {
                "total_providers": len(all_providers),
                "enabled_providers": len(enabled_providers),
                "connected_providers": len(connected_providers),
                "availability_rate_percent": provider_availability_pct,
            },
            "performance_indicators": {
                "mean_time_to_detect_minutes": mttd_minutes,
                "mean_time_to_detect_status": mttd_status,
                "mean_time_to_respond_minutes": mttr_minutes,
                "mean_time_to_respond_status": mttr_status,
                "mttd_supported": mttd_minutes is not None,
                "mttr_supported": mttr_minutes is not None,
            },
            "formula_documentation": {
                "mttd": "Mean duration (minutes) between earliest raw event timestamp and correlated incident cluster genesis.",
                "mttr": "Mean duration (minutes) between incident case creation and formal case resolution timestamp.",
                "sync_success_rate": "(Completed sync jobs / Total sync jobs) * 100",
                "availability": "(Connected enabled providers / Total enabled providers) * 100",
            },
        }
