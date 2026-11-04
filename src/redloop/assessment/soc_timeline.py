"""Chronological SOC Timeline & Incident Correlation Engine (Phase 5).

Provides:
- Chronological investigation timeline with strict UTC ordering and provenance linkage
- Incident correlation clustering related alerts, events, and evidence
- Graph relations: SAME_SOURCE, SAME_HOST, SAME_USER, SAME_INDICATOR, TEMPORALLY_RELATED, SUPPORTS, CONTRADICTS, POSSIBLY_CAUSED_BY
- Strict contextual isolation between unrelated investigations
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from redloop.assessment.finding_models import Finding
from redloop.assessment.soc_detection import SOCAlert
from redloop.assessment.soc_events import EventCategory, EventSeverity, UniversalSecurityEvent


class IncidentRelationType(str, Enum):
    SAME_SOURCE = "SAME_SOURCE"
    SAME_HOST = "SAME_HOST"
    SAME_USER = "SAME_USER"
    SAME_INDICATOR = "SAME_INDICATOR"
    TEMPORALLY_RELATED = "TEMPORALLY_RELATED"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    POSSIBLY_CAUSED_BY = "POSSIBLY_CAUSED_BY"


class EvidenceObservationClass(str, Enum):
    CONFIRMED_OBSERVATION = "CONFIRMED_OBSERVATION"
    CORRELATED_OBSERVATION = "CORRELATED_OBSERVATION"
    INFERENCE = "INFERENCE"
    UNVERIFIED_HYPOTHESIS = "UNVERIFIED_HYPOTHESIS"


@dataclass
class SOCTimelineItem:
    """Single chronological item within an investigation timeline."""
    item_id: str
    timestamp: str  # ISO 8601 UTC
    item_type: str  # "event", "alert", "finding", "ioc_lookup"
    title: str
    description: str
    severity: EventSeverity
    source_id: str
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    category: str = "security"
    raw_evidence_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        return d


@dataclass
class SOCIncidentRelation:
    """Directed relational link between incident entities or evidence items."""
    source_id: str
    target_id: str
    relation_type: IncidentRelationType
    confidence: float
    rationale: str
    supporting_evidence_ids: list[str] = field(default_factory=list)
    observation_class: EvidenceObservationClass = EvidenceObservationClass.CORRELATED_OBSERVATION

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["relation_type"] = self.relation_type.value if hasattr(self.relation_type, "value") else str(self.relation_type)
        d["observation_class"] = self.observation_class.value if hasattr(self.observation_class, "value") else str(self.observation_class)
        return d


@dataclass
class SOCIncident:
    """Correlated Security Incident grouping alerts, timeline, and response actions."""
    incident_id: str
    title: str
    severity: EventSeverity
    status: str = "NEW"  # NEW, TRIAGED, CONTAINED, RESOLVED, CLOSED
    summary: str = ""
    alerts: list[SOCAlert] = field(default_factory=list)
    timeline: list[SOCTimelineItem] = field(default_factory=list)
    relations: list[SOCIncidentRelation] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    scope_hosts: list[str] = field(default_factory=list)
    scope_users: list[str] = field(default_factory=list)
    scope_ips: list[str] = field(default_factory=list)
    recommended_playbook_id: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now_iso
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "status": self.status,
            "summary": self.summary,
            "alerts": [a.to_dict() for a in self.alerts],
            "timeline": [t.to_dict() for t in self.timeline],
            "relations": [r.to_dict() for r in self.relations],
            "indicators": self.indicators,
            "scope_hosts": self.scope_hosts,
            "scope_users": self.scope_users,
            "scope_ips": self.scope_ips,
            "recommended_playbook_id": self.recommended_playbook_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class SOCTimelineEngine:
    """Builds and filters sorted, evidence-grounded incident timelines."""

    @staticmethod
    def build_timeline(
        events: list[UniversalSecurityEvent] | None = None,
        alerts: list[SOCAlert] | None = None,
        findings: list[Finding] | None = None,
    ) -> list[SOCTimelineItem]:
        """Constructs unified chronological timeline from disparate security observations."""
        items: list[SOCTimelineItem] = []

        if events:
            for ev in events:
                items.append(
                    SOCTimelineItem(
                        item_id=f"tl-evt-{ev.event_id}",
                        timestamp=ev.timestamp,
                        item_type="event",
                        title=f"{ev.source_type.upper()}: {ev.event_action}",
                        description=f"Action '{ev.event_action}' logged on {ev.hostname or ev.source_ip or 'host'}.",
                        severity=ev.severity,
                        source_id=ev.event_id,
                        hostname=ev.hostname,
                        username=ev.username,
                        source_ip=ev.source_ip,
                        destination_ip=ev.destination_ip,
                        category=ev.event_category.value if hasattr(ev.event_category, "value") else str(ev.event_category),
                        raw_evidence_id=ev.raw_evidence_id,
                    )
                )

        if alerts:
            for al in alerts:
                items.append(
                    SOCTimelineItem(
                        item_id=f"tl-alt-{al.alert_id}",
                        timestamp=al.timestamp,
                        item_type="alert",
                        title=f"ALERT [{al.rule_id}]: {al.title}",
                        description=al.description,
                        severity=al.severity,
                        source_id=al.alert_id,
                        hostname=al.target_host,
                        username=al.target_user,
                        source_ip=al.target_ip,
                        category="alert",
                        metadata={"confidence": al.confidence, "rule_id": al.rule_id},
                    )
                )

        if findings:
            for f in findings:
                sev_map = {
                    "CRITICAL": EventSeverity.CRITICAL,
                    "HIGH": EventSeverity.HIGH,
                    "MEDIUM": EventSeverity.MEDIUM,
                    "LOW": EventSeverity.LOW,
                    "INFORMATIONAL": EventSeverity.INFORMATIONAL,
                }
                items.append(
                    SOCTimelineItem(
                        item_id=f"tl-fnd-{f.finding_id}",
                        timestamp=f.first_seen or datetime.now(timezone.utc).isoformat(),
                        item_type="finding",
                        title=f"VULNERABILITY: {f.title}",
                        description=f.description,
                        severity=sev_map.get(f.severity.value, EventSeverity.MEDIUM),
                        source_id=f.finding_id,
                        hostname=f.target if f.target_type == "domain" else None,
                        source_ip=f.target if f.target_type == "ip" else None,
                        category="vulnerability",
                        raw_evidence_id=f.raw_evidence_id,
                        metadata={"risk_score": f.risk_score, "cves": f.cve_ids},
                    )
                )

        # Strict chronological sort (earliest first)
        items.sort(key=lambda x: x.timestamp)
        return items

    @staticmethod
    def filter_timeline(
        items: list[SOCTimelineItem],
        host: str | None = None,
        user: str | None = None,
        ip: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[SOCTimelineItem]:
        filtered = items
        if host:
            filtered = [i for i in filtered if i.hostname and host.lower() in i.hostname.lower()]
        if user:
            filtered = [i for i in filtered if i.username and user.lower() in i.username.lower()]
        if ip:
            filtered = [i for i in filtered if (i.source_ip == ip or i.destination_ip == ip)]
        if category:
            filtered = [i for i in filtered if category.lower() in i.category.lower()]
        if severity:
            filtered = [i for i in filtered if i.severity.value.upper() == severity.upper()]
        if start_time:
            filtered = [i for i in filtered if i.timestamp >= start_time]
        if end_time:
            filtered = [i for i in filtered if i.timestamp <= end_time]
        return filtered


class SOCIncidentCorrelator:
    """Correlates alerts and events into structured, evidence-backed security incidents."""

    @classmethod
    def correlate_alerts(
        cls,
        alerts: list[SOCAlert],
        events: list[UniversalSecurityEvent] | None = None,
    ) -> list[SOCIncident]:
        """Clusters alerts sharing common indicators, hosts, or users into incidents."""
        if not alerts:
            return []

        incidents: list[SOCIncident] = []
        # Group alerts by primary entity (Host, User, or IP)
        entity_clusters: dict[str, list[SOCAlert]] = {}

        for alert in alerts:
            entity_key = alert.target_host or alert.target_ip or alert.target_user or "perimeter"
            entity_clusters.setdefault(entity_key, []).append(alert)

        for entity, cluster_alerts in entity_clusters.items():
            max_sev = EventSeverity.LOW
            for al in cluster_alerts:
                if al.severity == EventSeverity.CRITICAL:
                    max_sev = EventSeverity.CRITICAL
                    break
                elif al.severity == EventSeverity.HIGH and max_sev != EventSeverity.CRITICAL:
                    max_sev = EventSeverity.HIGH
                elif al.severity == EventSeverity.MEDIUM and max_sev not in (EventSeverity.CRITICAL, EventSeverity.HIGH):
                    max_sev = EventSeverity.MEDIUM

            # Gather indicators
            indicators: set[str] = set()
            hosts: set[str] = set()
            users: set[str] = set()
            ips: set[str] = set()
            all_event_ids: set[str] = set()

            for al in cluster_alerts:
                if al.target_host:
                    hosts.add(al.target_host)
                if al.target_user:
                    users.add(al.target_user)
                if al.target_ip:
                    ips.add(al.target_ip)
                    indicators.add(al.target_ip)
                for ci_key, ci_val in al.context_indicators.items():
                    if isinstance(ci_val, str) and len(ci_val) < 60:
                        indicators.add(ci_val)
                all_event_ids.update(al.matched_event_ids)

            # Build sub-timeline
            matched_events = [e for e in (events or []) if e.event_id in all_event_ids]
            sub_timeline = SOCTimelineEngine.build_timeline(events=matched_events, alerts=cluster_alerts)

            # Build relations
            relations: list[SOCIncidentRelation] = []
            for idx in range(len(cluster_alerts) - 1):
                a1 = cluster_alerts[idx]
                a2 = cluster_alerts[idx + 1]
                rel_type = IncidentRelationType.SAME_HOST if a1.target_host == a2.target_host else IncidentRelationType.SAME_SOURCE
                relations.append(
                    SOCIncidentRelation(
                        source_id=a1.alert_id,
                        target_id=a2.alert_id,
                        relation_type=rel_type,
                        confidence=0.85,
                        rationale=f"Alerts share common entity '{entity}'.",
                        supporting_evidence_ids=a1.matched_event_ids[:2] + a2.matched_event_ids[:2],
                        observation_class=EvidenceObservationClass.CORRELATED_OBSERVATION,
                    )
                )

            # Recommended playbook based on rules
            playbook_id = "PB-MALWARE"
            rule_ids = {al.rule_id for al in cluster_alerts}
            if "SEC-AUTH-001" in rule_ids or "SEC-AUTH-002" in rule_ids:
                playbook_id = "PB-CRED" if "SEC-AUTH-002" in rule_ids else "PB-BRUTE"
            elif "SEC-PROC-001" in rule_ids:
                playbook_id = "PB-PSHELL"
            elif "SEC-WEB-001" in rule_ids or "SEC-PROC-002" in rule_ids:
                playbook_id = "PB-WEB"
            elif "SEC-NET-001" in rule_ids:
                playbook_id = "PB-OUTBOUND"

            title = f"Security Incident: {cluster_alerts[0].title} on {entity}"
            summary = (
                f"Correlated {len(cluster_alerts)} alerts across {len(matched_events)} events. "
                f"Impacted assets: {', '.join(hosts or ips or ['Perimeter'])}. "
                f"Primary indicators: {', '.join(list(indicators)[:5])}."
            )

            incidents.append(
                SOCIncident(
                    incident_id=f"inc-{uuid.uuid4().hex[:8]}",
                    title=title,
                    severity=max_sev,
                    status="TRIAGED",
                    summary=summary,
                    alerts=cluster_alerts,
                    timeline=sub_timeline,
                    relations=relations,
                    indicators=sorted(list(indicators)),
                    scope_hosts=sorted(list(hosts)),
                    scope_users=sorted(list(users)),
                    scope_ips=sorted(list(ips)),
                    recommended_playbook_id=playbook_id,
                )
            )

        return incidents
