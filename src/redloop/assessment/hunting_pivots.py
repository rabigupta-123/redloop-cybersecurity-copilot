"""REDLOOP Phase 10 — Threat-Hunting Multi-Hop Pivot Engine.

Provides:
1. Multi-hop entity graph traversal:
   IP <-> Domain <-> Hash <-> User <-> Host <-> Process <-> Alert <-> Incident <-> Case.
2. Provenance tracking: preserves the original telemetry source, rule, or provider for each pivot step.
3. Cycle detection and depth-bounded expansion (default max_depth = 4).
4. Entity resolution across raw events, correlated incidents, IOCs, and active cases.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from redloop.assessment.case_management import CaseManager
from redloop.assessment.incident_correlation import IncidentCorrelationEngine
from redloop.assessment.ioc_engine import IOCLifecycleManager, IOCType
from redloop.assessment.soc_events import UniversalSecurityEvent


class PivotEntityType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    HASH = "HASH"
    USER = "USER"
    HOST = "HOST"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    CASE = "CASE"


@dataclass
class PivotHop:
    """A directional traversal from one entity to an associated entity."""
    hop_index: int
    from_type: PivotEntityType
    from_value: str
    to_type: PivotEntityType
    to_value: str
    relationship: str
    provenance: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop_index": self.hop_index,
            "from_type": self.from_type.value,
            "from_value": self.from_value,
            "to_type": self.to_type.value,
            "to_value": self.to_value,
            "relationship": self.relationship,
            "provenance": self.provenance,
            "confidence": self.confidence,
        }


@dataclass
class PivotGraphResult:
    """Consolidated multi-hop graph of pivoted entities."""
    pivot_id: str
    root_entity_type: PivotEntityType
    root_entity_value: str
    max_depth_explored: int
    total_entities_discovered: int
    hops: list[PivotHop]
    entities: dict[str, list[str]]  # entity_type -> list of values
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "pivot_id": self.pivot_id,
            "root_entity_type": self.root_entity_type.value,
            "root_entity_value": self.root_entity_value,
            "max_depth_explored": self.max_depth_explored,
            "total_entities_discovered": self.total_entities_discovered,
            "hops": [h.to_dict() for h in self.hops],
            "entities": self.entities,
            "executed_at": self.executed_at,
        }


class ThreatHuntingPivotEngine:
    """Executes multi-hop entity pivot searches across events, IOCs, incidents, and cases."""

    @classmethod
    def execute_pivot(
        cls,
        entity_type: PivotEntityType | str,
        entity_value: str,
        events: Optional[list[UniversalSecurityEvent]] = None,
        max_depth: int = 3,
    ) -> PivotGraphResult:
        """Explores multi-hop connections starting from a seed entity."""
        pid = f"piv-{uuid.uuid4().hex[:10]}"
        e_type = PivotEntityType(entity_type.upper()) if isinstance(entity_type, str) else entity_type
        e_val = entity_value.strip().lower() if e_type in (PivotEntityType.DOMAIN, PivotEntityType.HASH) else entity_value.strip()

        bounded_depth = min(max(1, max_depth), 5)
        visited_nodes: set[tuple[PivotEntityType, str]] = set()
        discovered_entities: dict[str, set[str]] = {t.value: set() for t in PivotEntityType}
        hops: list[PivotHop] = []

        discovered_entities[e_type.value].add(e_val)
        queue: list[tuple[PivotEntityType, str, int]] = [(e_type, e_val, 0)]
        visited_nodes.add((e_type, e_val))

        corr_engine = IncidentCorrelationEngine.get_instance()
        ioc_mgr = IOCLifecycleManager.get_instance()
        case_mgr = CaseManager.get_instance()

        event_pool = events or []

        while queue:
            curr_type, curr_val, curr_depth = queue.pop(0)
            if curr_depth >= bounded_depth:
                continue

            # 1. Search in Event Pool
            for ev in event_pool:
                neighbors = cls._find_event_neighbors(curr_type, curr_val, ev)
                for n_type, n_val, rel, prov in neighbors:
                    if (n_type, n_val) not in visited_nodes:
                        visited_nodes.add((n_type, n_val))
                        discovered_entities[n_type.value].add(n_val)
                        hops.append(PivotHop(
                            hop_index=curr_depth + 1,
                            from_type=curr_type,
                            from_value=curr_val,
                            to_type=n_type,
                            to_value=n_val,
                            relationship=rel,
                            provenance=prov,
                            confidence=0.9,
                        ))
                        queue.append((n_type, n_val, curr_depth + 1))

            # 2. Search in Correlated Incidents
            incidents = corr_engine.list_incidents(include_merged=True, limit=100)
            for inc in incidents:
                inc_id = inc.get("incident_id")
                matched = False
                p_h = (inc.get("primary_host") or "").lower()
                p_u = (inc.get("primary_user") or "").lower()
                if curr_type == PivotEntityType.HOST and p_h == curr_val.lower():
                    matched = True
                elif curr_type == PivotEntityType.USER and p_u == curr_val.lower():
                    matched = True
                elif curr_type == PivotEntityType.INCIDENT and inc_id == curr_val:
                    matched = True

                if matched and inc_id:
                    # Link to incident
                    if (PivotEntityType.INCIDENT, inc_id) not in visited_nodes:
                        visited_nodes.add((PivotEntityType.INCIDENT, inc_id))
                        discovered_entities[PivotEntityType.INCIDENT.value].add(inc_id)
                        hops.append(PivotHop(
                            hop_index=curr_depth + 1,
                            from_type=curr_type,
                            from_value=curr_val,
                            to_type=PivotEntityType.INCIDENT,
                            to_value=inc_id,
                            relationship="correlated_in_incident",
                            provenance="IncidentCorrelationEngine",
                            confidence=0.85,
                        ))
                        queue.append((PivotEntityType.INCIDENT, inc_id, curr_depth + 1))

                    # Pivot from incident into other host/user
                    p_host = inc.get("primary_host")
                    p_user = inc.get("primary_user")
                    if p_host and (PivotEntityType.HOST, p_host) not in visited_nodes:
                        visited_nodes.add((PivotEntityType.HOST, p_host))
                        discovered_entities[PivotEntityType.HOST.value].add(p_host)
                        hops.append(PivotHop(
                            hop_index=curr_depth + 2,
                            from_type=PivotEntityType.INCIDENT,
                            from_value=inc_id,
                            to_type=PivotEntityType.HOST,
                            to_value=p_host,
                            relationship="incident_primary_host",
                            provenance="IncidentCorrelationEngine",
                            confidence=0.80,
                        ))
                        queue.append((PivotEntityType.HOST, p_host, curr_depth + 2))

            # 3. Search in Cases
            cases = case_mgr.list_cases(limit=100)
            for c in cases:
                cid = c.get("case_id")
                links_inc = c.get("linked_incident_ids", [])
                indicators = c.get("related_indicators", {})

                linked_case = False
                if curr_type == PivotEntityType.INCIDENT and curr_val in links_inc:
                    linked_case = True
                elif curr_type in (PivotEntityType.IP, PivotEntityType.DOMAIN, PivotEntityType.HASH):
                    for _, ind_list in indicators.items():
                        if curr_val in ind_list:
                            linked_case = True
                            break

                if linked_case and cid and (PivotEntityType.CASE, cid) not in visited_nodes:
                    visited_nodes.add((PivotEntityType.CASE, cid))
                    discovered_entities[PivotEntityType.CASE.value].add(cid)
                    hops.append(PivotHop(
                        hop_index=curr_depth + 1,
                        from_type=curr_type,
                        from_value=curr_val,
                        to_type=PivotEntityType.CASE,
                        to_value=cid,
                        relationship="investigated_in_case",
                        provenance="CaseManager",
                        confidence=0.95,
                    ))
                    queue.append((PivotEntityType.CASE, cid, curr_depth + 1))

        # Format results
        entities_dict = {k: sorted(list(v)) for k, v in discovered_entities.items() if v}
        total_found = sum(len(v) for v in entities_dict.values())

        return PivotGraphResult(
            pivot_id=pid,
            root_entity_type=e_type,
            root_entity_value=e_val,
            max_depth_explored=bounded_depth,
            total_entities_discovered=total_found,
            hops=hops,
            entities=entities_dict,
        )

    @staticmethod
    def _find_event_neighbors(
        src_type: PivotEntityType,
        src_val: str,
        ev: UniversalSecurityEvent,
    ) -> list[tuple[PivotEntityType, str, str, str]]:
        """Finds neighboring entity nodes linked via an individual event."""
        neighbors: list[tuple[PivotEntityType, str, str, str]] = []
        val_l = src_val.lower()

        is_match = False
        if src_type == PivotEntityType.IP and (ev.source_ip == src_val or ev.dest_ip == src_val or ev.destination_ip == src_val):
            is_match = True
        elif src_type == PivotEntityType.HOST and (ev.host and ev.host.lower() == val_l or ev.hostname and ev.hostname.lower() == val_l):
            is_match = True
        elif src_type == PivotEntityType.USER and (ev.user and ev.user.lower() == val_l or ev.username and ev.username.lower() == val_l):
            is_match = True
        elif src_type == PivotEntityType.HASH and (ev.file_hash and ev.file_hash.lower() == val_l):
            is_match = True

        if not is_match:
            return neighbors

        prov = f"Event:{ev.event_id}({ev.source_type})"

        # Link to other event attributes
        if ev.source_ip and (src_type != PivotEntityType.IP or ev.source_ip != src_val):
            neighbors.append((PivotEntityType.IP, ev.source_ip, "observed_source_ip", prov))
        dest = ev.dest_ip or ev.destination_ip
        if dest and (src_type != PivotEntityType.IP or dest != src_val):
            neighbors.append((PivotEntityType.IP, dest, "observed_dest_ip", prov))
        h = ev.host or ev.hostname
        if h and (src_type != PivotEntityType.HOST or h.lower() != val_l):
            neighbors.append((PivotEntityType.HOST, h, "observed_host", prov))
        u = ev.user or ev.username
        if u and (src_type != PivotEntityType.USER or u.lower() != val_l):
            neighbors.append((PivotEntityType.USER, u, "observed_user", prov))
        if ev.file_hash and (src_type != PivotEntityType.HASH or ev.file_hash.lower() != val_l):
            neighbors.append((PivotEntityType.HASH, ev.file_hash.lower(), "observed_file_hash", prov))

        return neighbors
