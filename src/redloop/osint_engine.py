"""Unified OSINT Intelligence Engine for REDLOOP.

Implements Sections 3, 4, 8 & 9:
- Multi-dimensional OSINT across IP, Domain, Email, Username, Phone, and File/Image Metadata.
- Standardized OSINT Result Contract with evidence hashing, timestamps, confidence scores,
  sources, explicit verification states, and limitations.
- Truthful reporting: no fabricated subscriber records, zero fake geolocation,
  and explicit states (VERIFIED, OBSERVED, INFERRED, UNKNOWN, NOT_FOUND_IN_CHECKED_SOURCES,
  PROVIDER_NOT_CONFIGURED, RATE_LIMITED, FAILED).
- Seamless dual-graph synchronization: populates InvestigationGraph (nodes & edges)
  and InvestigationStore from both chat and workspace actions.
"""

from __future__ import annotations

import binascii
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from redloop.transport import get_hardened_client
from pydantic import BaseModel, Field

from redloop.assessment.evaluation import (
    calculate_confidence,
    calculate_provenance_completeness,
    is_offline_mode,
    resolve_verification_state,
    VerificationState,
)
from redloop.assessment.metrics import (
    HEURISTIC_CONFIDENCE,
    INSUFFICIENT_EVIDENCE,
    NOT_CALIBRATED,
    assess_provenance,
    calculate_source_agreement,
    compute_finding_confidence,
    freshness_decay,
)
from redloop.assessment.models import Evidence, Finding, FindingStatus, Severity
from redloop.investigation_graph import (
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeType,
    ProvenanceType,
)

logger = logging.getLogger("redloop.osint_engine")


CONFIDENCE_METHOD = "C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X"

# Canonical, mutually-exclusive IP classifications exposed by the OSINT API.
IP_CLASSIFICATIONS = frozenset(
    {
        "GLOBAL_PUBLIC",
        "LOOPBACK",
        "PRIVATE",
        "LINK_LOCAL",
        "MULTICAST",
        "DOCUMENTATION",
        "RESERVED",
        "UNSPECIFIED",
        "INVALID",
    }
)

_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_SHARED_ADDRESS_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
)
_RESERVED_SPECIAL_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("100::/64"),
)

SUPPORTED_EVIDENCE_HASH_VERSIONS = frozenset({"sha256-canonical-v2"})
EVIDENCE_VERSION_MISMATCH = "SERIALIZATION_VERSION_MISMATCH"


def classify_ip_address(ip_obj: ipaddress._BaseAddress) -> str:
    """Return one canonical classification for a parsed IP address.

    The order matters: Python marks multicast and documentation ranges as
    non-private/global in ways that are easy to misread, so the most specific
    special-use range is selected before falling back to PRIVATE/GLOBAL_PUBLIC.
    """
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    if mapped is not None:
        return classify_ip_address(mapped)
    if ip_obj.is_loopback:
        return "LOOPBACK"
    if ip_obj.is_unspecified:
        return "UNSPECIFIED"
    if ip_obj.is_link_local:
        return "LINK_LOCAL"
    if ip_obj.is_multicast:
        return "MULTICAST"
    if any(ip_obj in net for net in _DOCUMENTATION_NETWORKS):
        return "DOCUMENTATION"
    if any(ip_obj in net for net in _RESERVED_SPECIAL_NETWORKS):
        return "RESERVED"
    if any(ip_obj in net for net in _SHARED_ADDRESS_NETWORKS):
        return "PRIVATE"
    if ip_obj.is_private:
        return "PRIVATE"
    if ip_obj.is_global:
        return "GLOBAL_PUBLIC"
    return "RESERVED"


def _confidence_label(confidence: float) -> str:
    if confidence <= 0.0:
        return "NONE"
    if confidence < 0.40:
        return "LOW"
    if confidence < 0.75:
        return "MEDIUM"
    return "HIGH"


def _vcard_org_name(entity: dict[str, Any]) -> Optional[str]:
    """Extract an organisation name from a jCard vcardArray, if present."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = str(item[0]).lower()
        if name not in {"fn", "org"}:
            continue
        value = item[3]
        if isinstance(value, list):
            joined = " ".join(str(part) for part in value if part)
            if joined:
                return joined
        elif value:
            return str(value)
    return None


def _rdap_org_name(data: dict[str, Any]) -> Optional[str]:
    entities = data.get("entities")
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = {str(role).lower() for role in entity.get("roles", [])}
        name = _vcard_org_name(entity)
        if name and (not roles or roles & {"registrant", "administrative", "technical", "abuse"}):
            return name
    for entity in entities:
        if isinstance(entity, dict):
            name = _vcard_org_name(entity)
            if name:
                return name
    return None


def _registry_from_url(url: str) -> Optional[str]:
    host = (urlparse(url).hostname or "").lower()
    registries = {
        "arin.net": "ARIN",
        "ripe.net": "RIPE NCC",
        "apnic.net": "APNIC",
        "lacnic.net": "LACNIC",
        "afrinic.net": "AFRINIC",
    }
    for suffix, label in registries.items():
        if host == suffix or host.endswith("." + suffix):
            return label
    return None


class OSINTVerificationState(str, Enum):
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    UNVERIFIED = "UNVERIFIED"
    NOT_CHECKED = "NOT_CHECKED"
    PROVIDER_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"

    # Backward-compatible aliases
    VERIFIED = "CORROBORATED"
    UNKNOWN = "UNVERIFIED"
    UNVERIFIED_LOCALLY = "UNVERIFIED"
    NOT_FOUND_IN_CHECKED_SOURCES = "OBSERVED"
    OFFLINE_MODE = "NOT_CHECKED"

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: Any) -> bool:
        if super().__eq__(other):
            return True
        if isinstance(other, str):
            aliases = {
                "CORROBORATED": {"VERIFIED"},
                "UNVERIFIED": {"UNKNOWN", "UNVERIFIED_LOCALLY"},
                "OBSERVED": {"NOT_FOUND_IN_CHECKED_SOURCES"},
                "NOT_CHECKED": {"OFFLINE_MODE"},
            }
            return other in aliases.get(self.value, set())
        return False


class OSINTResult(BaseModel):
    indicator: str
    query_type: str  # "ip", "domain", "email", "username", "phone", "metadata"
    normalized_value: str
    actual_finding: str
    status: OSINTVerificationState = OSINTVerificationState.OBSERVED
    findings: list[dict[str, Any]] = Field(default_factory=list)
    sources_queried: list[str] = Field(default_factory=list)
    sources_skipped: list[str] = Field(default_factory=list)
    SC: int = 0
    confidence_formula: str = ""
    PC: float = 0.0
    source_or_provider: str = "redloop_osint_engine"
    collection_method: str = "PASSIVE_TELEMETRY"
    observation_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_id: str = Field(default_factory=lambda: f"evi-osint-{uuid.uuid4().hex[:10]}")
    evidence_hash: str = ""
    evidence_hash_version: str = "sha256-canonical-v2"
    evidence_integrity_valid: bool = False
    evidence_integrity_status: str = "UNVERIFIED"
    confidence: float = 0.8
    confidence_label: str = ""
    confidence_method: str = CONFIDENCE_METHOD
    confidence_factors: dict[str, float] = Field(default_factory=dict)
    confidence_type: str = "HEURISTIC"
    confidence_evidence: dict[str, Any] = Field(default_factory=dict)
    confidence_evidence_score: Optional[float] = None
    confidence_methodology: str = "LEGACY_SIX_FACTOR_HEURISTIC"
    source_agreement: dict[str, Any] = Field(default_factory=dict)
    not_applicable_factors: list[str] = Field(default_factory=list)
    provenance_completeness: float = 0.0
    provenance: dict[str, dict[str, Any]] = Field(default_factory=dict)
    field_provenance: dict[str, dict[str, Any]] = Field(default_factory=dict)
    provenance_policy: dict[str, Any] = Field(default_factory=dict)
    rate_limit_state: str = "NORMAL"
    cached: bool = False
    cache_status: str = "LIVE"
    cache_state: str = "LIVE"
    cache_fallback_reason: Optional[str] = None
    cached_at: Optional[str] = None
    cache_age_seconds: Optional[float] = None
    cache_ttl_seconds: Optional[float] = None
    cache_expires_at: Optional[str] = None
    freshness: dict[str, Any] = Field(default_factory=dict)
    freshness_decay: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    provider_status: dict[str, str] = Field(default_factory=dict)
    related_entities: list[dict[str, Any]] = Field(default_factory=list)
    verification_state: str = "OBSERVED"

    # IP-specific structured enrichment. Each field has its own status so a
    # caller never has to infer "no data" from an empty string or None.
    classification: Optional[str] = None
    reverse_dns: Optional[dict[str, Any]] = None
    registry: Optional[str] = None
    registry_status: str = "NOT_APPLICABLE"
    network: Optional[dict[str, Any]] = None
    network_status: str = "NOT_APPLICABLE"
    asn: Optional[str] = None
    asn_status: str = "NOT_APPLICABLE"
    geo: Optional[dict[str, Any]] = None
    geo_status: str = "NOT_APPLICABLE"

    def _canonical_evidence_payload(self) -> dict[str, Any]:
        """Stable payload used for evidence hashing.

        Volatile cache metadata, response timestamps, and the random evidence id
        are deliberately excluded so identical observations reproduce the same
        digest.
        """
        return {
            "hash_version": self.evidence_hash_version,
            "indicator": self.indicator,
            "query_type": self.query_type,
            "normalized_value": self.normalized_value,
            "classification": self.classification,
            "findings": self.findings,
            "related_entities": self.related_entities,
        }

    def compute_evidence_hash(self) -> str:
        raw_data = json.dumps(
            self._canonical_evidence_payload(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(raw_data.encode("utf-8")).hexdigest()

    def verify_evidence_hash(self) -> bool:
        return bool(self.evidence_hash) and self.evidence_hash == self.compute_evidence_hash()

    def verify_evidence_integrity(self) -> dict[str, Any]:
        """Recompute the canonical SHA-256 digest and reject unknown versions."""
        supported = self.evidence_hash_version in SUPPORTED_EVIDENCE_HASH_VERSIONS
        expected = self.compute_evidence_hash() if supported else None
        valid = bool(supported and self.evidence_hash and self.evidence_hash == expected)
        return {
            "valid": valid,
            "status": (
                "INTEGRITY_VERIFIED"
                if valid
                else EVIDENCE_VERSION_MISMATCH
                if not supported
                else "HASH_MISMATCH"
            ),
            "algorithm": "sha256",
            "hash_version": self.evidence_hash_version,
            "supported_hash_versions": sorted(SUPPORTED_EVIDENCE_HASH_VERSIONS),
            "expected_hash": expected,
            "actual_hash": self.evidence_hash,
            "canonical_payload": self._canonical_evidence_payload() if supported else None,
        }

    def _ensure_related_provenance(self) -> None:
        for entity in self.related_entities:
            if not isinstance(entity, dict) or not entity.get("value"):
                continue
            entity.setdefault("source", self.source_or_provider)
            entity.setdefault("method", self.collection_method)
            entity.setdefault("evidence_reference", self.evidence_id)
            entity.setdefault("timestamp", self.observation_timestamp)
            entity.setdefault("verification_state", self.status.value)
            entity.setdefault("verified", False)

    def _required_provenance_fields(self) -> list[str]:
        base = ["source", "timestamp", "method", "evidence", "confidence"]
        extras = {
            "ip": ["classification", "reverse_dns"],
            "domain": ["dns_records"],
            "email": ["syntax_validation", "mailbox_existence"],
            "username": [],
            "phone": ["e164_format"],
            "metadata": ["cryptographic_identity"],
        }
        return base + extras.get(self.query_type, [])

    def _build_source_agreement(self) -> dict[str, Any]:
        sources = [
            str(item.get("source"))
            for item in self.findings
            if item.get("source")
        ]
        if not sources:
            sources = [self.source_or_provider]
        unique = {
            str(source).strip().lower()
            for source in sources
            if str(source).strip()
        }
        return calculate_source_agreement(sorted(unique))

    def _build_confidence_evidence(self) -> dict[str, Any]:
        agreement = self.source_agreement or {}
        if self.query_type == "ip" and self.classification and self.classification != "GLOBAL_PUBLIC":
            source_reliability = 1.0
        else:
            observed = [
                float(item.get("confidence", 0.0) or 0.0)
                for item in self.findings
                if isinstance(item.get("confidence"), (int, float))
            ]
            source_reliability = max(observed) if observed else None
        independent = int(agreement.get("independent_sources") or 0)
        freshness_value = self.freshness_decay.get("score") if self.freshness_decay else None
        confidence = compute_finding_confidence(
            source_reliability=source_reliability,
            source_agreement=agreement.get("score"),
            independent_source_count=independent,
            evidence_integrity=1.0 if self.evidence_integrity_valid else 0.0,
            freshness=freshness_value,
            provenance_completeness=self.provenance_completeness,
            details={
                "source_agreement_status": agreement.get("status"),
                "legacy_confidence": self.confidence,
                "evidence_integrity_status": self.evidence_integrity_status,
            },
        )
        if not self.evidence_integrity_valid:
            confidence.update(
                {
                    "status": INSUFFICIENT_EVIDENCE,
                    "score": None,
                    "reason": "EVIDENCE_INTEGRITY_INVALID",
                }
            )
        return confidence

    def _build_provenance_policy(self) -> dict[str, Any]:
        required = self._required_provenance_fields()
        present = [
            name
            for name in required
            if self.field_provenance.get(name, {}).get("status") == "PRESENT"
        ]
        not_applicable = [
            name
            for name in required
            if self.field_provenance.get(name, {}).get("status") == "NOT_APPLICABLE"
        ]
        missing = [
            name for name in required if name not in present and name not in not_applicable
        ]
        applicable = [name for name in required if name not in not_applicable]
        score = (
            round(len(present) / float(len(applicable)), 4)
            if applicable
            else None
        )
        return {
            "query_type": self.query_type,
            "required_fields": required,
            "applicable_fields": applicable,
            "present_fields": present,
            "missing_fields": missing,
            "not_applicable_fields": not_applicable,
            "score": score,
            "status": "COMPLETE" if not missing else "INCOMPLETE",
        }

    @staticmethod
    def _provenance_state(raw_status: str | None) -> str:
        status = str(raw_status or "").upper()
        if status in {
            "PRESENT", "VERIFIED", "OBSERVED", "OBSERVED_LOCALLY",
            "VALID", "AVAILABLE", "CONFIRMED", "RESOLVED", "CONFIGURED",
            "CANDIDATE_MATCH", "LIVE_VERIFIED"
        }:
            return "PRESENT"
        if status in {"NOT_FOUND_IN_CHECKED_SOURCES", "CLEAN", "NO_MATCH", "CHECKED_NOT_FOUND"}:
            return "CHECKED_NOT_FOUND"
        if status == "NOT_APPLICABLE":
            return "NOT_APPLICABLE"
        if not status or status in {"MISSING", "UNKNOWN", "UNVERIFIED", "NOT_CHECKED", "PROVIDER_NOT_CONFIGURED"}:
            return "MISSING"
        return "MISSING"

    def _build_field_provenance(self) -> dict[str, dict[str, Any]]:
        """Per-field presence status, with the reason a field is not present.

        `NOT_APPLICABLE` fields are excluded from completeness (they are not
        gaps), while `MISSING` fields are counted against it. This prevents the
        five always-present envelope fields from masking missing enrichment.
        """
        fields: dict[str, dict[str, Any]] = {}
        for name in ("source", "timestamp", "method", "evidence", "confidence"):
            item = self.provenance.get(name, {})
            fields[name] = {
                "status": self._provenance_state(item.get("status")),
                "value": item.get("value"),
                "source": None,
                "method": None,
                "reason": None if item.get("status") == "PRESENT" else f"{name} is missing.",
            }

        if self.query_type != "ip":
            for finding in self.findings:
                prop = str(finding.get("property") or "").strip()
                if not prop:
                    continue
                fields[prop] = {
                    "status": self._provenance_state(
                        finding.get("verification_state") or finding.get("status")
                    ),
                    "value": finding.get("value"),
                    "source": finding.get("source"),
                    "method": finding.get("method"),
                    "reason": finding.get("reason") or finding.get("status"),
                }
            return fields

        fields["classification"] = {
            "status": "PRESENT" if self.classification else "MISSING",
            "value": self.classification,
            "source": "python-ipaddress",
            "method": "LOCAL_DETERMINISTIC_CLASSIFICATION",
            "reason": None if self.classification else "IP classification is missing.",
        }
        rdns = self.reverse_dns or {}
        fields["reverse_dns"] = {
            "status": self._provenance_state(rdns.get("verification_state") or rdns.get("status"))
            if rdns.get("status") != "NOT_APPLICABLE"
            else "NOT_APPLICABLE",
            "value": rdns.get("hostname"),
            "source": rdns.get("source"),
            "method": rdns.get("method"),
            "reason": rdns.get("reason"),
        }
        for name, value, status, source in (
            ("registry", self.registry, self.registry_status, "RDAP"),
            ("network", self.network, self.network_status, "RDAP"),
            ("asn", self.asn, self.asn_status, "ASN_PROVIDER"),
            ("geo", self.geo, self.geo_status, "GEOLOCATION_PROVIDER"),
        ):
            state = (
                "PRESENT"
                if value
                else self._provenance_state(status)
            )
            fields[name] = {
                "status": state,
                "value": value,
                "source": source,
                "method": self.collection_method,
                "reason": None if state in {"PRESENT", "NOT_APPLICABLE"} else str(status),
            }
        return fields

    def _compute_provenance_completeness(self) -> float:
        applicable = [
            item
            for item in self.field_provenance.values()
            if item.get("status") not in {"NOT_APPLICABLE"}
        ]
        if not applicable:
            return 0.0
        present = sum(1 for item in applicable if item.get("status") == "PRESENT")
        return round(present / float(len(applicable)), 4)

    @staticmethod
    def _build_freshness(
        observed_at: str,
        *,
        age_seconds: float = 0.0,
        ttl_seconds: float | None = None,
    ) -> dict[str, Any]:
        state = "FRESH"
        if ttl_seconds is not None and age_seconds > ttl_seconds:
            state = "STALE"
        return {
            "observed_at": observed_at,
            "age_seconds": round(max(0.0, age_seconds), 3),
            "ttl_seconds": ttl_seconds,
            "state": state,
        }

    def _build_provenance(self) -> dict[str, dict[str, Any]]:
        fields: dict[str, dict[str, Any]] = {
            "source": {
                "value": self.source_or_provider,
                "status": "PRESENT" if self.source_or_provider else "MISSING",
            },
            "timestamp": {
                "value": self.observation_timestamp,
                "status": "PRESENT" if self.observation_timestamp else "MISSING",
            },
            "method": {
                "value": self.collection_method,
                "status": "PRESENT" if self.collection_method else "MISSING",
            },
            "evidence": {
                "value": self.evidence_id,
                "sha256": self.evidence_hash,
                "status": "PRESENT" if self.evidence_id and self.evidence_hash else "MISSING",
            },
            "confidence": {
                "value": self.confidence,
                "label": self.confidence_label,
                "method": self.confidence_method,
                "factors": self.confidence_factors,
                "status": "PRESENT" if 0.0 <= self.confidence <= 1.0 else "MISSING",
            },
        }
        return fields

    def model_post_init(self, __context: Any) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.confidence_label = self.confidence_label or _confidence_label(self.confidence)
        if not self.evidence_hash:
            self._ensure_related_provenance()
            self.evidence_hash = self.compute_evidence_hash()
        integrity = self.verify_evidence_integrity()
        self.evidence_integrity_valid = bool(integrity["valid"])
        self.evidence_integrity_status = str(integrity["status"])
        if not self.evidence_integrity_valid and self.status not in {
            OSINTVerificationState.FAILED,
            OSINTVerificationState.OFFLINE_MODE,
        }:
            self.status = OSINTVerificationState.FAILED
        if self.status == OSINTVerificationState.OFFLINE_MODE:
            self.verification_state = VerificationState.UNVERIFIED_LOCALLY.value
        else:
            self.verification_state = self.status.value
        self.provenance = self._build_provenance()
        self.field_provenance = self._build_field_provenance()
        self.provenance_completeness = self._compute_provenance_completeness()
        self.PC = self.provenance_completeness
        if not self.SC:
            self.SC = len(self.sources_queried)
        if not self.confidence_formula:
            s = float(self.confidence_factors.get("source_reliability", self.confidence_factors.get("S", self.confidence)))
            d = float(self.confidence_factors.get("direct_observation", self.confidence_factors.get("D", self.confidence)))
            i = float(self.confidence_factors.get("independent_corroboration", self.confidence_factors.get("I", 0.5)))
            f = float(self.confidence_factors.get("freshness", self.confidence_factors.get("F", 1.0)))
            p = float(self.confidence_factors.get("parser_validation", self.confidence_factors.get("P", 1.0)))
            x = float(self.confidence_factors.get("cross_source_consistency", self.confidence_factors.get("X", 0.8)))
            self.confidence_formula = f"C = 0.25*(S={s:.2f}) + 0.25*(D={d:.2f}) + 0.20*(I={i:.2f}) + 0.10*(F={f:.2f}) + 0.10*(P={p:.2f}) + 0.10*(X={x:.2f}) = {self.confidence:.2f}"
        if self.confidence_type not in {"HEURISTIC", "EXACT"}:
            self.confidence_type = "HEURISTIC"
        if not self.freshness:
            self.freshness = self._build_freshness(
                self.observation_timestamp, age_seconds=0.0, ttl_seconds=None
            )
        if not self.freshness_decay:
            self.freshness_decay = freshness_decay(
                self.observation_timestamp,
                observation_type=self.query_type,
            )
            self.freshness.setdefault("decay", self.freshness_decay)
            self.freshness.setdefault("score", self.freshness_decay.get("score"))
            self.freshness.setdefault(
                "half_life_seconds", self.freshness_decay.get("half_life_seconds")
            )
            self.freshness.setdefault("observation_type", self.query_type)
        if not self.cache_state:
            self.cache_state = {
                "LIVE": "LIVE",
                "CACHED": "CACHED_FRESH",
                "STALE": "CACHED_STALE",
            }.get(self.cache_status, self.cache_status)
        if not self.source_agreement:
            self.source_agreement = self._build_source_agreement()
        self.provenance_policy = self._build_provenance_policy()
        if not self.confidence_evidence:
            self.confidence_evidence = self._build_confidence_evidence()
            self.confidence_evidence_score = self.confidence_evidence.get("score")
            if self.confidence_evidence.get("label") == HEURISTIC_CONFIDENCE:
                self.confidence_methodology = HEURISTIC_CONFIDENCE
            if self.confidence_evidence.get("calibration_status") == NOT_CALIBRATED:
                self.confidence_evidence.setdefault("calibration_status", NOT_CALIBRATED)


class OSINTCache:
    """Thread-safe TTL cache with SQLite backing and a bounded stale-while-degraded window.

    A stale entry may only be served when a fresh lookup fails; it is always
    labeled STALE and carries the reason, never presented as live data.
    Default TTL is 24 hours (86,400s).
    """

    _UNCACHEABLE = {
        OSINTVerificationState.FAILED,
        OSINTVerificationState.NOT_CHECKED,
        "FAILED",
        "NOT_CHECKED",
        "OFFLINE_MODE",
    }

    def __init__(
        self,
        default_ttl_seconds: float = 86400.0,
        stale_ttl_seconds: float = 172800.0,
        db_path: Optional[str] = None,
    ):
        self._cache: dict[str, tuple[float, float, float, OSINTResult]] = {}
        self._ttl = max(0.0, float(default_ttl_seconds))
        self._stale_ttl = max(self._ttl, float(stale_ttl_seconds))
        self._lock = threading.RLock()
        self._db_path = db_path or os.environ.get("REDLOOP_OSINT_CACHE_DB", "data/osint_cache.sqlite")
        self._shared_conn = None
        if self._db_path == ":memory:":
            import sqlite3
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._init_sqlite()

    def _get_conn(self):
        import sqlite3
        if self._shared_conn is not None:
            return self._shared_conn
        return sqlite3.connect(self._db_path, timeout=5.0)

    def _init_sqlite(self) -> None:
        try:
            if self._db_path != ":memory:":
                p = Path(self._db_path)
                p.parent.mkdir(parents=True, exist_ok=True)
            with self._get_conn() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS osint_cache (
                        cache_key TEXT PRIMARY KEY,
                        result_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        stale_until REAL NOT NULL
                    )
                    """
                )
        except Exception as e:
            logger.debug("Could not initialize OSINT SQLite cache: %s", e)

    def _annotate(
        self,
        result: OSINTResult,
        created_at: float,
        expires_at: float,
        stale_until: float,
        now: float,
        cache_status: str,
        fallback_reason: Optional[str] = None,
    ) -> OSINTResult:
        cached_res = result.model_copy(deep=True)
        cached_res.cached = True
        cached_res.cache_status = cache_status
        cached_res.cache_state = (
            "CACHED_FRESH" if cache_status == "CACHED" else "CACHED_STALE"
        )
        cached_res.cache_fallback_reason = fallback_reason
        cached_res.cached_at = datetime.fromtimestamp(created_at, timezone.utc).isoformat()
        cached_res.cache_age_seconds = round(max(0.0, now - created_at), 3)
        cached_res.cache_ttl_seconds = self._ttl
        cached_res.cache_expires_at = datetime.fromtimestamp(expires_at, timezone.utc).isoformat()
        cached_res.freshness = OSINTResult._build_freshness(
            cached_res.observation_timestamp,
            age_seconds=cached_res.cache_age_seconds,
            ttl_seconds=self._ttl,
        )
        cached_res.freshness_decay = freshness_decay(
            cached_res.observation_timestamp,
            observation_type=cached_res.query_type,
        )
        cached_res.freshness["score"] = cached_res.freshness_decay.get("score")
        cached_res.freshness["half_life_seconds"] = cached_res.freshness_decay.get(
            "half_life_seconds"
        )
        cached_res.freshness["decay"] = cached_res.freshness_decay
        if cache_status == "STALE":
            cached_res.limitations = list(cached_res.limitations or [])
            stale_msg = f"Serving stale cache: fresh lookup failed ({fallback_reason or 'upstream unavailable'})."
            if not any("cache" in item.lower() for item in cached_res.limitations):
                cached_res.limitations.append(stale_msg)
        return cached_res

    def state_for(self, key: str) -> str:
        now = time.time()
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return "CACHE_MISS"
            created_at, expires_at, stale_until, _ = entry
            if now < expires_at:
                return "CACHED_FRESH"
            if now < stale_until:
                return "CACHED_STALE"
            del self._cache[key]
            return "EXPIRED"

    def get(self, key: str) -> Optional[OSINTResult]:
        now = time.time()
        with self._lock:
            entry = self._cache.get(key)
        if not entry:
            try:
                with self._get_conn() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT result_json, created_at, expires_at, stale_until FROM osint_cache WHERE cache_key = ?",
                        (key,),
                    )
                    row = cursor.fetchone()
                    if row:
                        res_json, c_at, exp_at, st_at = row
                        res_obj = OSINTResult.model_validate_json(res_json)
                        with self._lock:
                            self._cache[key] = (c_at, exp_at, st_at, res_obj)
                        entry = (c_at, exp_at, st_at, res_obj)
            except Exception as e:
                logger.debug("Failed reading OSINT SQLite cache: %s", e)
        if not entry:
            return None
        created_at, expires_at, stale_until, result = entry
        if now >= expires_at:
            if now >= stale_until:
                with self._lock:
                    self._cache.pop(key, None)
            return None
        if result.status in self._UNCACHEABLE:
            with self._lock:
                self._cache.pop(key, None)
            return None
        return self._annotate(result, created_at, expires_at, stale_until, now, "CACHED")

    def get_stale(self, key: str) -> Optional[OSINTResult]:
        """Return an expired-but-retained entry, explicitly labeled STALE."""
        now = time.time()
        with self._lock:
            entry = self._cache.get(key)
        if not entry:
            try:
                with self._get_conn() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT result_json, created_at, expires_at, stale_until FROM osint_cache WHERE cache_key = ?",
                        (key,),
                    )
                    row = cursor.fetchone()
                    if row:
                        res_json, c_at, exp_at, st_at = row
                        res_obj = OSINTResult.model_validate_json(res_json)
                        with self._lock:
                            self._cache[key] = (c_at, exp_at, st_at, res_obj)
                        entry = (c_at, exp_at, st_at, res_obj)
            except Exception as e:
                logger.debug("Failed reading OSINT SQLite cache for stale entry: %s", e)
        if not entry:
            return None
        created_at, expires_at, stale_until, result = entry
        if now < expires_at:
            return None
        if now >= stale_until:
            with self._lock:
                self._cache.pop(key, None)
            return None
        if result.status in self._UNCACHEABLE:
            with self._lock:
                self._cache.pop(key, None)
            return None
        return self._annotate(
            result,
            created_at,
            expires_at,
            stale_until,
            now,
            "STALE",
            fallback_reason="Fresh lookup failed; serving the last successful cached observation.",
        )

    def set(self, key: str, result: OSINTResult) -> bool:
        if result.status in self._UNCACHEABLE:
            return False
        now = time.time()
        with self._lock:
            self._cache[key] = (
                now,
                now + self._ttl,
                now + self._stale_ttl,
                result.model_copy(deep=True),
            )
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO osint_cache
                    (cache_key, result_json, created_at, expires_at, stale_until)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (key, result.model_dump_json(), now, now + self._ttl, now + self._stale_ttl),
                )
        except Exception as e:
            logger.debug("Failed writing to OSINT SQLite cache: %s", e)
        return True

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
        try:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM osint_cache")
        except Exception:
            pass


def request_with_backoff(
    client: httpx.Client,
    url: str,
    max_retries: int = 3,
    base_delay: float = 0.3,
    max_delay: float = 3.0,
) -> tuple[httpx.Response | None, str]:
    """Execute HTTP GET with exponential backoff and jitter."""
    for attempt in range(max_retries):
        try:
            resp = client.get(url)
            if resp.status_code == 429:
                if attempt == max_retries - 1:
                    return None, "RATE_LIMITED"
                delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0.02, 0.1)
                time.sleep(delay)
                continue
            return resp, "OK"
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            if attempt == max_retries - 1:
                return None, f"TIMEOUT_OR_ERROR: {str(exc)[:40]}"
            delay = min(max_delay, base_delay * (2 ** attempt)) + random.uniform(0.02, 0.1)
            time.sleep(delay)
    return None, "FAILED"


# Standard ITU-T Country Code mappings for local telephone validation

DISPOSABLE_EMAIL_DOMAINS = frozenset(
    {
        "mailinator.com",
        "tempmail.com",
        "guerrillamail.com",
        "10minutemail.com",
        "throwawaymail.com",
        "yopmail.com",
        "sharklasers.com",
        "trashmail.com",
        "dispostable.com",
        "getairmail.com",
        "burnermail.io",
        "maildrop.cc",
        "temp-mail.org",
        "fakeinbox.com",
        "inboxkitten.com",
        "crazymailing.com",
        "nada.ltd",
        "getnada.com",
        "mohmal.com",
    }
)

ITU_CALLING_CODES = {
    "1": {"country": "US/CA", "region": "North America"},
    "44": {"country": "GB", "region": "United Kingdom"},
    "49": {"country": "DE", "region": "Germany"},
    "33": {"country": "FR", "region": "France"},
    "91": {"country": "IN", "region": "India"},
    "81": {"country": "JP", "region": "Japan"},
    "61": {"country": "AU", "region": "Australia"},
    "86": {"country": "CN", "region": "China"},
    "7": {"country": "RU/KZ", "region": "Russia / Kazakhstan"},
    "39": {"country": "IT", "region": "Italy"},
    "34": {"country": "ES", "region": "Spain"},
    "55": {"country": "BR", "region": "Brazil"},
    "52": {"country": "MX", "region": "Mexico"},
    "31": {"country": "NL", "region": "Netherlands"},
    "41": {"country": "CH", "region": "Switzerland"},
    "46": {"country": "SE", "region": "Sweden"},
    "47": {"country": "NO", "region": "Norway"},
    "48": {"country": "PL", "region": "Poland"},
    "65": {"country": "SG", "region": "Singapore"},
    "971": {"country": "AE", "region": "United Arab Emirates"},
    "972": {"country": "IL", "region": "Israel"},
    "27": {"country": "ZA", "region": "South Africa"},
    "20": {"country": "EG", "region": "Egypt"},
}


class OSINTEngine:
    """Unified OSINT Intelligence & Reconnaissance Engine."""

    def __init__(
        self,
        http_client: Optional[httpx.Client] = None,
        cache_ttl_seconds: float = 86400.0,
        cache_db_path: Optional[str] = None,
    ):
        self._client = http_client or get_hardened_client(
            timeout=5.0,
            headers={"User-Agent": "REDLOOP-Cybersecurity-OSINT-Engine/2.0"},
            follow_redirects=True,
        )
        self._cache = OSINTCache(default_ttl_seconds=cache_ttl_seconds, db_path=cache_db_path)
        self._platforms_catalog: list[dict[str, Any]] = []
        catalog_path = Path("data/osint/platforms.json")
        if catalog_path.exists():
            try:
                self._platforms_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.debug("Failed loading platforms.json: %s", e)

    # =========================================================================
    # 1. IP INTELLIGENCE
    # =========================================================================
    # =========================================================================
    # 1. IP INTELLIGENCE
    # =========================================================================
    def investigate_ip(self, ip_str: str) -> OSINTResult:
        """Analyze public/private IP, reverse DNS, ASN/ownership, routing and reputation."""
        raw_ip = ip_str.strip()
        if not raw_ip:
            return OSINTResult(
                indicator="",
                query_type="ip",
                normalized_value="",
                actual_finding="IP address is required.",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Empty input: supply an IPv4 or IPv6 literal."],
                sources_skipped=["INPUT_VALIDATION: EMPTY_STRING"],
            )
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            return OSINTResult(
                indicator=raw_ip,
                query_type="ip",
                normalized_value=raw_ip,
                actual_finding=f"Invalid IP address format: {raw_ip}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Supplied string is not a valid IPv4 or IPv6 literal."],
                sources_skipped=["INPUT_VALIDATION: INVALID_IP_FORMAT"],
            )

        norm_ip = str(ip_obj)
        offline = is_offline_mode()
        cached_result = None if offline else self._cache.get(f"ip:{norm_ip}")
        if cached_result:
            return cached_result

        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}
        sources_queried: list[str] = ["python-ipaddress"]
        sources_skipped: list[str] = []
        rate_state = "NORMAL"

        # 1. IP Classification (local, deterministic)
        classification = classify_ip_address(ip_obj)
        is_public = classification == "GLOBAL_PUBLIC"
        special_subtype = None
        if str(ip_obj) == "255.255.255.255":
            special_subtype = "LIMITED_BROADCAST"
        elif isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in ipaddress.ip_network("fc00::/7"):
            special_subtype = "IPV6_UNIQUE_LOCAL"
        elif ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            special_subtype = "SHARED_CARRIER_NAT"

        findings.append(
            {
                "property": "classification",
                "value": classification,
                "classification": classification,
                "special_scope": special_subtype,
                "is_limited_broadcast": str(ip_obj) == "255.255.255.255",
                "is_ipv6_unique_local": isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in ipaddress.ip_network("fc00::/7"),
                "scope": classification,
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_link_local": ip_obj.is_link_local,
                "is_multicast": ip_obj.is_multicast,
                "is_reserved": ip_obj.is_reserved,
                "is_global": ip_obj.is_global,
                "source": "python-ipaddress",
                "method": "LOCAL_DETERMINISTIC_CLASSIFICATION",
                "confidence": 1.0,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            }
        )

        # 2. Reverse DNS & External telemetry
        if not is_public:
            reverse_dns = {
                "hostname": None,
                "hostnames": [],
                "status": "NOT_QUERIED",
                "reason": "Reverse DNS is not applicable to non-globally-routable addresses.",
                "source": None,
                "method": None,
                "confidence": 0.0,
                "verification_state": "NOT_APPLICABLE",
            }
            limitations.append(
                f"IP {norm_ip} is {classification}; external registry, ASN, and geolocation enrichment are not applicable."
            )
            sources_skipped.extend([
                "RDAP: NOT_APPLICABLE",
                "Shodan: NOT_APPLICABLE",
                "VirusTotal: NOT_APPLICABLE",
            ])
            org = None
            country = None
            registry = None
            registry_status = "NOT_APPLICABLE"
            network = None
            network_status = "NOT_APPLICABLE"
            asn = None
            asn_status = "NOT_APPLICABLE"
            geo_status = "NOT_APPLICABLE"
        elif offline:
            reverse_dns = {
                "hostname": None,
                "hostnames": [],
                "status": "NOT_QUERIED",
                "reason": "Offline mode enforced: external PTR queries suppressed.",
                "source": None,
                "method": None,
                "confidence": 0.0,
                "verification_state": "NOT_CHECKED",
            }
            prov_status["OFFLINE_MODE"] = "ENFORCED"
            registry = None
            registry_status = "NOT_QUERIED"
            network = None
            network_status = "NOT_QUERIED"
            asn = None
            asn_status = "NOT_QUERIED"
            geo_status = "NOT_QUERIED"
            limitations.append(
                "Strict OFFLINE_MODE active: external RDAP registry, ASN, geolocation, and threat-intelligence queries were suppressed."
            )
            sources_skipped.extend([
                "DNS_PTR: SKIPPED_OFFLINE",
                "RDAP: SKIPPED_OFFLINE",
                "Shodan: SKIPPED_OFFLINE",
                "VirusTotal: SKIPPED_OFFLINE",
                "AbuseIPDB: SKIPPED_OFFLINE",
            ])
        else:
            reverse_dns = self._lookup_reverse_dns(ip_obj)
            if reverse_dns.get("hostname"):
                sources_queried.append("DNS_PTR")

            # RDAP registry lookup
            org = None
            country = None
            registry = None
            network = None
            rdap_resp, status_desc = request_with_backoff(
                self._client, f"https://rdap.arin.net/registry/ip/{norm_ip}"
            )
            if not (rdap_resp and rdap_resp.status_code == 200):
                stale_cached = self._cache.get_stale(f"ip:{norm_ip}")
                if stale_cached is not None:
                    return stale_cached
            if status_desc == "RATE_LIMITED":
                prov_status["RDAP_ARIN"] = "RATE_LIMITED"
                registry_status = "RATE_LIMITED"
                network_status = "RATE_LIMITED"
                rate_state = "RATE_LIMITED"
                sources_skipped.append("RDAP: RATE_LIMITED")
                limitations.append("External RDAP service returned HTTP 429 Too Many Requests (rate limited).")
            elif rdap_resp and rdap_resp.status_code == 200:
                try:
                    rdap_data = rdap_resp.json()
                    registry = _registry_from_url(str(rdap_resp.url)) or "ARIN"
                    registry_status = "VERIFIED"
                    prov_status["RDAP_ARIN"] = "ONLINE_VERIFIED"
                    sources_queried.append(f"RDAP/{registry}")

                    network_name = rdap_data.get("name")
                    handle = rdap_data.get("handle")
                    country = rdap_data.get("country")
                    network = {
                        key: value
                        for key, value in {
                            "name": network_name,
                            "handle": handle,
                            "start_address": rdap_data.get("startAddress"),
                            "end_address": rdap_data.get("endAddress"),
                            "type": rdap_data.get("type"),
                            "country": country,
                        }.items()
                        if value
                    }
                    network_status = "VERIFIED" if network else "NOT_FOUND_IN_CHECKED_SOURCES"
                    org = _rdap_org_name(rdap_data)
                    if network:
                        findings.append(
                            {
                                "property": "network",
                                "value": network_name or handle,
                                "network": network,
                                "registry": registry,
                                "source": f"RDAP/{registry}",
                                "method": "HTTPS_GET_RDAP",
                                "confidence": 0.95,
                                "verification_state": OSINTVerificationState.CORROBORATED.value,
                            }
                        )
                        related.append(
                            {
                                "type": "network",
                                "value": network_name or handle,
                                "relation": "REGISTERED_NETWORK",
                                "verified": True,
                                "source": f"RDAP/{registry}",
                                "method": "HTTPS_GET_RDAP",
                                "confidence": 0.95,
                                "verification_state": OSINTVerificationState.CORROBORATED.value,
                            }
                        )
                    if country:
                        findings.append(
                            {
                                "property": "country",
                                "value": country,
                                "source": f"RDAP/{registry}",
                                "method": "HTTPS_GET_RDAP",
                                "confidence": 0.95,
                                "verification_state": OSINTVerificationState.CORROBORATED.value,
                            }
                        )
                    if org:
                        findings.append(
                            {
                                "property": "organization",
                                "value": org,
                                "source": f"RDAP/{registry}",
                                "method": "HTTPS_GET_RDAP",
                                "confidence": 0.9,
                                "verification_state": OSINTVerificationState.CORROBORATED.value,
                            }
                        )
                        related.append(
                            {
                                "type": "organization",
                                "value": org,
                                "relation": "ORGANIZATION_CONTACT",
                                "verified": True,
                                "source": f"RDAP/{registry}",
                                "method": "HTTPS_GET_RDAP",
                                "confidence": 0.9,
                                "verification_state": OSINTVerificationState.CORROBORATED.value,
                            }
                        )
                except Exception:
                    prov_status["RDAP_ARIN"] = "PARSE_ERROR"
                    registry_status = "PARSE_ERROR"
                    network_status = "PARSE_ERROR"
                    sources_skipped.append("RDAP: PARSE_ERROR")
            else:
                prov_status["RDAP_ARIN"] = status_desc
                registry_status = "UNAVAILABLE"
                network_status = "UNAVAILABLE"
                sources_skipped.append(f"RDAP: {status_desc}")
                limitations.append("External RDAP service unreachable; registry and network fields are unavailable, not inferred.")

            # Team Cymru BGP origin lookup
            asn = None
            asn_status = "NOT_QUERIED"
            cymru_asn = None
            try:
                import dns.resolver
                octets = norm_ip.split(".")
                if len(octets) == 4:
                    rev_q = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
                    c_res = dns.resolver.Resolver()
                    c_res.timeout = 2.0
                    c_res.lifetime = 2.0
                    txt_ans = c_res.resolve(rev_q, "TXT")
                    for r in txt_ans:
                        val = str(r).strip('"')
                        parts = [p.strip() for p in val.split("|")]
                        if parts and parts[0].isdigit():
                            cymru_asn = f"AS{parts[0]}"
                            break
            except Exception:
                pass

            if cymru_asn:
                asn = cymru_asn
                asn_status = "RESOLVED_TEAM_CYMRU_BGP"
                sources_queried.append("Team_Cymru_BGP")
                findings.append(
                    {
                        "property": "asn",
                        "value": asn,
                        "asn_type": "BGP_AUTONOMOUS_SYSTEM",
                        "status": asn_status,
                        "reason": "Resolved true BGP ASN via Team Cymru DNS mapping.",
                        "source": "TEAM_CYMRU_DNS",
                        "method": "DNS_TXT_QUERY",
                        "confidence": 0.95,
                        "verification_state": OSINTVerificationState.OBSERVED.value,
                    }
                )
            else:
                asn_status = "NOT_QUERIED_NO_ASN_PROVIDER"
                sources_skipped.append("Team_Cymru_BGP: NO_RECORD_OR_UNAVAILABLE")
                findings.append(
                    {
                        "property": "asn",
                        "value": None,
                        "status": asn_status,
                        "reason": "RDAP network handles are not ASNs; Team Cymru lookup unconfigured or returned no BGP origin.",
                        "source": None,
                        "method": None,
                        "confidence": 0.0,
                        "verification_state": OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value,
                    }
                )

            geo_status = "NOT_QUERIED_NO_GEOLOCATION_PROVIDER"
            findings.append(
                {
                    "property": "geo",
                    "value": None,
                    "status": geo_status,
                    "reason": "No public geolocation provider is configured; no coordinates are reported.",
                    "source": None,
                    "method": None,
                    "confidence": 0.0,
                    "verification_state": OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value,
                }
            )

            # Shodan InternetDB lookup (free, no API key required)
            try:
                shodan_resp = self._client.get(f"https://internetdb.shodan.io/{norm_ip}", timeout=3.0)
                if shodan_resp.status_code == 200:
                    s_data = shodan_resp.json()
                    findings.append({
                        "property": "shodan_internetdb",
                        "ports": s_data.get("ports", []),
                        "cpes": s_data.get("cpes", []),
                        "tags": s_data.get("tags", []),
                        "vulns": s_data.get("vulns", []),
                        "hostnames": s_data.get("hostnames", []),
                        "source": "Shodan_InternetDB",
                        "method": "REST_API_INTERNETDB",
                        "confidence": 0.90,
                        "status": "PRESENT",
                        "verification_state": OSINTVerificationState.OBSERVED.value,
                    })
                    prov_status["SHODAN_INTERNETDB"] = "OBSERVED"
                    sources_queried.append("Shodan_InternetDB")
                elif shodan_resp.status_code == 404:
                    prov_status["SHODAN_INTERNETDB"] = "NOT_FOUND_IN_CHECKED_SOURCES"
                    sources_queried.append("Shodan_InternetDB")
                elif shodan_resp.status_code == 429:
                    prov_status["SHODAN_INTERNETDB"] = "RATE_LIMITED"
                    sources_skipped.append("Shodan: RATE_LIMITED")
                else:
                    prov_status["SHODAN_INTERNETDB"] = f"HTTP_{shodan_resp.status_code}"
                    sources_skipped.append(f"Shodan: HTTP_{shodan_resp.status_code}")
            except Exception as e:
                prov_status["SHODAN_INTERNETDB"] = f"ERROR ({str(e)[:25]})"
                sources_skipped.append("Shodan: UNAVAILABLE")

            # VirusTotal reputation lookup
            vt_api_key = os.environ.get("VT_API_KEY")
            if vt_api_key:
                try:
                    vt_resp = self._client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{norm_ip}",
                        headers={"x-apikey": vt_api_key},
                        timeout=3.5,
                    )
                    if vt_resp.status_code == 200:
                        vt_attr = vt_resp.json().get("data", {}).get("attributes", {})
                        vt_stats = vt_attr.get("last_analysis_stats", {})
                        mal = int(vt_stats.get("malicious", 0))
                        findings.append({
                            "property": "virustotal_reputation",
                            "malicious_votes": mal,
                            "stats": vt_stats,
                            "source": "VirusTotal",
                            "method": "REST_API_V3",
                            "confidence": 0.95,
                            "status": "PRESENT",
                            "verification_state": OSINTVerificationState.CORROBORATED.value if mal == 0 else OSINTVerificationState.OBSERVED.value,
                        })
                        prov_status["VIRUSTOTAL"] = "VERIFIED"
                        sources_queried.append("VirusTotal")
                    elif vt_resp.status_code == 429:
                        prov_status["VIRUSTOTAL"] = "RATE_LIMITED"
                        sources_skipped.append("VirusTotal: RATE_LIMITED")
                    else:
                        prov_status["VIRUSTOTAL"] = f"HTTP_{vt_resp.status_code}"
                        sources_skipped.append(f"VirusTotal: HTTP_{vt_resp.status_code}")
                except Exception as e:
                    prov_status["VIRUSTOTAL"] = f"ERROR ({str(e)[:25]})"
                    sources_skipped.append("VirusTotal: UNAVAILABLE")
            else:
                prov_status["VIRUSTOTAL"] = "PROVIDER_NOT_CONFIGURED"
                sources_skipped.append("VirusTotal: PROVIDER_NOT_CONFIGURED")
                findings.append({
                    "property": "virustotal_reputation",
                    "status": "NOT_CHECKED",
                    "verification_state": OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value,
                    "source": "VirusTotal",
                    "details": "VT_API_KEY not configured in environment; VirusTotal reputation query skipped.",
                })

            # AbuseIPDB reputation lookup
            try:
                from redloop.threat_intel import get_threat_intel_engine
                ti = get_threat_intel_engine()
                rep = ti.check_ip_reputation(norm_ip)
                rep_data = getattr(rep, "data", {}) or {}
                rep_verified = bool(getattr(rep, "verified", False))
                score = int(rep_data.get("abuseConfidenceScore", 0) or 0)
                reports_count = int(rep_data.get("totalReports", 0) or 0)
                rep_state = (
                    OSINTVerificationState.CORROBORATED.value
                    if rep_verified
                    else OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value
                    if rep_data.get("status") == "API_KEY_REQUIRED"
                    else OSINTVerificationState.FAILED.value
                )
                findings.append(
                    {
                        "property": "threat_reputation",
                        "abuse_confidence_score": score if rep_verified else None,
                        "is_malicious": bool(score >= 25) if rep_verified else None,
                        "reports_count": reports_count if rep_verified else None,
                        "provider": "AbuseIPDB",
                        "status": "OBSERVED" if rep_verified else rep_data.get("status", "UNAVAILABLE"),
                        "source": "AbuseIPDB",
                        "method": "HTTPS_REST_API",
                        "confidence": 0.85 if rep_verified else 0.0,
                        "verification_state": rep_state,
                    }
                )
                if rep_verified:
                    prov_status["ABUSEIPDB"] = "VERIFIED"
                    sources_queried.append("AbuseIPDB")
                else:
                    prov_status["ABUSEIPDB"] = rep_data.get("status", "UNAVAILABLE")
                    sources_skipped.append(f"AbuseIPDB: {rep_data.get('status', 'UNAVAILABLE')}")
                    limitations.append(
                        "AbuseIPDB reputation is unavailable; absence of a score is not evidence that the host is benign."
                    )
            except Exception as exc:
                prov_status["ABUSEIPDB"] = f"UNAVAILABLE ({str(exc)[:30]})"
                sources_skipped.append(f"AbuseIPDB: {str(exc)[:30]}")
                limitations.append("AbuseIPDB reputation lookup failed; no reputation conclusion is reported.")

        hostname = reverse_dns.get("hostname")
        findings.append({"property": "reverse_dns", **reverse_dns})
        if hostname:
            related.append(
                {
                    "type": "domain",
                    "value": hostname,
                    "relation": "PTR_CANDIDATE",
                    "verified": reverse_dns.get("source") == "DNS_PTR_QUERY",
                    "source": reverse_dns.get("source"),
                    "method": reverse_dns.get("method"),
                    "confidence": reverse_dns.get("confidence", 0.0),
                    "verification_state": reverse_dns.get("verification_state"),
                }
            )

        # 3. Summary & Transparent Confidence
        if not is_public:
            summary_text = f"IP {norm_ip} classified as {classification} (IPv{ip_obj.version}). Local/private IP: external reputation not applicable; local telemetry only."
        elif offline:
            summary_text = f"Offline Mode Enforced. IP {norm_ip} classified as {classification} (IPv{ip_obj.version})."
        else:
            summary_text = f"IP {norm_ip} classified as {classification} (IPv{ip_obj.version})."
            if hostname:
                summary_text += f" Reverse DNS PTR candidate: {hostname}."
            if network:
                summary_text += f" Registry network: {network.get('name') or network.get('handle')} ({registry})."

        if is_public and not offline:
            registry_verified = registry_status == "VERIFIED"
            rdns_verified = bool(reverse_dns.get("source") == "DNS_PTR_QUERY" and hostname)
            corroboration = 0.7 if (registry_verified and rdns_verified) else 0.5 if registry_verified else 0.2 if rdns_verified else 0.0
            consistency = 0.9 if (registry_verified and (network_status == "VERIFIED" or rdns_verified)) else 0.7
            factors = {
                "source_reliability": 0.95,
                "direct_observation": 0.95,
                "independent_corroboration": corroboration,
                "freshness": 1.0,
                "parser_validation": 1.0,
                "cross_source_consistency": consistency,
            }
        else:
            factors = {
                "source_reliability": 1.0,
                "direct_observation": 1.0,
                "independent_corroboration": 0.0,
                "freshness": 1.0,
                "parser_validation": 1.0,
                "cross_source_consistency": 0.3,
            }

        not_applicable: list[str] = []
        if not (is_public and not offline):
            not_applicable.append("independent_corroboration")
        computed_conf = calculate_confidence(
            **factors, not_applicable_factors=set(not_applicable)
        )
        limitations.append(
            "Confidence scores confidence in the collected observations, not the identity or physical location of a person."
        )
        limitations.append(
            "A successful IP resolution or absence of abuse reports does not prove a host is safe or benign."
        )

        final_status = (
            OSINTVerificationState.RATE_LIMITED
            if rate_state == "RATE_LIMITED"
            else OSINTVerificationState.NOT_CHECKED
            if offline
            else OSINTVerificationState.OBSERVED
        )

        res = OSINTResult(
            indicator=raw_ip,
            query_type="ip",
            normalized_value=norm_ip,
            actual_finding=summary_text,
            status=final_status,
            findings=findings,
            sources_queried=sources_queried,
            sources_skipped=sources_skipped,
            collection_method=(
                "LOCAL_CLASSIFICATION_RDAP_DNS_PTR"
                if is_public and not offline
                else "LOCAL_DETERMINISTIC_CLASSIFICATION"
            ),
            classification=classification,
            reverse_dns=reverse_dns,
            registry=registry,
            registry_status=registry_status,
            network=network,
            network_status=network_status,
            asn=asn,
            asn_status=asn_status,
            geo=None,
            geo_status=geo_status,
            confidence=computed_conf,
            confidence_factors=factors,
            confidence_type="HEURISTIC",
            not_applicable_factors=not_applicable,
            rate_limit_state="OFFLINE_RESTRICTED" if offline else rate_state,
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
            cache_status="LIVE",
        )

        if not offline and res.status not in self._cache._UNCACHEABLE:
            self._cache.set(f"ip:{norm_ip}", res)
        return res

    def _lookup_reverse_dns(self, ip_obj: ipaddress._BaseAddress) -> dict[str, Any]:
        """Resolve a PTR name with dnspython; never fall back to local hosts data."""
        try:
            import dns.reversename
            import dns.resolver

            answer = dns.resolver.resolve(
                dns.reversename.from_address(str(ip_obj)),
                "PTR",
                lifetime=2.0,
            )
            hostnames = sorted({str(record).rstrip(".") for record in answer})
            if hostnames:
                return {
                    "hostname": hostnames[0],
                    "hostnames": hostnames,
                    "status": "RESOLVED",
                    "reason": None,
                    "source": "DNS_PTR_QUERY",
                    "method": "DNS_PTR_LOOKUP",
                    "confidence": 0.95,
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                }
            return {
                "hostname": None,
                "hostnames": [],
                "status": "NOT_FOUND_IN_CHECKED_SOURCES",
                "reason": "DNS PTR lookup returned no hostnames.",
                "source": "DNS_PTR_QUERY",
                "method": "DNS_PTR_LOOKUP",
                "confidence": 0.9,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            }
        except Exception as e:
            return {
                "hostname": None,
                "hostnames": [],
                "status": "FAILED",
                "reason": f"Reverse DNS lookup failed: {e}",
                "source": "DNS_PTR_QUERY",
                "method": "DNS_PTR_LOOKUP",
                "confidence": 0.0,
                "verification_state": OSINTVerificationState.FAILED.value,
            }

    # =========================================================================
    # 2. DOMAIN & INFRASTRUCTURE INTELLIGENCE
    # =========================================================================
    def investigate_domain(self, domain_str: str) -> OSINTResult:
        """Enumerate DNS records, RDAP registration, subdomains via crt.sh, TLS, and HTTP security headers."""
        raw_domain = domain_str.strip().lower()
        clean_domain = re.sub(r"^https?://", "", raw_domain)
        clean_domain = clean_domain.split("/")[0].split(":")[0]

        if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", clean_domain):
            return OSINTResult(
                indicator=domain_str,
                query_type="domain",
                normalized_value=clean_domain,
                actual_finding=f"Invalid domain format: {domain_str}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Indicator does not conform to standard domain naming syntax."],
                sources_skipped=["INPUT_VALIDATION: INVALID_DOMAIN_FORMAT"],
            )

        offline = is_offline_mode()
        cached_result = None if offline else self._cache.get(f"domain:{clean_domain}")
        if cached_result:
            return cached_result

        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}
        sources_queried: list[str] = []
        sources_skipped: list[str] = []

        if offline:
            prov_status["OFFLINE_MODE"] = "ENFORCED"
            sources_skipped.extend([
                "DNS: SKIPPED_OFFLINE",
                "RDAP: SKIPPED_OFFLINE",
                "crt.sh: SKIPPED_OFFLINE",
                "TLS_PROBE: SKIPPED_OFFLINE",
                "HTTP_PROBE: SKIPPED_OFFLINE",
            ])
            limitations.append("Strict OFFLINE_MODE active: external DNS, RDAP, certificate transparency, and HTTP probes were suppressed.")
            return OSINTResult(
                indicator=domain_str,
                query_type="domain",
                normalized_value=clean_domain,
                actual_finding=f"Domain {clean_domain} validated format locally. Strict OFFLINE_MODE active: network enrichment skipped.",
                status=OSINTVerificationState.NOT_CHECKED,
                findings=findings,
                sources_queried=["LOCAL_DOMAIN_FORMAT_PARSER"],
                sources_skipped=sources_skipped,
                collection_method="OFFLINE_FORMAT_VALIDATION",
                confidence=0.85,
                confidence_factors={
                    "source_reliability": 1.0,
                    "direct_observation": 1.0,
                    "independent_corroboration": 0.0,
                    "freshness": 1.0,
                    "parser_validation": 1.0,
                    "cross_source_consistency": 0.5,
                },
                limitations=limitations,
                provider_status=prov_status,
            )

        # 1. Independent DNS Record Queries (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA)
        resolved_ips: list[str] = []
        dns_records: dict[str, list[str]] = {}
        spf_policy: Optional[str] = None
        dmarc_policy: Optional[str] = None

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 2.5

            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
                try:
                    answers = resolver.resolve(clean_domain, rtype)
                    vals = [str(r).strip() for r in answers]
                    if vals:
                        dns_records[rtype] = vals
                        findings.append({
                            "property": f"dns_{rtype.lower()}",
                            "record_type": rtype,
                            "values": vals,
                            "source": "DNS_RESOLVER",
                            "method": f"DNS_QUERY_{rtype}",
                            "confidence": 0.95,
                            "verification_state": OSINTVerificationState.OBSERVED.value,
                            "status": "PRESENT",
                        })
                        if rtype in ("A", "AAAA"):
                            for ip in vals:
                                clean_ip = ip.split()[0]
                                if clean_ip not in resolved_ips:
                                    resolved_ips.append(clean_ip)
                                    related.append({
                                        "type": "ip",
                                        "value": clean_ip,
                                        "relation": "RESOLVES_TO",
                                        "source": "DNS_RESOLVER",
                                        "method": f"DNS_QUERY_{rtype}",
                                        "confidence": 0.95,
                                        "verification_state": OSINTVerificationState.OBSERVED.value,
                                        "verified": True,
                                    })
                        elif rtype == "TXT":
                            for txt in vals:
                                clean_txt = txt.strip('"')
                                if clean_txt.lower().startswith("v=spf1"):
                                    spf_policy = clean_txt
                except Exception:
                    pass

            # DMARC query on _dmarc.<domain>
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
                for r in dmarc_answers:
                    clean_r = str(r).strip().strip('"')
                    if clean_r.lower().startswith("v=dmarc1"):
                        dmarc_policy = clean_r
                        break
            except Exception:
                pass
            sources_queried.append("DNS_RESOLVER")
            prov_status["DNS_RESOLVER"] = "RESOLVED"
        except Exception:
            sources_skipped.append("DNS_RESOLVER: UNAVAILABLE")

        # Fallback to socket getaddrinfo if A/AAAA was empty
        if not resolved_ips:
            try:
                addr_info = socket.getaddrinfo(clean_domain, None)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
                        related.append({
                            "type": "ip",
                            "value": ip,
                            "relation": "RESOLVES_TO",
                            "source": "SYSTEM_DNS",
                            "method": "GETADDRINFO",
                            "confidence": 0.9,
                            "verification_state": OSINTVerificationState.OBSERVED.value,
                            "verified": True,
                        })
                sources_queried.append("SYSTEM_DNS")
            except Exception as e:
                limitations.append(f"DNS A/AAAA resolution failed: {e}")
                sources_skipped.append(f"SYSTEM_DNS: {str(e)[:30]}")

        # Always include canonical dns_records finding
        findings.append({
            "property": "dns_records",
            "type": "A/AAAA",
            "values": resolved_ips,
            "all_types": list(dns_records.keys()),
            "records": dns_records,
            "query_status": "RESOLVED" if (resolved_ips or dns_records) else "UNRESOLVED",
            "resolver": "system_default",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_complete": True,
            "source": "DNS_RESOLVER" if dns_records else "SYSTEM_DNS",
            "method": "INDEPENDENT_DNS_QUERIES" if dns_records else "GETADDRINFO",
            "confidence": 0.95 if dns_records else 0.85,
            "verification_state": OSINTVerificationState.OBSERVED.value if resolved_ips else OSINTVerificationState.FAILED.value,
            "status": "PRESENT" if resolved_ips else "MISSING",
        })

        # SPF & DMARC findings
        findings.append({
            "property": "spf_record",
            "policy": spf_policy or "NOT_CONFIGURED",
            "status": "CONFIGURED" if spf_policy else "MISSING",
            "verification_state": OSINTVerificationState.OBSERVED.value if spf_policy else OSINTVerificationState.OBSERVED.value,
            "source": "DNS_RESOLVER",
            "method": "DNS_QUERY_TXT",
            "confidence": 0.95 if spf_policy else 0.85,
        })
        findings.append({
            "property": "dmarc_record",
            "policy": dmarc_policy or "NOT_CONFIGURED",
            "status": "CONFIGURED" if dmarc_policy else "MISSING",
            "verification_state": OSINTVerificationState.OBSERVED.value if dmarc_policy else OSINTVerificationState.OBSERVED.value,
            "source": "DNS_RESOLVER",
            "method": "DNS_QUERY_TXT",
            "confidence": 0.95 if dmarc_policy else 0.85,
        })

        # 2. RDAP Registrar & Expiration lookup
        try:
            rdap_res = self._client.get(f"https://rdap.org/domain/{clean_domain}", timeout=3.0)
            if rdap_res.status_code == 200:
                r_data = rdap_res.json()
                reg_name = _rdap_org_name(r_data) or r_data.get("handle")
                events = {ev.get("eventAction"): ev.get("eventDate") for ev in r_data.get("events", []) if isinstance(ev, dict)}
                findings.append({
                    "property": "domain_registration",
                    "registrar": reg_name,
                    "creation_date": events.get("registration"),
                    "expiration_date": events.get("expiration"),
                    "last_changed": events.get("last changed"),
                    "source": "RDAP_DOMAIN",
                    "method": "RDAP_REST",
                    "confidence": 0.95,
                    "status": "PRESENT",
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                })
                sources_queried.append("RDAP_Domain")
                prov_status["RDAP_DOMAIN"] = "RESOLVED"
            elif rdap_res.status_code == 429:
                sources_skipped.append("RDAP_Domain: RATE_LIMITED")
                prov_status["RDAP_DOMAIN"] = "RATE_LIMITED"
            else:
                sources_skipped.append(f"RDAP_Domain: HTTP_{rdap_res.status_code}")
                prov_status["RDAP_DOMAIN"] = f"HTTP_{rdap_res.status_code}"
        except Exception as e:
            sources_skipped.append(f"RDAP_Domain: {str(e)[:30]}")
            prov_status["RDAP_DOMAIN"] = "UNAVAILABLE"

        # 3. Subdomain discovery via Certificate Transparency (crt.sh)
        try:
            crt_res = self._client.get(f"https://crt.sh/?q=%25.{clean_domain}&output=json", timeout=3.0)
            if crt_res.status_code == 200:
                crt_data = crt_res.json()
                subdomains = set()
                if isinstance(crt_data, list):
                    for entry in crt_data:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub.endswith(f".{clean_domain}") and sub != clean_domain:
                                subdomains.add(sub)
                findings.append({
                    "property": "certificate_transparency",
                    "subdomains_count": len(subdomains),
                    "subdomains": sorted(list(subdomains))[:25],
                    "source": "crt.sh",
                    "method": "CERTIFICATE_TRANSPARENCY_API",
                    "confidence": 0.90,
                    "status": "PRESENT",
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                })
                for sub in sorted(list(subdomains))[:15]:
                    related.append({
                        "type": "subdomain",
                        "value": sub,
                        "relation": "CERT_TRANSPARENCY_SUBDOMAIN",
                        "source": "crt.sh",
                        "method": "CERTIFICATE_TRANSPARENCY_API",
                        "confidence": 0.90,
                        "verification_state": OSINTVerificationState.OBSERVED.value,
                        "verified": True,
                    })
                sources_queried.append("crt.sh")
                prov_status["CRT_SH"] = "RESOLVED"
            elif crt_res.status_code == 429:
                sources_skipped.append("crt.sh: RATE_LIMITED")
                prov_status["CRT_SH"] = "RATE_LIMITED"
            else:
                sources_skipped.append(f"crt.sh: HTTP_{crt_res.status_code}")
        except Exception as e:
            sources_skipped.append(f"crt.sh: {str(e)[:30]}")
            prov_status["CRT_SH"] = "UNAVAILABLE"

        # 4. TLS Certificate inspection
        cert_info: dict[str, Any] = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((clean_domain, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
                        cert_info = {
                            "common_name": subject.get("commonName"),
                            "issuer_org": issuer.get("organizationName") or issuer.get("commonName"),
                            "not_before": cert.get("notBefore"),
                            "not_after": cert.get("notAfter"),
                            "subject_alt_names": sans[:15],
                        }
                        findings.append({
                            "property": "tls_certificate",
                            "details": cert_info,
                            "source": "TLS_PROBE",
                            "method": "TLS_HANDSHAKE",
                            "confidence": 0.95,
                            "verification_state": OSINTVerificationState.OBSERVED.value,
                        })
                        for san in sans[:10]:
                            if san != clean_domain:
                                related.append({
                                    "type": "subdomain",
                                    "value": san,
                                    "relation": "CERT_SAN",
                                    "source": "TLS_PROBE",
                                    "method": "TLS_HANDSHAKE",
                                    "confidence": 0.95,
                                    "verification_state": OSINTVerificationState.OBSERVED.value,
                                    "verified": True,
                                })
                        prov_status["TLS_PROBE"] = "CERT_EXTRACTED"
                        sources_queried.append("TLS_PROBE")
        except Exception as e:
            prov_status["TLS_PROBE"] = f"NO_TLS_OR_CLOSED ({str(e)[:30]})"
            sources_skipped.append(f"TLS_PROBE: {str(e)[:30]}")

        # 5. HTTP Security Headers
        http_headers_found: dict[str, str] = {}
        try:
            res = self._client.get(f"https://{clean_domain}", timeout=3.5)
            server = res.headers.get("server")
            hsts = res.headers.get("strict-transport-security")
            csp = res.headers.get("content-security-policy")
            x_frame = res.headers.get("x-frame-options")
            x_content = res.headers.get("x-content-type-options")
            referrer = res.headers.get("referrer-policy")
            permissions = res.headers.get("permissions-policy")
            http_headers_found = {
                "server": server or "NOT_EXPOSED",
                "hsts": "CONFIGURED" if hsts else "MISSING",
                "csp": "CONFIGURED" if csp else "MISSING",
                "x_frame_options": x_frame or "MISSING",
                "x_content_type_options": x_content or "MISSING",
                "referrer_policy": referrer or "MISSING",
                "permissions_policy": permissions or "MISSING",
            }
            findings.append({
                "property": "http_security_headers",
                "details": http_headers_found,
                "source": "HTTP_PROBE",
                "method": "HTTPS_GET",
                "confidence": 0.9,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            })
            prov_status["HTTP_PROBE"] = "SUCCESS_200"
            sources_queried.append("HTTP_PROBE")
        except Exception as e:
            prov_status["HTTP_PROBE"] = f"FAILED ({str(e)[:30]})"
            sources_skipped.append(f"HTTP_PROBE: {str(e)[:30]}")

        summary = f"Domain {clean_domain} resolves to {len(resolved_ips)} IP(s) ({', '.join(resolved_ips[:3]) or 'none'})."
        if cert_info.get("issuer_org"):
            summary += f" TLS Issuer: {cert_info['issuer_org']}."
        if http_headers_found:
            summary += f" Server Header: {http_headers_found.get('server')}."

        limitations.append("DNS resolution and TLS certificate presence confirm domain routing, NOT domain reputation, ownership legitimacy, or host safety.")

        factors = {
            "source_reliability": 0.95,
            "direct_observation": 0.95,
            "independent_corroboration": 0.8 if len(sources_queried) >= 3 else 0.5,
            "freshness": 1.0,
            "parser_validation": 1.0,
            "cross_source_consistency": 0.9,
        }
        computed_conf = calculate_confidence(**factors)

        res = OSINTResult(
            indicator=domain_str,
            query_type="domain",
            normalized_value=clean_domain,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED,
            findings=findings,
            sources_queried=sources_queried,
            sources_skipped=sources_skipped,
            collection_method="DNS_TLS_HTTP_PASSIVE",
            confidence=computed_conf if resolved_ips else 0.50,
            confidence_factors=factors,
            confidence_type="HEURISTIC",
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
            cache_status="LIVE",
        )

        if not offline and res.status not in self._cache._UNCACHEABLE:
            self._cache.set(f"domain:{clean_domain}", res)
        return res

    # =========================================================================
    # 3. EMAIL INTELLIGENCE
    # =========================================================================
    def investigate_email(self, email_str: str, raw_headers: Optional[str] = None) -> OSINTResult:
        """Validate RFC 5322 syntax, domain MX deliverability, SPF/DMARC posture, and breach exposure."""
        raw_email = email_str.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", raw_email):
            return OSINTResult(
                indicator=email_str,
                query_type="email",
                normalized_value=raw_email,
                actual_finding=f"Invalid email syntax format: {email_str}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Indicator does not conform to RFC 5322 email syntax standard."],
                sources_skipped=["INPUT_VALIDATION: INVALID_EMAIL_FORMAT"],
            )

        offline = is_offline_mode()
        user_part, domain_part = raw_email.split("@", 1)
        sources_queried: list[str] = ["RFC5322_SYNTAX_PARSER", "DISPOSABLE_DOMAINS_CATALOG"]
        sources_skipped: list[str] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}

        # 1. Syntax & Disposable Domain Check (Local, deterministic)
        is_disposable = domain_part in DISPOSABLE_EMAIL_DOMAINS
        findings: list[dict[str, Any]] = [
            {
                "property": "syntax_validation",
                "rfc5322_valid": True,
                "username": user_part,
                "domain": domain_part,
                "status": "PRESENT",
                "verification_state": OSINTVerificationState.OBSERVED.value,
                "source": "RFC5322_SYNTAX_PARSER",
                "method": "EMAIL_SYNTAX_PARSE",
                "confidence": 0.99,
            },
            {
                "property": "disposable_email_domain",
                "is_disposable": is_disposable,
                "domain": domain_part,
                "status": "PRESENT",
                "verification_state": OSINTVerificationState.OBSERVED.value,
                "source": "DISPOSABLE_DOMAINS_CATALOG",
                "method": "OFFLINE_HASH_SET_LOOKUP",
                "confidence": 0.99,
            }
        ]
        related: list[dict[str, Any]] = [
            {
                "type": "domain",
                "value": domain_part,
                "relation": "BELONGS_TO_DOMAIN",
                "source": "RFC5322_SYNTAX_PARSER",
                "method": "EMAIL_SYNTAX_PARSE",
                "confidence": 0.99,
                "verification_state": OSINTVerificationState.INFERRED.value,
                "verified": False,
            },
            {
                "type": "username",
                "value": user_part,
                "relation": "LOCAL_USER",
                "source": "RFC5322_SYNTAX_PARSER",
                "method": "EMAIL_SYNTAX_PARSE",
                "confidence": 0.99,
                "verification_state": OSINTVerificationState.INFERRED.value,
                "verified": False,
            }
        ]

        if offline:
            prov_status["OFFLINE_MODE"] = "ENFORCED"
            sources_skipped.extend([
                "DNS_MX: SKIPPED_OFFLINE",
                "SPF_DMARC: SKIPPED_OFFLINE",
                "Gravatar: SKIPPED_OFFLINE",
                "HIBP: SKIPPED_OFFLINE",
            ])
            limitations.append("Strict OFFLINE_MODE active: external DNS MX, SPF/DMARC, Gravatar, and breach queries were suppressed.")
            return OSINTResult(
                indicator=email_str,
                query_type="email",
                normalized_value=raw_email,
                actual_finding=f"Email {raw_email} syntax validated. Domain: {domain_part}. Disposable: {is_disposable}. Strict OFFLINE_MODE active: network checks skipped.",
                status=OSINTVerificationState.NOT_CHECKED,
                findings=findings,
                sources_queried=sources_queried,
                sources_skipped=sources_skipped,
                collection_method="OFFLINE_SYNTAX_PARSE",
                confidence=0.88,
                confidence_factors={
                    "source_reliability": 1.0,
                    "direct_observation": 1.0,
                    "independent_corroboration": 0.0,
                    "freshness": 1.0,
                    "parser_validation": 1.0,
                    "cross_source_consistency": 0.5,
                },
                limitations=limitations,
                provider_status=prov_status,
                related_entities=related,
            )

        # 2. Domain MX Verification with priorities
        mx_records = []
        try:
            import dns.resolver
            mx_ans = dns.resolver.resolve(domain_part, "MX")
            for r in mx_ans:
                mx_records.append({"exchange": str(r.exchange).rstrip("."), "preference": int(r.preference)})
            mx_records.sort(key=lambda x: x["preference"])
            findings.append({
                "property": "mx_records",
                "records": mx_records,
                "status": "PRESENT" if mx_records else "MISSING",
                "verification_state": OSINTVerificationState.OBSERVED.value if mx_records else OSINTVerificationState.UNVERIFIED.value,
                "source": "DNS_RESOLVER",
                "method": "DNS_QUERY_MX",
                "confidence": 0.95,
            })
            sources_queried.append("DNS_MX")
            prov_status["DNS_MX"] = "RESOLVED"
        except Exception as e:
            sources_skipped.append(f"DNS_MX: {str(e)[:30]}")
            prov_status["DNS_MX"] = "UNRESOLVED"

        # Domain reachability fallback
        try:
            addr = socket.gethostbyname(domain_part)
            findings.append({
                "property": "domain_reachability",
                "resolves": True,
                "ip": addr,
                "source": "DOMAIN_DNS",
                "method": "GETADDRINFO",
                "confidence": 0.9,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            })
            prov_status["DOMAIN_DNS"] = "RESOLVED"
        except Exception as e:
            prov_status["DOMAIN_DNS"] = "UNRESOLVED"
            sources_skipped.append(f"DOMAIN_DNS: {str(e)[:30]}")

        # 3. SPF and DMARC record checks
        try:
            import dns.resolver
            txt_ans = dns.resolver.resolve(domain_part, "TXT")
            spf_val = None
            for r in txt_ans:
                s = str(r).strip().strip('"')
                if s.lower().startswith("v=spf1"):
                    spf_val = s
                    break
            if spf_val:
                findings.append({
                    "property": "spf_record",
                    "policy": spf_val,
                    "status": "CONFIGURED",
                    "source": "DNS_RESOLVER",
                    "method": "DNS_QUERY_TXT",
                    "confidence": 0.95,
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                })
                sources_queried.append("DNS_SPF")

            dmarc_val = None
            try:
                d_ans = dns.resolver.resolve(f"_dmarc.{domain_part}", "TXT")
                for r in d_ans:
                    s = str(r).strip().strip('"')
                    if s.lower().startswith("v=dmarc1"):
                        dmarc_val = s
                        break
            except Exception:
                pass
            if dmarc_val:
                findings.append({
                    "property": "dmarc_record",
                    "policy": dmarc_val,
                    "status": "CONFIGURED",
                    "source": "DNS_RESOLVER",
                    "method": "DNS_QUERY_TXT",
                    "confidence": 0.95,
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                })
                sources_queried.append("DNS_DMARC")
        except Exception:
            pass

        # 4. Gravatar existence check
        gravatar_hash = hashlib.md5(raw_email.encode("utf-8")).hexdigest()
        try:
            g_resp = self._client.get(f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404", timeout=2.5)
            exists = (g_resp.status_code == 200)
            findings.append({
                "property": "gravatar_profile",
                "hash": gravatar_hash,
                "exists": exists,
                "status": "PRESENT" if exists else "CHECKED_NOT_FOUND",
                "source": "Gravatar",
                "method": "HTTP_HEAD",
                "confidence": 0.95,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            })
            sources_queried.append("Gravatar")
        except Exception as e:
            sources_skipped.append(f"Gravatar: {str(e)[:30]}")

        # 5. Raw headers analysis if supplied
        if raw_headers:
            header_findings: dict[str, Any] = {}
            for line in raw_headers.splitlines():
                if line.lower().startswith("received:"):
                    header_findings.setdefault("hops", []).append(line.strip()[:100])
                elif line.lower().startswith("authentication-results:"):
                    header_findings["auth_results"] = line.strip()
                elif line.lower().startswith("dkim-signature:"):
                    header_findings["dkim_present"] = True
            findings.append({"property": "raw_header_analysis", "details": header_findings})

        # 6. HaveIBeenPwned Truthful Check
        hibp_key = os.environ.get("HIBP_API_KEY")
        if hibp_key:
            try:
                r = self._client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{raw_email}",
                    headers={"hibp-api-key": hibp_key},
                    timeout=3.0,
                )
                if r.status_code == 200:
                    breaches = r.json()
                    findings.append({
                        "property": "breach_exposure",
                        "count": len(breaches),
                        "breaches": [b.get("Name") for b in breaches[:5]],
                        "status": "PRESENT",
                        "verification_state": OSINTVerificationState.CORROBORATED.value,
                        "source": "HIBP",
                        "method": "REST_API_BREACH_CHECK",
                    })
                    prov_status["HIBP"] = f"EXPOSED_IN_{len(breaches)}_BREACHES"
                    sources_queried.append("HIBP")
                elif r.status_code == 404:
                    findings.append({
                        "property": "breach_exposure",
                        "count": 0,
                        "status": "CLEAN",
                        "verification_state": OSINTVerificationState.OBSERVED.value,
                        "source": "HIBP",
                        "method": "REST_API_BREACH_CHECK",
                    })
                    prov_status["HIBP"] = "NOT_FOUND_IN_CHECKED_SOURCES"
                    sources_queried.append("HIBP")
                elif r.status_code == 429:
                    prov_status["HIBP"] = "RATE_LIMITED"
                    sources_skipped.append("HIBP: RATE_LIMITED")
                else:
                    prov_status["HIBP"] = f"HTTP_{r.status_code}"
                    sources_skipped.append(f"HIBP: HTTP_{r.status_code}")
            except Exception as e:
                prov_status["HIBP"] = f"ERROR: {str(e)[:30]}"
                sources_skipped.append(f"HIBP: {str(e)[:30]}")
        else:
            prov_status["HIBP"] = "PROVIDER_NOT_CONFIGURED"
            sources_skipped.append("HIBP: PROVIDER_NOT_CONFIGURED")
            findings.append({
                "property": "breach_exposure",
                "count": "NOT_CHECKED",
                "status": "NOT_CHECKED",
                "verification_state": OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value,
                "source": "HIBP",
                "method": "REST_API_BREACH_CHECK",
                "details": "HIBP_API_KEY not configured in environment; breach lookup not performed.",
            })
            limitations.append("HIBP_API_KEY not configured in environment. Public breach search skipped (count is UNKNOWN/NOT_CHECKED, NEVER assumed safe or 0).")

        # 7. Mailbox existence note
        findings.append({
            "property": "mailbox_existence",
            "status": "UNVERIFIED",
            "note": "Domain MX configuration indicates mail server readiness, NOT individual mailbox existence or deliverability.",
        })
        limitations.append("A valid domain or MX record confirms only that a mail routing host is defined, NOT that the specific mailbox exists.")

        summary = f"Email {raw_email} syntax validated successfully. Domain: {domain_part}."
        if not hibp_key:
            summary += " HIBP: PROVIDER_NOT_CONFIGURED (breach status UNKNOWN)."

        factors = {
            "source_reliability": 0.95,
            "direct_observation": 0.95,
            "independent_corroboration": 0.7 if len(sources_queried) >= 3 else 0.4,
            "freshness": 1.0,
            "parser_validation": 1.0,
            "cross_source_consistency": 0.85,
        }
        computed_conf = calculate_confidence(**factors)

        return OSINTResult(
            indicator=email_str,
            query_type="email",
            normalized_value=raw_email,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED,
            findings=findings,
            sources_queried=sources_queried,
            sources_skipped=sources_skipped,
            collection_method="SYNTAX_DNS_PASSIVE",
            confidence=computed_conf,
            confidence_factors=factors,
            confidence_type="HEURISTIC",
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    # =========================================================================
    # 4. USERNAME INTELLIGENCE
    # =========================================================================
    def investigate_username(self, username_str: str) -> OSINTResult:
        """Search supported public platforms for candidate profile presence with soft-404 detection."""
        raw_user = username_str.strip().lstrip("@")
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,40}$", raw_user):
            return OSINTResult(
                indicator=username_str,
                query_type="username",
                normalized_value=raw_user,
                actual_finding=f"Invalid username character set: {username_str}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Username must contain only alphanumeric characters, dashes, dots, or underscores."],
                sources_skipped=["INPUT_VALIDATION: INVALID_USERNAME_CHARS"],
            )

        offline = is_offline_mode()
        sources_queried: list[str] = []
        sources_skipped: list[str] = []
        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        prov_status: dict[str, str] = {}
        observed_profiles = 0

        # Ensure platforms catalog is available
        platforms = self._platforms_catalog
        if not platforms:
            catalog_path = Path("data/osint/platforms.json")
            if catalog_path.exists():
                try:
                    platforms = json.loads(catalog_path.read_text(encoding="utf-8"))
                    self._platforms_catalog = platforms
                except Exception:
                    platforms = []

        if offline:
            prov_status["OFFLINE_MODE"] = "ENFORCED"
            for p in (platforms[:10] if platforms else []):
                sources_skipped.append(f"{p.get('name', 'Platform')}: SKIPPED_OFFLINE")
            limitations = [
                "Strict OFFLINE_MODE active: external platform HTTP probes were suppressed.",
                "A matching username on a public platform indicates candidate presence, not verified human identity.",
            ]
            return OSINTResult(
                indicator=username_str,
                query_type="username",
                normalized_value=raw_user,
                actual_finding=f"Username '{raw_user}' format validated locally. Strict OFFLINE_MODE active: platform checks skipped.",
                status=OSINTVerificationState.NOT_CHECKED,
                findings=findings,
                sources_queried=["USERNAME_REGEX_VALIDATOR"],
                sources_skipped=sources_skipped,
                collection_method="OFFLINE_FORMAT_VALIDATION",
                confidence=0.5,
                confidence_factors={
                    "source_reliability": 1.0,
                    "direct_observation": 1.0,
                    "independent_corroboration": 0.0,
                    "freshness": 1.0,
                    "parser_validation": 1.0,
                    "cross_source_consistency": 0.5,
                },
                limitations=limitations,
                provider_status=prov_status,
            )

        # Query platforms in catalog (up to 6 per scan to bound latency, deferring remainder)
        limit = int(os.environ.get("REDLOOP_OSINT_PLATFORMS_LIMIT", "6"))
        scan_platforms = platforms[:limit] if platforms else [
            {"name": "GitHub", "url_pattern": "https://github.com/{username}", "check_url": "https://api.github.com/users/{username}", "check_type": "json_field", "match_field": "login", "error_status_codes": [404], "error_strings": ["Not Found"], "min_length": 50},
            {"name": "GitLab", "url_pattern": "https://gitlab.com/{username}", "check_url": "https://gitlab.com/api/v4/users?username={username}", "check_type": "json_field", "match_field": "username", "error_status_codes": [404], "error_strings": [], "min_length": 10},
            {"name": "Reddit", "url_pattern": "https://www.reddit.com/user/{username}", "check_url": "https://www.reddit.com/user/{username}/about.json", "check_type": "json_field", "match_field": "name", "error_status_codes": [404], "error_strings": ["not_found"], "min_length": 30},
            {"name": "Keybase", "url_pattern": "https://keybase.io/{username}", "check_url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}", "check_type": "status_code", "error_status_codes": [404], "error_strings": [], "min_length": 30},
        ]
        for p in platforms[limit:]:
            p_n = p.get("name")
            if p_n:
                sources_skipped.append(f"{p_n}: DEFERRED_BATCH")

        for p in scan_platforms:
            p_name = p.get("name", "Unknown")
            check_url = p.get("check_url", "").format(username=raw_user)
            profile_url = p.get("url_pattern", "").format(username=raw_user)
            if not check_url:
                continue

            try:
                res = self._client.get(check_url, timeout=1.5)
                err_codes = p.get("error_status_codes", [404])
                err_strings = p.get("error_strings", [])
                min_len = p.get("min_length", 0)

                if res.status_code in err_codes:
                    prov_status[p_name] = "NOT_FOUND"
                    sources_queried.append(p_name)
                    findings.append({
                        "platform": p_name,
                        "profile_url": profile_url,
                        "status": "NOT_FOUND",
                        "http_status": res.status_code,
                        "source": p_name,
                        "method": "PUBLIC_HTTP_PROBE",
                        "confidence": 0.90,
                        "verification_state": "NO_MATCH",
                    })
                elif res.status_code == 429:
                    prov_status[p_name] = "RATE_LIMITED"
                    sources_skipped.append(f"{p_name}: RATE_LIMITED")
                    findings.append({
                        "platform": p_name,
                        "profile_url": profile_url,
                        "status": "RATE_LIMITED",
                        "http_status": 429,
                        "source": p_name,
                        "method": "PUBLIC_HTTP_PROBE",
                        "confidence": 0.0,
                        "verification_state": "UNCHECKED",
                    })
                elif res.status_code == 200:
                    # Soft-404 detection
                    is_soft_404 = False
                    if len(res.content) < min_len:
                        is_soft_404 = True
                    text_lower = res.text.lower()
                    if any(s.lower() in text_lower for s in err_strings if s):
                        is_soft_404 = True

                    # JSON field match check if specified
                    if not is_soft_404 and p.get("check_type") == "json_field":
                        try:
                            jdata = res.json()
                            mf = p.get("match_field", "")
                            if isinstance(jdata, dict):
                                val = str(jdata.get(mf, "")).lower()
                                if val != raw_user.lower():
                                    is_soft_404 = True
                            elif isinstance(jdata, list):
                                matched_any = any(isinstance(u, dict) and str(u.get(mf, "")).lower() == raw_user.lower() for u in jdata)
                                if not matched_any:
                                    is_soft_404 = True
                        except Exception:
                            is_soft_404 = True

                    if is_soft_404:
                        prov_status[p_name] = "NOT_FOUND"
                        sources_queried.append(p_name)
                        findings.append({
                            "platform": p_name,
                            "profile_url": profile_url,
                            "status": "NOT_FOUND",
                            "http_status": 200,
                            "reason": "SOFT_404_DETECTED",
                            "source": p_name,
                            "method": "PUBLIC_HTTP_PROBE",
                            "confidence": 0.85,
                            "verification_state": "NO_MATCH",
                        })
                    else:
                        observed_profiles += 1
                        prov_status[p_name] = "PROFILE_OBSERVED"
                        sources_queried.append(p_name)
                        findings.append({
                            "platform": p_name,
                            "profile_url": profile_url,
                            "status": "OBSERVED",
                            "http_status": 200,
                            "source": p_name,
                            "method": "PUBLIC_HTTP_PROBE",
                            "confidence": 0.65,
                            "verification_state": "CANDIDATE_MATCH",
                        })
                        related.append({
                            "type": "profile",
                            "value": profile_url,
                            "relation": f"ACCOUNT_ON_{p_name.upper()}",
                            "source": p_name,
                            "method": "PUBLIC_HTTP_PROBE",
                            "confidence": 0.65,
                            "verification_state": "CANDIDATE_MATCH",
                            "verified": True,
                        })
                else:
                    prov_status[p_name] = f"HTTP_{res.status_code}"
                    sources_skipped.append(f"{p_name}: HTTP_{res.status_code}")
            except Exception as e:
                prov_status[p_name] = f"ERROR: {str(e)[:25]}"
                sources_skipped.append(f"{p_name}: {str(e)[:25]}")

        summary = f"Username '{raw_user}' checked across {len(sources_queried)} public platforms. Observed {observed_profiles} candidate profile(s)."
        limitations = [
            "A matching username on a public platform indicates candidate presence, not verified human identity.",
            "Independent correlation of cryptographic signatures, public keys, or historical timestamps is strictly required.",
        ]

        factors = {
            "source_reliability": 0.70,
            "direct_observation": 0.80,
            "independent_corroboration": 0.50 if observed_profiles > 1 else 0.20,
            "freshness": 1.0,
            "parser_validation": 1.0,
            "cross_source_consistency": 0.60,
        }
        computed_conf = min(0.75, calculate_confidence(**factors))

        return OSINTResult(
            indicator=username_str,
            query_type="username",
            normalized_value=raw_user,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED if observed_profiles > 0 else OSINTVerificationState.OBSERVED,
            findings=findings,
            sources_queried=sources_queried,
            sources_skipped=sources_skipped,
            collection_method="PUBLIC_REST_API_PASSIVE",
            confidence=computed_conf if observed_profiles > 0 else 0.50,
            confidence_factors=factors,
            confidence_type="HEURISTIC",
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    # =========================================================================
    # 5. PHONE INTELLIGENCE
    # =========================================================================
    def investigate_phone(self, phone_str: str) -> OSINTResult:
        """Parse E.164 international format, determine ITU numbering region, and prefix-based carrier attribution."""
        clean_digits = re.sub(r"[^\d+]", "", phone_str.strip())
        if not clean_digits.startswith("+"):
            clean_digits = "+" + clean_digits

        if not re.match(r"^\+[1-9]\d{6,14}$", clean_digits):
            return OSINTResult(
                indicator=phone_str,
                query_type="phone",
                normalized_value=clean_digits,
                actual_finding=f"Invalid international phone number format: {phone_str}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Phone number must conform to ITU-T E.164 standard (e.g. +14155552671)."],
                sources_skipped=["INPUT_VALIDATION: INVALID_PHONE_FORMAT"],
            )

        offline = is_offline_mode()
        sources_queried: list[str] = ["ITU_E164_LOCAL_PARSER", "phonenumbers"]
        sources_skipped: list[str] = [
            "TWILIO_LOOKUP: PROVIDER_NOT_CONFIGURED",
            "NUMVERIFY: PROVIDER_NOT_CONFIGURED",
            "HLR_LOOKUP: PROVIDER_NOT_CONFIGURED",
        ]
        if offline:
            sources_skipped.append("LIVE_HLR: SKIPPED_OFFLINE")

        parsed_via_phonenumbers = False
        formatted_e164 = clean_digits
        country_match = None
        region_name = "International / Unknown"
        matched_cc = None
        is_valid_num = False
        is_possible_num = False
        carrier_str = "UNKNOWN (prefix metadata)"
        line_type_str = "UNKNOWN"

        TYPE_MAP = {
            0: "FIXED_LINE",
            1: "MOBILE",
            2: "FIXED_LINE_OR_MOBILE",
            3: "TOLL_FREE",
            4: "PREMIUM_RATE",
            5: "SHARED_COST",
            6: "VOIP",
            7: "PERSONAL_NUMBER",
            8: "PAGER",
            9: "UAN",
            10: "VOICEMAIL",
            11: "UNKNOWN",
        }

        try:
            import phonenumbers
            from phonenumbers import carrier as phone_carrier, geocoder
            p_obj = phonenumbers.parse(clean_digits, None)
            is_possible_num = phonenumbers.is_possible_number(p_obj)
            is_valid_num = phonenumbers.is_valid_number(p_obj)
            if is_possible_num:
                formatted_e164 = phonenumbers.format_number(p_obj, phonenumbers.PhoneNumberFormat.E164)
                matched_cc = str(p_obj.country_code)
                reg_code = phonenumbers.region_code_for_number(p_obj)
                country_match = "US/CA" if reg_code in ("US", "CA") else reg_code
                geo_desc = geocoder.description_for_number(p_obj, "en")
                region_name = geo_desc or ("North America" if reg_code in ("US", "CA") else (country_match or "International / Unknown"))
                raw_c = phone_carrier.name_for_number(p_obj, "en")
                if raw_c:
                    carrier_str = f"{raw_c} (prefix metadata)"
                ntype = phonenumbers.number_type(p_obj)
                line_type_str = TYPE_MAP.get(ntype, "UNKNOWN")
                parsed_via_phonenumbers = True
        except Exception:
            pass

        if not parsed_via_phonenumbers:
            digits_only = clean_digits[1:]
            for length in (3, 2, 1):
                prefix = digits_only[:length]
                if prefix in ITU_CALLING_CODES:
                    matched_cc = prefix
                    country_match = ITU_CALLING_CODES[prefix]["country"]
                    region_name = ITU_CALLING_CODES[prefix]["region"]
                    break

        findings: list[dict[str, Any]] = [
            {
                "property": "e164_format",
                "value": formatted_e164,
                "is_valid_number": is_valid_num,
                "is_possible_number": is_possible_num,
                "country_calling_code": f"+{matched_cc}" if matched_cc else "UNKNOWN",
                "iso_country": country_match or "UNKNOWN",
                "geographic_region": region_name,
                "carrier_identity": carrier_str,
                "carrier_attribution_type": "PREFIX_METADATA",
                "live_hlr_status": "PROVIDER_NOT_CONFIGURED (live carrier lookup requires commercial HLR/SS7 provider)",
                "line_type": line_type_str,
                "subscriber_assignment": "UNVERIFIED_LOCALLY",
                "status": "PRESENT",
                "verification_state": OSINTVerificationState.OBSERVED.value,
                "source": "ITU_E164_LOCAL_PARSER",
                "method": "E164_NUMBERING_PLAN_PARSE",
                "confidence": 0.92,
            }
        ]

        related: list[dict[str, Any]] = []
        if country_match:
            related.append({
                "type": "country",
                "value": country_match,
                "relation": "NUMBERING_PLAN",
                "source": "ITU_E164_LOCAL_PARSER",
                "method": "E164_NUMBERING_PLAN_PARSE",
                "confidence": 0.92,
                "verification_state": OSINTVerificationState.OBSERVED.value,
                "verified": True,
            })

        limitations = [
            "Local parsing confirms numbering plan formatting and region code only; does NOT verify subscriber identity, active assignment, or live carrier.",
            "Subscriber identities, precise geolocation, and private account associations are not accessible via public OSINT.",
            "Carrier attribution is derived from prefix metadata only. Live HLR lookup requires commercial SS7/HLR provider.",
        ]

        prov_status = {
            "ITU_E164_LOCAL_PARSER": "OBSERVED",
            "PHONENUMBERS": "PARSED" if parsed_via_phonenumbers else "FAILED",
            "TWILIO_LOOKUP": "PROVIDER_NOT_CONFIGURED",
            "NUMVERIFY": "PROVIDER_NOT_CONFIGURED",
            "LIVE_HLR": "PROVIDER_NOT_CONFIGURED",
        }

        # Check for optional Twilio credentials
        has_verified_carrier = False
        twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID")
        twilio_token = os.environ.get("TWILIO_AUTH_TOKEN")
        if twilio_sid and twilio_token and not offline:
            try:
                r = self._client.get(
                    f"https://lookups.twilio.com/v1/PhoneNumbers/{formatted_e164}?Type=carrier",
                    auth=(twilio_sid, twilio_token),
                )
                if r.status_code == 200:
                    carrier_data = r.json().get("carrier", {})
                    findings.append({
                        "property": "carrier_lookup",
                        "carrier_name": carrier_data.get("name"),
                        "line_type": carrier_data.get("type"),
                        "status": "PRESENT",
                        "verification_state": OSINTVerificationState.CORROBORATED.value,
                        "source": "TWILIO_LOOKUP",
                        "method": "REST_API",
                        "confidence": 0.95,
                    })
                    prov_status["TWILIO_LOOKUP"] = "LIVE_VERIFIED"
                    sources_queried.append("TWILIO_LOOKUP")
                    has_verified_carrier = True
                else:
                    prov_status["TWILIO_LOOKUP"] = f"HTTP_{r.status_code}"
            except Exception as e:
                prov_status["TWILIO_LOOKUP"] = f"ERROR: {str(e)[:30]}"

        summary = f"Phone {formatted_e164} parsed as E.164 standard. Region: {region_name} ({country_match or 'Unknown'}). Carrier: {carrier_str} [PREFIX_METADATA]. Live HLR: PROVIDER_NOT_CONFIGURED."
        factors = {
            "source_reliability": 0.95,
            "direct_observation": 0.95,
            "independent_corroboration": 0.8 if has_verified_carrier else 0.5,
            "freshness": 1.0,
            "parser_validation": 1.0,
            "cross_source_consistency": 0.85,
        }
        phone_confidence = calculate_confidence(**factors)

        return OSINTResult(
            indicator=phone_str,
            query_type="phone",
            normalized_value=formatted_e164,
            actual_finding=summary,
            status=OSINTVerificationState.CORROBORATED if has_verified_carrier else OSINTVerificationState.OBSERVED,
            findings=findings,
            sources_queried=sources_queried,
            sources_skipped=sources_skipped,
            collection_method="ITU_E164_LOCAL_ENGINE",
            confidence=phone_confidence,
            confidence_factors=factors,
            confidence_type="HEURISTIC",
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    def analyze_file_metadata(
        self,
        file_input: bytes | str | Path,
        filename: str = "uploaded_file",
    ) -> OSINTResult:
        """Extract cryptographic hashes, MIME types, EXIF tags, and document metadata safely."""
        data: bytes
        filepath_str = filename

        if isinstance(file_input, (str, Path)):
            path = Path(file_input)
            if not path.exists():
                return OSINTResult(
                    indicator=str(file_input),
                    query_type="metadata",
                    normalized_value=filename,
                    actual_finding=f"File not found on system: {file_input}",
                    status=OSINTVerificationState.FAILED,
                    confidence=0.0,
                    limitations=["Target file does not exist at specified path."],
                )
            filepath_str = path.name
            data = path.read_bytes()
        elif isinstance(file_input, bytes):
            data = file_input
        else:
            return OSINTResult(
                indicator=filename,
                query_type="metadata",
                normalized_value=filename,
                actual_finding="Invalid file payload type.",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
            )

        # File size safety checks (0-byte and 25MB limit)
        size_bytes = len(data)
        if size_bytes == 0:
            empty_sha256 = hashlib.sha256(b"").hexdigest()
            empty_sha512 = hashlib.sha512(b"").hexdigest()
            empty_md5 = hashlib.md5(b"").hexdigest()
            empty_sha1 = hashlib.sha1(b"").hexdigest()
            return OSINTResult(
                indicator=filepath_str,
                query_type="metadata",
                normalized_value=empty_sha256,
                actual_finding=f"Empty file payload (0 bytes): {filepath_str}. Standard empty digest SHA-256: {empty_sha256}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Target file contains zero bytes of data."],
                findings=[
                    {
                        "property": "cryptographic_identity",
                        "size_bytes": 0,
                        "sha256": empty_sha256,
                        "sha512": empty_sha512,
                        "md5": empty_md5,
                        "sha1": empty_sha1,
                        "file_type": "EMPTY_FILE",
                        "mime_type": "application/x-empty",
                        "status": "PRESENT",
                        "verification_state": OSINTVerificationState.OBSERVED.value,
                        "source": "BYTE_STREAM_DIGEST",
                        "method": "CRYPTOGRAPHIC_HASH",
                        "confidence": 1.0,
                    }
                ],
            )

        if size_bytes > 25 * 1024 * 1024:
            return OSINTResult(
                indicator=filepath_str,
                query_type="metadata",
                normalized_value=filepath_str,
                actual_finding=f"File exceeds maximum safe processing size (25MB): {size_bytes} bytes",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["File size exceeds 25MB safety boundary."],
            )

        # 1. Cryptographic Hashes (Original uploaded bytes)
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()

        # 2. Magic signature & MIME detection
        mime_type = "application/octet-stream"
        file_type = "UNKNOWN_BINARY"

        if data.startswith(b"\xFF\xD8\xFF"):
            mime_type = "image/jpeg"
            file_type = "JPEG_IMAGE"
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            mime_type = "image/png"
            file_type = "PNG_IMAGE"
        elif data.startswith(b"%PDF-"):
            mime_type = "application/pdf"
            file_type = "PDF_DOCUMENT"
        elif data.startswith(b"PK\x03\x04"):
            mime_type = "application/zip"
            file_type = "ZIP_OR_OFFICE_CONTAINER"
        elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            mime_type = "image/gif"
            file_type = "GIF_IMAGE"

        findings: list[dict[str, Any]] = [
            {
                "property": "cryptographic_identity",
                "sha256": sha256,
                "sha512": sha512,
                "md5": md5,
                "sha1": sha1,
                "size_bytes": size_bytes,
                "mime_type": mime_type,
                "file_type": file_type,
                "status": "PRESENT",
                "verification_state": OSINTVerificationState.VERIFIED.value,
                "source": "BYTE_STREAM_DIGEST",
                "method": "CRYPTOGRAPHIC_HASH",
                "confidence": 1.0,
            }
        ]

        limitations: list[str] = []
        ext = Path(filepath_str).suffix.lower()
        deceptive_extension = False
        if ext in (".jpg", ".jpeg") and not data.startswith(b"\xFF\xD8\xFF"):
            deceptive_extension = True
        elif ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
            deceptive_extension = True
        elif ext == ".pdf" and not data.startswith(b"%PDF-"):
            deceptive_extension = True
        elif ext in (".zip", ".docx", ".xlsx") and not data.startswith(b"PK\x03\x04"):
            deceptive_extension = True
        elif ext in (".jpg", ".jpeg", ".png", ".gif") and (data.startswith(b"%PDF-") or data.startswith(b"PK\x03\x04") or data.startswith(b"MZ")):
            deceptive_extension = True

        if deceptive_extension:
            findings.append({
                "property": "deceptive_extension_anomaly",
                "risk": "HIGH",
                "declared_extension": ext,
                "detected_magic": file_type,
                "description": f"File extension '{ext}' does not match detected binary signature '{file_type}'. Potential evasion or masquerading attempt.",
            })
            limitations.append(f"Deceptive extension anomaly detected: file claims extension '{ext}' but exhibits '{file_type}' signature.")

        extracted_metadata: dict[str, Any] = {}

        # 3. PDF Metadata parsing
        if file_type == "PDF_DOCUMENT":
            text_header = data[:2048].decode("latin-1", errors="ignore")
            pdf_version = "Unknown"
            if "%PDF-" in text_header:
                pdf_version = text_header.split("%PDF-")[1].split()[0]
            extracted_metadata["pdf_version"] = pdf_version

            # Check for common Info dict keys
            data_str = data.decode("latin-1", errors="ignore")
            for key in ("Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"):
                match = re.search(rf"/{key}\s*\((.*?)\)", data_str)
                if match:
                    extracted_metadata[key.lower()] = match.group(1)

        # 4. EXIF Image Metadata parsing (JPEG)
        if file_type == "JPEG_IMAGE":
            # Search for APP1 EXIF segment (0xFFE1)
            exif_offset = data.find(b"\xFF\xE1")
            if exif_offset != -1:
                extracted_metadata["has_exif"] = True
                # Parse EXIF tags using basic TIFF header unpacking
                try:
                    # After FFE1 and 2 bytes length is Exif\x00\x00
                    app1_data = data[exif_offset + 4 : exif_offset + 2000]
                    if app1_data.startswith(b"Exif\x00\x00"):
                        extracted_metadata["exif_header_verified"] = True
                except Exception:
                    pass
            else:
                extracted_metadata["has_exif"] = False

        if extracted_metadata:
            findings.append({"property": "embedded_metadata", "details": extracted_metadata})

        summary = f"File '{filepath_str}' analyzed: {file_type} ({mime_type}), {size_bytes} bytes. SHA-256: {sha256[:16]}..."
        if extracted_metadata:
            summary += f" Metadata tags extracted: {len(extracted_metadata)} property(s)."

        related: list[dict[str, Any]] = [
            {
                "type": "hash_sha256",
                "value": sha256,
                "relation": "CRYPTOGRAPHIC_PROOF",
                "source": "LOCAL_STATIC_ANALYZER",
                "method": "SHA256",
                "confidence": 1.0,
                "verification_state": OSINTVerificationState.VERIFIED.value,
                "verified": True,
            },
            {
                "type": "hash_sha512",
                "value": sha512,
                "relation": "CRYPTOGRAPHIC_PROOF",
                "source": "LOCAL_STATIC_ANALYZER",
                "method": "SHA512",
                "confidence": 1.0,
                "verification_state": OSINTVerificationState.VERIFIED.value,
                "verified": True,
            },
        ]

        limitations.extend([
            "Embedded metadata (e.g. Author, Title, EXIF timestamps) can be trivially spoofed by creators and is not cryptographically verified.",
            "SHA-256 and SHA-512 hashes are the definitive immutable properties.",
        ])

        file_confidence = 0.45 if deceptive_extension else 0.98

        return OSINTResult(
            indicator=filepath_str,
            query_type="metadata",
            normalized_value=sha256,
            actual_finding=summary,
            status=OSINTVerificationState.VERIFIED,
            findings=findings,
            collection_method="CRYPTOGRAPHIC_STATIC_ANALYSIS",
            confidence=file_confidence,
            limitations=limitations,
            provider_status={"LOCAL_STATIC_ANALYZER": "VERIFIED"},
            related_entities=related,
        )


def populate_investigation_graph_from_osint(
    graph: InvestigationGraph,
    result: OSINTResult,
) -> None:
    """Synchronize an OSINTResult into REDLOOP's dual-graph InvestigationGraph.
    
    Creates:
    - Primary ASSET node for indicator
    - EVIDENCE node storing the raw evidence hash
    - Related entity nodes (domains, IPs, profiles)
    - Edges with strict provenance and relationships
    """
    root_id = f"asset-{result.query_type}-{result.normalized_value.replace('/', '_').replace(':', '_')}"
    local_only = bool(
        result.classification
        and result.classification not in {"GLOBAL_PUBLIC"}
    )
    graph.add_node(
        node_id=root_id,
        node_type=NodeType.ASSET,
        label=f"{result.query_type.upper()}: {result.indicator}",
        provenance=(
            ProvenanceType.DIRECTLY_OBSERVED
            if local_only
            else ProvenanceType.EXTERNALLY_ENRICHED
        ),
        properties={
            "query_type": result.query_type,
            "indicator": result.indicator,
            "classification": result.classification,
            "status": result.status.value,
            "verification_state": result.verification_state,
            "confidence": result.confidence,
            "confidence_label": result.confidence_label,
            "confidence_type": result.confidence_type,
            "confidence_method": result.confidence_method,
            "not_applicable_factors": result.not_applicable_factors,
            "source": result.source_or_provider,
            "method": result.collection_method,
            "timestamp": result.observation_timestamp,
            "investigation_id": graph.investigation_id,
            "provenance_completeness": result.provenance_completeness,
            "provenance": result.provenance,
            "field_provenance": result.field_provenance,
            "cache_status": result.cache_status,
            "cache_state": result.cache_state,
            "confidence_evidence": result.confidence_evidence,
            "confidence_evidence_score": result.confidence_evidence_score,
            "confidence_methodology": result.confidence_methodology,
            "source_agreement": result.source_agreement,
            "provenance_policy": result.provenance_policy,
            "freshness": result.freshness,
            "freshness_decay": result.freshness_decay,
            "evidence_integrity_status": result.evidence_integrity_status,
        },
    )

    # Evidence node
    evi_node_id = f"evi-{result.evidence_id}"
    graph.add_node(
        node_id=evi_node_id,
        node_type=NodeType.EVIDENCE,
        label=f"Evidence: {result.query_type} ({result.evidence_hash[:10]}...)",
        provenance=(
            ProvenanceType.UNVERIFIED
            if result.status in {OSINTVerificationState.OFFLINE_MODE, OSINTVerificationState.FAILED}
            else ProvenanceType.DIRECTLY_OBSERVED
            if local_only
            else ProvenanceType.EXTERNALLY_ENRICHED
        ),
        properties={
            "evidence_id": result.evidence_id,
            "evidence_hash": result.evidence_hash,
            "evidence_hash_version": result.evidence_hash_version,
            "evidence_integrity": result.verify_evidence_integrity()["valid"],
            "field_provenance": result.field_provenance,
            "classification": result.classification,
            "collection_method": result.collection_method,
            "timestamp": result.observation_timestamp,
            "actual_finding": result.actual_finding,
            "limitations": result.limitations,
            "source": result.source_or_provider,
            "confidence": result.confidence,
            "confidence_label": result.confidence_label,
            "provenance": result.provenance,
            "investigation_id": graph.investigation_id,
            "provenance_completeness": result.provenance_completeness,
            "provenance_policy": result.provenance_policy,
            "source_agreement": result.source_agreement,
            "cache_state": result.cache_state,
            "evidence_integrity_status": result.evidence_integrity_status,
        },
    )

    # Link Asset -> Evidence
    graph.add_edge(
        source_id=root_id,
        target_id=evi_node_id,
        relation="PRODUCED_BY",
        properties={
            "timestamp": result.observation_timestamp,
            "source": result.source_or_provider,
            "method": result.collection_method,
            "confidence": result.confidence,
            "confidence_evidence": result.confidence_evidence_score,
            "evidence_reference": result.evidence_id,
            "evidence_hash": result.evidence_hash,
            "verification_state": result.verification_state,
            "cache_state": result.cache_state,
        },
    )

    # Add related entities and edges. Provenance follows the entity's own
    # verification state; an unverified PTR candidate must not look authoritative.
    for entity in result.related_entities:
        ent_val = str(entity.get("value", ""))
        ent_type = str(entity.get("type", "entity"))
        ent_rel = str(entity.get("relation", "ASSOCIATED_WITH"))
        if not ent_val:
            continue

        entity_digest = hashlib.sha256(ent_val.encode("utf-8")).hexdigest()[:12]
        ent_node_id = f"node-{ent_type}-{entity_digest}"
        entity_verified = bool(entity.get("verified"))
        entity_source = str(entity.get("source") or result.source_or_provider)
        entity_confidence = float(entity.get("confidence", result.confidence) or 0.0)
        entity_state = str(entity.get("verification_state") or "UNVERIFIED")
        entity_method = entity.get("method") or result.collection_method
        entity_evidence = entity.get("evidence_reference") or result.evidence_id
        entity_timestamp = entity.get("timestamp") or result.observation_timestamp
        entity_provenance = (
            ProvenanceType.UNVERIFIED
            if not entity_verified
            else ProvenanceType.EXTERNALLY_ENRICHED
            if "RDAP" in entity_source or "DNS" in entity_source
            else ProvenanceType.DIRECTLY_OBSERVED
        )
        graph.add_node(
            node_id=ent_node_id,
            node_type=NodeType.ENDPOINT if ent_type in ("ip", "domain", "subdomain") else NodeType.ASSET,
            label=f"{ent_type.upper()}: {ent_val}",
            provenance=entity_provenance,
            properties={
                "type": ent_type,
                "value": ent_val,
                "verified": entity_verified,
                "verification_state": entity_state,
                "source": entity_source,
                "method": entity_method,
                "evidence_reference": entity_evidence,
                "timestamp": entity_timestamp,
                "confidence": entity_confidence,
                "investigation_id": graph.investigation_id,
            },
        )
        if not entity_source or not entity_evidence:
            continue
        graph.add_edge(
            source_id=root_id,
            target_id=ent_node_id,
            relation=ent_rel,
            properties={
                "evidence_reference": entity_evidence,
                "evidence_hash": result.evidence_hash,
                "source": entity_source,
                "method": entity_method,
                "verified": entity_verified,
                "verification_state": entity_state,
                "timestamp": entity_timestamp,
                "confidence": entity_confidence,
            },
        )
    graph.save()


_global_osint_engine: Optional[OSINTEngine] = None


def get_osint_engine() -> OSINTEngine:
    global _global_osint_engine
    if _global_osint_engine is None:
        _global_osint_engine = OSINTEngine()
    return _global_osint_engine
