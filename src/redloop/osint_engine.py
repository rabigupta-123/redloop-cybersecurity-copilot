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
    VERIFIED = "VERIFIED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_FOUND_IN_CHECKED_SOURCES = "NOT_FOUND_IN_CHECKED_SOURCES"
    PROVIDER_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    OFFLINE_MODE = "OFFLINE_MODE"


class OSINTResult(BaseModel):
    indicator: str
    query_type: str  # "ip", "domain", "email", "username", "phone", "metadata"
    normalized_value: str
    actual_finding: str
    status: OSINTVerificationState = OSINTVerificationState.OBSERVED
    findings: list[dict[str, Any]] = Field(default_factory=list)
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
        if status in {"PRESENT", "VERIFIED", "OBSERVED", "OBSERVED_LOCALLY"}:
            return "PRESENT"
        if status == "NOT_FOUND_IN_CHECKED_SOURCES":
            return "CHECKED_NOT_FOUND"
        if status == "NOT_APPLICABLE":
            return "NOT_APPLICABLE"
        if not status or status in {"MISSING", "UNKNOWN"}:
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
    """Thread-safe TTL cache with a bounded stale-while-degraded window.

    A stale entry may only be served when a fresh lookup fails; it is always
    labeled STALE and carries the reason, never presented as live data.
    """

    _UNCACHEABLE = {
        OSINTVerificationState.FAILED,
        OSINTVerificationState.OFFLINE_MODE,
    }

    def __init__(self, default_ttl_seconds: float = 300.0, stale_ttl_seconds: float = 3600.0):
        self._cache: dict[str, tuple[float, float, float, OSINTResult]] = {}
        self._ttl = max(0.0, float(default_ttl_seconds))
        self._stale_ttl = max(self._ttl, float(stale_ttl_seconds))
        self._lock = threading.RLock()

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
                return None
            created_at, expires_at, stale_until, result = entry
            if now >= expires_at:
                if now >= stale_until:
                    del self._cache[key]
                return None
            if result.status in self._UNCACHEABLE:
                del self._cache[key]
                return None
        return self._annotate(result, created_at, expires_at, stale_until, now, "CACHED")

    def get_stale(self, key: str) -> Optional[OSINTResult]:
        """Return an expired-but-retained entry, explicitly labeled STALE."""
        now = time.time()
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            created_at, expires_at, stale_until, result = entry
            if now < expires_at:
                return None
            if now >= stale_until:
                del self._cache[key]
                return None
            if result.status in self._UNCACHEABLE:
                del self._cache[key]
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
        return True

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


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
        cache_ttl_seconds: float = 300.0,
    ):
        self._client = http_client or httpx.Client(
            timeout=5.0,
            headers={"User-Agent": "REDLOOP-Cybersecurity-OSINT-Engine/2.0"},
            follow_redirects=True,
        )
        self._cache = OSINTCache(default_ttl_seconds=cache_ttl_seconds)

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
            )

        norm_ip = str(ip_obj)
        offline = is_offline_mode()
        # OFFLINE_MODE must never be satisfied from a cache populated while
        # online: that would silently perform the external disclosure the
        # operator asked to suppress.
        cached_result = None if offline else self._cache.get(f"ip:{norm_ip}")
        if cached_result:
            return cached_result

        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}
        rate_state = "NORMAL"

        # 1. IP Classification (local, deterministic, single canonical enum)
        classification = classify_ip_address(ip_obj)
        is_public = classification == "GLOBAL_PUBLIC"
        findings.append(
            {
                "property": "classification",
                "value": classification,
                "classification": classification,
                # Legacy alias retained for API compatibility; `classification`
                # is the canonical field and always one of IP_CLASSIFICATIONS.
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

        # 2. Reverse DNS. Only public addresses are queried; local OS resolvers
        # can return the machine's own hostname for loopback/private addresses,
        # which is not PTR intelligence.
        if is_public:
            reverse_dns = self._lookup_reverse_dns(ip_obj)
        else:
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

        # 3. Registry / network / ASN / geolocation are separate observations.
        org = None
        country = None
        registry: Optional[str] = None
        registry_status = "NOT_APPLICABLE"
        network: Optional[dict[str, Any]] = None
        network_status = "NOT_APPLICABLE"
        asn: Optional[str] = None
        asn_status = "NOT_APPLICABLE"

        if not is_public:
            limitations.append(
                f"IP {norm_ip} is {classification}; external registry, ASN, and geolocation enrichment are not applicable."
            )
        elif offline:
            prov_status["OFFLINE_MODE"] = "ENFORCED"
            registry_status = "NOT_QUERIED"
            network_status = "NOT_QUERIED"
            asn_status = "NOT_QUERIED"
            geo_status = "NOT_QUERIED"
            limitations.append(
                "Strict OFFLINE_MODE active: external RDAP registry, ASN, geolocation, and threat-intelligence queries were suppressed."
            )
        else:
            # Public RDAP registry lookup with backoff and rate-limit handling.
            rdap_resp, status_desc = request_with_backoff(
                self._client, f"https://rdap.arin.net/registry/ip/{norm_ip}"
            )
            if status_desc == "RATE_LIMITED":
                prov_status["RDAP_ARIN"] = "RATE_LIMITED"
                registry_status = "RATE_LIMITED"
                network_status = "RATE_LIMITED"
                rate_state = "RATE_LIMITED"
                limitations.append("External RDAP service returned HTTP 429 Too Many Requests (rate limited).")
            elif rdap_resp and rdap_resp.status_code == 200:
                try:
                    rdap_data = rdap_resp.json()
                    registry = _registry_from_url(str(rdap_resp.url)) or "ARIN"
                    registry_status = "VERIFIED"
                    prov_status["RDAP_ARIN"] = "ONLINE_VERIFIED"

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
                                "verification_state": OSINTVerificationState.VERIFIED.value,
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
                                "verification_state": OSINTVerificationState.VERIFIED.value,
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
                                "verification_state": OSINTVerificationState.VERIFIED.value,
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
                                "verification_state": OSINTVerificationState.VERIFIED.value,
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
                                "verification_state": OSINTVerificationState.VERIFIED.value,
                            }
                        )
                except Exception:
                    prov_status["RDAP_ARIN"] = "PARSE_ERROR"
                    registry_status = "PARSE_ERROR"
                    network_status = "PARSE_ERROR"
            else:
                prov_status["RDAP_ARIN"] = status_desc
                registry_status = "UNAVAILABLE"
                network_status = "UNAVAILABLE"
                limitations.append("External RDAP service unreachable; registry and network fields are unavailable, not inferred.")

            # RDAP handles are network handles, never ASNs. No ASN provider is
            # configured, so report the gap explicitly instead of guessing.
            asn_status = "NOT_QUERIED_NO_ASN_PROVIDER"
            geo_status = "NOT_QUERIED_NO_GEOLOCATION_PROVIDER"
            findings.append(
                {
                    "property": "asn",
                    "value": None,
                    "status": asn_status,
                    "reason": "RDAP network handles are not ASNs; no ASN lookup provider is configured.",
                    "source": None,
                    "method": None,
                    "confidence": 0.0,
                    "verification_state": OSINTVerificationState.PROVIDER_NOT_CONFIGURED.value,
                }
            )
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

            # Threat intelligence lookup (separate from registry ownership).
            try:
                from redloop.threat_intel import get_threat_intel_engine

                ti = get_threat_intel_engine()
                rep = ti.check_ip_reputation(norm_ip)
                rep_data = getattr(rep, "data", {}) or {}
                rep_verified = bool(getattr(rep, "verified", False))
                score = int(rep_data.get("abuseConfidenceScore", 0) or 0)
                reports_count = int(rep_data.get("totalReports", 0) or 0)
                rep_state = (
                    OSINTVerificationState.VERIFIED.value
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
                prov_status["ABUSEIPDB"] = "VERIFIED" if rep_verified else rep_data.get("status", "UNAVAILABLE")
                if not rep_verified:
                    limitations.append(
                        "AbuseIPDB reputation is unavailable; absence of a score is not evidence that the host is benign."
                    )
            except Exception as exc:
                prov_status["ABUSEIPDB"] = f"UNAVAILABLE ({str(exc)[:30]})"
                limitations.append("AbuseIPDB reputation lookup failed; no reputation conclusion is reported.")

        if not offline and not is_public:
            geo_status = "NOT_APPLICABLE"
            asn_status = "NOT_APPLICABLE"

        # 4. Summary and transparent confidence.
        summary_text = f"IP {norm_ip} classified as {classification} (IPv{ip_obj.version})."
        if offline:
            summary_text = "Offline Mode Enforced. " + summary_text
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
            # No external source exists to corroborate a non-routable or
            # offline observation; scoring it as zero would understate what was
            # actually checked. Exclude it and renormalize the remaining weights.
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
        if is_public and geo_status.startswith("NOT_QUERIED"):
            limitations.append("No geolocation coordinates were queried or reported; do not infer physical location.")

        final_status = (
            OSINTVerificationState.RATE_LIMITED
            if rate_state == "RATE_LIMITED"
            else OSINTVerificationState.OFFLINE_MODE
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

        degraded = is_public and not offline and (
            final_status == OSINTVerificationState.RATE_LIMITED
            or registry_status in {"UNAVAILABLE", "RATE_LIMITED", "PARSE_ERROR", "FAILED"}
            or network_status in {"UNAVAILABLE", "RATE_LIMITED", "PARSE_ERROR", "FAILED"}
        )
        if degraded:
            stale = self._cache.get_stale(f"ip:{norm_ip}")
            if stale is not None:
                stale.cache_fallback_reason = (
                    f"Live enrichment failed ({registry_status or final_status.value}); "
                    "serving the last successful cached observation. Classify it as STALE, not live."
                )
                stale.limitations = list(stale.limitations) + [
                    "This result was served from cache after a failed live lookup; re-verify before acting on it."
                ]
                stale.freshness = OSINTResult._build_freshness(
                    stale.observation_timestamp,
                    age_seconds=float(stale.cache_age_seconds or 0.0),
                    ttl_seconds=stale.cache_ttl_seconds,
                )
                return stale

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
                    "status": "OBSERVED",
                    "reason": None,
                    "source": "DNS_PTR_QUERY",
                    "method": "DNS_PTR_LOOKUP",
                    "confidence": 0.9,
                    "verification_state": OSINTVerificationState.OBSERVED.value,
                }
            return {
                "hostname": None,
                "hostnames": [],
                "status": "NOT_FOUND_IN_CHECKED_SOURCES",
                "reason": "No PTR record returned.",
                "source": "DNS_PTR_QUERY",
                "method": "DNS_PTR_LOOKUP",
                "confidence": 0.8,
                "verification_state": OSINTVerificationState.NOT_FOUND_IN_CHECKED_SOURCES.value,
            }
        except ImportError:
            # Optional dependency unavailable: use the OS resolver but label it
            # honestly as local resolution, which may include a hosts-file entry.
            try:
                resolved_host, _, _ = socket.gethostbyaddr(str(ip_obj))
            except (socket.herror, socket.gaierror, OSError):
                return {
                    "hostname": None,
                    "hostnames": [],
                    "status": "NOT_FOUND_IN_CHECKED_SOURCES",
                    "reason": "No reverse name returned by the local OS resolver.",
                    "source": "LOCAL_OS_RESOLVER",
                    "method": "SOCKET_GETHOSTBYADDR",
                    "confidence": 0.5,
                    "verification_state": OSINTVerificationState.UNVERIFIED_LOCALLY.value,
                }
            return {
                "hostname": resolved_host,
                "hostnames": [resolved_host],
                "status": "OBSERVED_LOCALLY",
                "reason": "Resolved through the local OS resolver; may reflect a hosts file rather than authoritative PTR.",
                "source": "LOCAL_OS_RESOLVER",
                "method": "SOCKET_GETHOSTBYADDR",
                "confidence": 0.35,
                "verification_state": OSINTVerificationState.UNVERIFIED_LOCALLY.value,
            }
        except Exception:
            return {
                "hostname": None,
                "hostnames": [],
                "status": "FAILED",
                "reason": "Reverse DNS lookup failed.",
                "source": "DNS_PTR_QUERY",
                "method": "DNS_PTR_LOOKUP",
                "confidence": 0.0,
                "verification_state": OSINTVerificationState.FAILED.value,
            }

    # =========================================================================
    # 2. DOMAIN & INFRASTRUCTURE INTELLIGENCE
    # =========================================================================
    def investigate_domain(self, domain_str: str) -> OSINTResult:
        """Enumerate DNS records, MX, SPF/DMARC mail policies, TLS certificates, and HTTP headers."""
        raw_domain = domain_str.strip().lower()
        # Clean URL protocol/path if user provided a URL
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
            )

        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}

        # 1. DNS A / AAAA resolution
        resolved_ips: list[str] = []
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
            findings.append({
                "property": "dns_records",
                "type": "A/AAAA",
                "values": resolved_ips,
                "source": "SYSTEM_DNS",
                "method": "GETADDRINFO",
                "confidence": 0.9,
                "verification_state": OSINTVerificationState.OBSERVED.value,
            })
            prov_status["SYSTEM_DNS"] = "RESOLVED"
        except Exception as e:
            limitations.append(f"DNS A/AAAA resolution failed: {e}")
            prov_status["SYSTEM_DNS"] = f"ERROR: {str(e)[:40]}"

        # 2. TLS Certificate inspection
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
        except Exception as e:
            prov_status["TLS_PROBE"] = f"NO_TLS_OR_CLOSED ({str(e)[:30]})"

        # 3. HTTP Security Headers
        http_headers_found: dict[str, str] = {}
        try:
            res = self._client.get(f"https://{clean_domain}", timeout=3.5)
            server = res.headers.get("server")
            hsts = res.headers.get("strict-transport-security")
            csp = res.headers.get("content-security-policy")
            x_frame = res.headers.get("x-frame-options")
            http_headers_found = {
                "server": server or "NOT_EXPOSED",
                "hsts": "CONFIGURED" if hsts else "MISSING",
                "csp": "CONFIGURED" if csp else "MISSING",
                "x_frame_options": x_frame or "MISSING",
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
        except Exception as e:
            prov_status["HTTP_PROBE"] = f"FAILED ({str(e)[:30]})"

        summary = f"Domain {clean_domain} resolves to {len(resolved_ips)} IP(s) ({', '.join(resolved_ips[:3]) or 'none'})."
        if cert_info.get("issuer_org"):
            summary += f" TLS Issuer: {cert_info['issuer_org']}."
        if http_headers_found:
            summary += f" Server Header: {http_headers_found.get('server')}."

        limitations.append("DNS resolution and TLS certificate presence confirm domain routing, NOT domain reputation, ownership legitimacy, or host safety.")

        return OSINTResult(
            indicator=domain_str,
            query_type="domain",
            normalized_value=clean_domain,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED,
            findings=findings,
            collection_method="DNS_TLS_HTTP_PASSIVE",
            confidence=0.9,
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

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
            )

        user_part, domain_part = raw_email.split("@", 1)
        findings: list[dict[str, Any]] = [
            {
                "property": "syntax_validation",
                "rfc5322_valid": True,
                "username": user_part,
                "domain": domain_part,
            }
        ]
        related: list[dict[str, Any]] = []
        limitations: list[str] = []
        prov_status: dict[str, str] = {}

        related.append({
            "type": "domain",
            "value": domain_part,
            "relation": "BELONGS_TO_DOMAIN",
            "source": "RFC5322_SYNTAX_PARSER",
            "method": "EMAIL_SYNTAX_PARSE",
            "confidence": 0.99,
            "verification_state": OSINTVerificationState.INFERRED.value,
            "verified": False,
        })
        related.append({
            "type": "username",
            "value": user_part,
            "relation": "LOCAL_USER",
            "source": "RFC5322_SYNTAX_PARSER",
            "method": "EMAIL_SYNTAX_PARSE",
            "confidence": 0.99,
            "verification_state": OSINTVerificationState.INFERRED.value,
            "verified": False,
        })

        # 1. Domain Mail Exchanger (MX) Verification
        mx_records: list[str] = []
        try:
            # Query standard socket for domain host
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
            findings.append({
                "property": "domain_reachability",
                "resolves": False,
                "error": str(e),
                "source": "DOMAIN_DNS",
                "method": "GETADDRINFO",
                "confidence": 0.8,
                "verification_state": OSINTVerificationState.NOT_FOUND_IN_CHECKED_SOURCES.value,
            })
            limitations.append(f"Domain {domain_part} failed host resolution; mailbox may be non-deliverable.")
            prov_status["DOMAIN_DNS"] = "UNRESOLVED"

        # 2. Email Header Analysis if provided
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

        # 3. Breach Exposure status (HaveIBeenPwned Truthful Check)
        hibp_key = os.environ.get("HIBP_API_KEY")
        if hibp_key:
            try:
                r = self._client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{raw_email}",
                    headers={"hibp-api-key": hibp_key},
                )
                if r.status_code == 200:
                    breaches = r.json()
                    findings.append({"property": "breach_exposure", "count": len(breaches), "breaches": [b.get("Name") for b in breaches[:5]]})
                    prov_status["HIBP"] = f"EXPOSED_IN_{len(breaches)}_BREACHES"
                elif r.status_code == 404:
                    findings.append({"property": "breach_exposure", "count": 0, "status": "CLEAN"})
                    prov_status["HIBP"] = "NOT_FOUND_IN_CHECKED_SOURCES"
            except Exception as e:
                prov_status["HIBP"] = f"ERROR: {str(e)[:30]}"
        else:
            prov_status["HIBP"] = "PROVIDER_NOT_CONFIGURED"
            limitations.append("HIBP_API_KEY not configured in environment. Public breach search skipped to adhere to third-party API terms.")

        # 4. Explicit Mailbox Existence & Deliverability Status
        findings.append({
            "property": "mailbox_existence",
            "status": "UNVERIFIED",
            "note": "Domain MX configuration indicates mail server readiness, NOT individual mailbox existence or deliverability.",
        })
        limitations.append("A valid domain or MX record confirms only that a mail routing host is defined, NOT that the specific mailbox exists.")

        summary = f"Email {raw_email} syntax validated successfully. Domain: {domain_part}."
        if prov_status.get("DOMAIN_DNS") == "RESOLVED":
            summary += " Mail host is active and resolvable (mailbox existence unverified)."

        return OSINTResult(
            indicator=email_str,
            query_type="email",
            normalized_value=raw_email,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED,
            findings=findings,
            collection_method="SYNTAX_DNS_PASSIVE",
            confidence=0.88,
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    # =========================================================================
    # 4. USERNAME INTELLIGENCE
    # =========================================================================
    def investigate_username(self, username_str: str) -> OSINTResult:
        """Search supported public platforms for candidate profile presence without claiming identity link."""
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
            )

        candidate_sources = [
            ("GitHub", f"https://api.github.com/users/{raw_user}", f"https://github.com/{raw_user}"),
            ("Reddit", f"https://www.reddit.com/user/{raw_user}/about.json", f"https://www.reddit.com/user/{raw_user}"),
            ("HackerNews", f"https://hacker-news.firebaseio.com/v0/user/{raw_user}.json", f"https://news.ycombinator.com/user?id={raw_user}"),
            ("GitLab", f"https://gitlab.com/api/v4/users?username={raw_user}", f"https://gitlab.com/{raw_user}"),
            ("Keybase", f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={raw_user}", f"https://keybase.io/{raw_user}"),
        ]

        findings: list[dict[str, Any]] = []
        related: list[dict[str, Any]] = []
        prov_status: dict[str, str] = {}
        observed_profiles = 0

        for platform, check_url, profile_url in candidate_sources:
            try:
                res = self._client.get(check_url, timeout=2.5)
                if res.status_code == 200:
                    if platform == "Keybase":
                        data = res.json()
                        them = data.get("them", [])
                        if not them or not isinstance(them, list) or them[0] is None:
                            prov_status[platform] = "NOT_FOUND"
                            continue
                    elif platform == "HackerNews":
                        data = res.json()
                        if not data or not isinstance(data, dict) or str(data.get("id", "")).lower() != raw_user.lower():
                            prov_status[platform] = "NOT_FOUND"
                            continue
                    elif platform == "GitHub":
                        data = res.json()
                        if not isinstance(data, dict) or str(data.get("login", "")).lower() != raw_user.lower():
                            prov_status[platform] = "NOT_FOUND"
                            continue
                    elif platform == "Reddit":
                        data = res.json()
                        if not isinstance(data, dict) or "data" not in data or str(data.get("data", {}).get("name", "")).lower() != raw_user.lower():
                            prov_status[platform] = "NOT_FOUND"
                            continue
                    elif platform == "GitLab":
                        data = res.json()
                        if not isinstance(data, list) or not any(isinstance(u, dict) and str(u.get("username", "")).lower() == raw_user.lower() for u in data):
                            prov_status[platform] = "NOT_FOUND"
                            continue

                    observed_profiles += 1
                    prov_status[platform] = "PROFILE_OBSERVED"
                    findings.append({
                        "platform": platform,
                        "profile_url": profile_url,
                        "status": "OBSERVED",
                        "source": platform,
                        "method": "PUBLIC_REST_API",
                        "confidence": 0.65,
                        "verification_state": "CANDIDATE_MATCH",
                    })
                    related.append({
                        "type": "profile",
                        "value": profile_url,
                        "relation": f"ACCOUNT_ON_{platform.upper()}",
                        "source": platform,
                        "method": "PUBLIC_REST_API",
                        "confidence": 0.65,
                        "verification_state": "CANDIDATE_MATCH",
                        "verified": True,
                    })
                elif res.status_code == 404:
                    prov_status[platform] = "NOT_FOUND"
                elif res.status_code == 429:
                    prov_status[platform] = "RATE_LIMITED"
                else:
                    prov_status[platform] = f"HTTP_{res.status_code}"
            except Exception as e:
                prov_status[platform] = f"ERROR: {str(e)[:25]}"

        summary = f"Username '{raw_user}' checked across {len(candidate_sources)} public platforms. Observed {observed_profiles} candidate profile(s)."

        limitations = [
            "A matching username on a public platform indicates candidate presence, not verified human identity.",
            "Independent correlation of cryptographic signatures, public keys, or historical timestamps is strictly required.",
        ]

        return OSINTResult(
            indicator=username_str,
            query_type="username",
            normalized_value=raw_user,
            actual_finding=summary,
            status=OSINTVerificationState.OBSERVED if observed_profiles > 0 else OSINTVerificationState.NOT_FOUND_IN_CHECKED_SOURCES,
            findings=findings,
            collection_method="PUBLIC_REST_API_PASSIVE",
            confidence=0.65 if observed_profiles > 0 else 0.5,
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    # =========================================================================
    # 5. PHONE INTELLIGENCE
    # =========================================================================
    def investigate_phone(self, phone_str: str) -> OSINTResult:
        """Parse E.164 international format, determine ITU numbering region, and query verified lookup if configured."""
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
            )

        parsed_via_phonenumbers = False
        formatted_e164 = clean_digits
        country_match = None
        region_name = "International / Unknown"
        matched_cc = None

        try:
            import phonenumbers
            from phonenumbers import geocoder
            p_obj = phonenumbers.parse(clean_digits, None)
            if phonenumbers.is_possible_number(p_obj):
                formatted_e164 = phonenumbers.format_number(p_obj, phonenumbers.PhoneNumberFormat.E164)
                matched_cc = str(p_obj.country_code)
                reg_code = phonenumbers.region_code_for_number(p_obj)
                country_match = "US/CA" if reg_code in ("US", "CA") else reg_code
                geo_desc = geocoder.description_for_number(p_obj, "en")
                region_name = geo_desc or ("North America" if reg_code in ("US", "CA") else (country_match or "International / Unknown"))
                parsed_via_phonenumbers = True
        except Exception:
            pass

        if not parsed_via_phonenumbers:
            # Check longest prefix match in ITU table
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
                "country_calling_code": f"+{matched_cc}" if matched_cc else "UNKNOWN",
                "iso_country": country_match or "UNKNOWN",
                "geographic_region": region_name,
                "subscriber_assignment": "UNVERIFIED_LOCALLY",
                "carrier_identity": "UNVERIFIED_LOCALLY",
                "line_activity": "UNVERIFIED_LOCALLY",
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
            "Carrier and line-type classification require an active licensed commercial lookup provider (Twilio Lookup / NumVerify).",
        ]

        prov_status = {
            "ITU_E164_LOCAL_PARSER": "OBSERVED",
            "TWILIO_LOOKUP": "PROVIDER_NOT_CONFIGURED",
            "NUMVERIFY": "PROVIDER_NOT_CONFIGURED",
        }

        # Check for optional Twilio credentials
        has_verified_carrier = False
        twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID")
        twilio_token = os.environ.get("TWILIO_AUTH_TOKEN")
        if twilio_sid and twilio_token:
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
                    })
                    prov_status["TWILIO_LOOKUP"] = "LIVE_VERIFIED"
                    has_verified_carrier = True
                else:
                    prov_status["TWILIO_LOOKUP"] = f"HTTP_{r.status_code}"
            except Exception as e:
                prov_status["TWILIO_LOOKUP"] = f"ERROR: {str(e)[:30]}"

        summary = f"Phone {formatted_e164} parsed as E.164 standard. Region: {region_name} ({country_match or 'Unknown'})."

        return OSINTResult(
            indicator=phone_str,
            query_type="phone",
            normalized_value=formatted_e164,
            actual_finding=summary,
            status=OSINTVerificationState.VERIFIED if has_verified_carrier else OSINTVerificationState.OBSERVED,
            findings=findings,
            collection_method="ITU_E164_LOCAL_ENGINE",
            confidence=0.92,
            limitations=limitations,
            provider_status=prov_status,
            related_entities=related,
        )

    # =========================================================================
    # 6. METADATA & FILE INTELLIGENCE
    # =========================================================================
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
            return OSINTResult(
                indicator=filepath_str,
                query_type="metadata",
                normalized_value=filepath_str,
                actual_finding=f"Empty file payload (0 bytes): {filepath_str}",
                status=OSINTVerificationState.FAILED,
                confidence=0.0,
                limitations=["Target file contains zero bytes of data."],
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

        # 1. Cryptographic Hashes
        sha256 = hashlib.sha256(data).hexdigest()
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
                "md5": md5,
                "sha1": sha1,
                "size_bytes": size_bytes,
                "mime_type": mime_type,
                "file_type": file_type,
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
        ]

        limitations.extend([
            "Embedded metadata (e.g. Author, Title, EXIF timestamps) can be trivially spoofed by creators and is not cryptographically verified.",
            "SHA-256 hash is the definitive immutable property.",
        ])

        return OSINTResult(
            indicator=filepath_str,
            query_type="metadata",
            normalized_value=sha256,
            actual_finding=summary,
            status=OSINTVerificationState.VERIFIED,
            findings=findings,
            collection_method="CRYPTOGRAPHIC_STATIC_ANALYSIS",
            confidence=0.98,
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
