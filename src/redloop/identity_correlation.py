"""Unified identity correlation and analyst review for RedLoop.

The engine aggregates typed observations (email, username, phone, domain, IP,
public profile, key, breach, ...) into conservative clusters.  Exact shared
identifiers and explicit correlation keys merge; names or avatar similarity do
not.  Every cluster can be confirmed, rejected, or marked unverified by an
analyst, and each review is persisted with an audit trail.

Classifications mirror the email-footprint engine so the UI can display one
consistent vocabulary:

* ``CONFIRMED_PUBLIC_ASSOCIATION``
* ``STRONG_PUBLIC_MATCH``
* ``POSSIBLE_MATCH``
* ``UNVERIFIED``
* ``NOT_PUBLICLY_VERIFIABLE``
* ``CONFLICTING_EVIDENCE``
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable

CLASSIFICATION_CONFIRMED = "CONFIRMED_PUBLIC_ASSOCIATION"
CLASSIFICATION_STRONG = "STRONG_PUBLIC_MATCH"
CLASSIFICATION_POSSIBLE = "POSSIBLE_MATCH"
CLASSIFICATION_UNVERIFIED = "UNVERIFIED"
CLASSIFICATION_NOT_PUBLIC = "NOT_PUBLICLY_VERIFIABLE"
CLASSIFICATION_CONFLICTING = "CONFLICTING_EVIDENCE"

REVIEW_CONFIRM = "CONFIRM"
REVIEW_REJECT = "REJECT"
REVIEW_UNVERIFIED = "UNVERIFIED"

ALLOWED_CLASSIFICATIONS = {
    CLASSIFICATION_CONFIRMED,
    CLASSIFICATION_STRONG,
    CLASSIFICATION_POSSIBLE,
    CLASSIFICATION_UNVERIFIED,
    CLASSIFICATION_NOT_PUBLIC,
    CLASSIFICATION_CONFLICTING,
}

_ALLOWED_TYPES = {
    "email",
    "username",
    "phone",
    "domain",
    "ip",
    "url",
    "person",
    "organization",
    "public_profile",
    "pgp_key",
    "breach",
    "other",
}

# Names, usernames, and profile images may support a match but must never be
# sufficient on their own to auto-confirm an identity.  At least one direct
# account/contact identifier is required unless an analyst or an explicitly
# authoritative source confirms the cluster.
_CONFIRMING_TYPES = frozenset({"email", "phone", "pgp_key"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS identity_observations (
    observation_id TEXT PRIMARY KEY,
    entity_type    TEXT NOT NULL,
    value          TEXT NOT NULL,
    normalized     TEXT NOT NULL,
    source         TEXT NOT NULL,
    method         TEXT NOT NULL,
    confidence     REAL,
    classification TEXT NOT NULL,
    authoritative  INTEGER NOT NULL DEFAULT 0,
    correlation_key TEXT,
    evidence_hash  TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    metadata       TEXT
);
CREATE INDEX IF NOT EXISTS idx_identity_norm ON identity_observations(normalized);
CREATE INDEX IF NOT EXISTS idx_identity_key  ON identity_observations(correlation_key);

CREATE TABLE IF NOT EXISTS identity_clusters (
    cluster_id     TEXT PRIMARY KEY,
    classification TEXT NOT NULL,
    confidence     REAL,
    review_status  TEXT NOT NULL DEFAULT 'UNREVIEWED',
    reviewed_by    TEXT,
    reviewed_at    TEXT,
    review_note    TEXT,
    member_count   INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_cluster_members (
    cluster_id     TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    PRIMARY KEY (cluster_id, observation_id)
);

CREATE TABLE IF NOT EXISTS identity_reviews (
    review_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id     TEXT NOT NULL,
    decision       TEXT NOT NULL,
    analyst        TEXT NOT NULL,
    note           TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_review_cluster ON identity_reviews(cluster_id);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _normalise_value(entity_type: str, value: str) -> str:
    text = (value or "").strip()
    if entity_type == "email":
        return text.lower()
    if entity_type == "domain":
        return text.lower().rstrip(".")
    if entity_type == "username":
        return text.lower().lstrip("@")
    if entity_type == "phone":
        return re.sub(r"[^\d+]", "", text)
    if entity_type == "ip":
        return text.lower()
    return text


@dataclass
class IdentityObservation:
    entity_type: str
    value: str
    source: str
    method: str
    confidence: float | None = None
    classification: str = CLASSIFICATION_UNVERIFIED
    authoritative: bool = False
    correlation_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)
    observation_id: str = ""
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        self.entity_type = self.entity_type.strip().lower()
        if self.entity_type not in _ALLOWED_TYPES:
            raise ValueError(f"Unsupported identity entity type: {self.entity_type}")
        self.value = self.value.strip()
        if not self.value or len(self.value) > 512:
            raise ValueError("Identity value must be between 1 and 512 characters.")
        if self.classification not in ALLOWED_CLASSIFICATIONS:
            raise ValueError(f"Unsupported identity classification: {self.classification}")
        if self.correlation_key is not None and len(self.correlation_key) > 256:
            raise ValueError("Correlation key must be at most 256 characters.")
        self.normalized = _normalise_value(self.entity_type, self.value)
        if not self.normalized:
            raise ValueError("Identity value normalised to empty.")
        if not self.observation_id:
            self.observation_id = _digest(
                {
                    "type": self.entity_type,
                    "value": self.normalized,
                    "source": self.source,
                    "method": self.method,
                    "observed_at": self.observed_at,
                    "evidence": self.metadata.get("evidence_hash") if isinstance(self.metadata, dict) else None,
                }
            )[:24]
        if not self.evidence_hash:
            self.evidence_hash = self.compute_evidence_hash()

    def _canonical(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "entity_type": self.entity_type,
            "value": self.value,
            "normalized": self.normalized,
            "source": self.source,
            "method": self.method,
            "confidence": self.confidence,
            "classification": self.classification,
            "authoritative": self.authoritative,
            "correlation_key": self.correlation_key,
            "metadata": self.metadata,
        }

    def compute_evidence_hash(self) -> str:
        return _digest(self._canonical())

    def verify_evidence(self) -> bool:
        return bool(self.evidence_hash) and self.evidence_hash == self.compute_evidence_hash()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["normalized"] = self.normalized
        data["evidence_valid"] = self.verify_evidence()
        return data


@dataclass
class IdentityCluster:
    cluster_id: str
    observations: list[IdentityObservation]
    classification: str
    confidence: float | None
    review_status: str = "UNREVIEWED"
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_note: str | None = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "classification": self.classification,
            "confidence": self.confidence,
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "review_note": self.review_note,
            "member_count": len(self.observations),
            "observations": [o.to_dict() for o in self.observations],
            "values": sorted({f"{o.entity_type}:{o.normalized}" for o in self.observations}),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class IdentityCorrelationStore:
    def __init__(self, db_path: str | Path | None = None):
        path = (
            Path(db_path)
            if db_path is not None
            else Path(os.environ.get("REDLOOP_DATA_DIR", "data")) / "identity_correlations.sqlite"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = path
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Observations
    # ------------------------------------------------------------------
    def add_observation(self, observation: IdentityObservation | dict[str, Any]) -> IdentityObservation:
        obs = observation if isinstance(observation, IdentityObservation) else IdentityObservation(**observation)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO identity_observations
                (observation_id, entity_type, value, normalized, source, method, confidence,
                 classification, authoritative, correlation_key, evidence_hash, observed_at, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    obs.observation_id,
                    obs.entity_type,
                    obs.value,
                    obs.normalized,
                    obs.source,
                    obs.method,
                    obs.confidence,
                    obs.classification,
                    1 if obs.authoritative else 0,
                    obs.correlation_key,
                    obs.evidence_hash,
                    obs.observed_at,
                    json.dumps(obs.metadata, default=str, sort_keys=True),
                ),
            )
        return obs

    def _load_observations(self) -> list[IdentityObservation]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM identity_observations ORDER BY observed_at").fetchall()
        observations = []
        for row in rows:
            metadata = {}
            try:
                metadata = json.loads(row["metadata"] or "{}")
            except ValueError:
                metadata = {}
            observations.append(
                IdentityObservation(
                    entity_type=row["entity_type"],
                    value=row["value"],
                    source=row["source"],
                    method=row["method"],
                    confidence=row["confidence"],
                    classification=row["classification"],
                    authoritative=bool(row["authoritative"]),
                    correlation_key=row["correlation_key"],
                    metadata=metadata,
                    observed_at=row["observed_at"],
                    observation_id=row["observation_id"],
                    evidence_hash=row["evidence_hash"],
                )
            )
        return observations

    # ------------------------------------------------------------------
    # Clustering
    # ------------------------------------------------------------------
    @staticmethod
    def _cluster_id(members: Iterable[IdentityObservation]) -> str:
        payload = sorted({f"{o.entity_type}:{o.normalized}" for o in members})
        return _digest({"members": payload})[:20]

    @staticmethod
    def _classify(members: list[IdentityObservation]) -> tuple[str, float | None]:
        if any(o.classification == CLASSIFICATION_CONFLICTING for o in members):
            return CLASSIFICATION_CONFLICTING, None
        confirmed = [o for o in members if o.classification == CLASSIFICATION_CONFIRMED]
        strong = [o for o in members if o.classification == CLASSIFICATION_STRONG]
        possible = [o for o in members if o.classification == CLASSIFICATION_POSSIBLE]
        sources = {o.source for o in confirmed + strong}
        has_confirming_identifier = any(
            o.entity_type in _CONFIRMING_TYPES for o in confirmed + strong
        )
        if confirmed and any(o.authoritative for o in confirmed):
            return CLASSIFICATION_CONFIRMED, _confidence(members, 0.85)
        if has_confirming_identifier and confirmed and len(sources) >= 2:
            return CLASSIFICATION_CONFIRMED, _confidence(members, 0.85)
        if has_confirming_identifier and len(sources) >= 2 and strong:
            return CLASSIFICATION_CONFIRMED, _confidence(members, 0.8)
        if len(sources) >= 2 and (strong or confirmed):
            return CLASSIFICATION_STRONG, _confidence(members, 0.6)
        if strong:
            return CLASSIFICATION_STRONG, _confidence(members, 0.65)
        if possible:
            return CLASSIFICATION_POSSIBLE, _confidence(members, 0.45)
        if len(members) > 1:
            return CLASSIFICATION_UNVERIFIED, _confidence(members, 0.25)
        return CLASSIFICATION_UNVERIFIED, None

    def build_clusters(self) -> list[IdentityCluster]:
        observations = self._load_observations()
        if not observations:
            return []
        parent = list(range(len(observations)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        by_value: dict[str, int] = {}
        by_key: dict[str, int] = {}
        for index, obs in enumerate(observations):
            value_key = f"{obs.entity_type}:{obs.normalized}"
            if value_key in by_value:
                union(by_value[value_key], index)
            else:
                by_value[value_key] = index
            if obs.correlation_key:
                if obs.correlation_key in by_key:
                    union(by_key[obs.correlation_key], index)
                else:
                    by_key[obs.correlation_key] = index

        groups: dict[int, list[IdentityObservation]] = {}
        for index, obs in enumerate(observations):
            groups.setdefault(find(index), []).append(obs)

        clusters: list[IdentityCluster] = []
        with self._conn() as conn:
            for members in groups.values():
                cluster_id = self._cluster_id(members)
                classification, confidence = self._classify(members)
                previous = conn.execute(
                    "SELECT * FROM identity_clusters WHERE cluster_id = ?", (cluster_id,)
                ).fetchone()
                review_status = previous["review_status"] if previous else "UNREVIEWED"
                reviewed_by = previous["reviewed_by"] if previous else None
                reviewed_at = previous["reviewed_at"] if previous else None
                review_note = previous["review_note"] if previous else None
                if review_status == "CONFIRMED":
                    classification = CLASSIFICATION_CONFIRMED
                    confidence = max(confidence or 0.0, 0.95)
                elif review_status == "REJECTED":
                    classification = CLASSIFICATION_UNVERIFIED
                    confidence = None
                elif review_status == "UNVERIFIED":
                    classification = CLASSIFICATION_UNVERIFIED
                    confidence = None
                created_at = previous["created_at"] if previous else _utc_now()
                now = _utc_now()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO identity_clusters
                    (cluster_id, classification, confidence, review_status, reviewed_by,
                     reviewed_at, review_note, member_count, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        cluster_id,
                        classification,
                        confidence,
                        review_status,
                        reviewed_by,
                        reviewed_at,
                        review_note,
                        len(members),
                        created_at,
                        now,
                    ),
                )
                conn.execute(
                    "DELETE FROM identity_cluster_members WHERE cluster_id = ?", (cluster_id,)
                )
                for obs in members:
                    conn.execute(
                        "INSERT OR REPLACE INTO identity_cluster_members (cluster_id, observation_id) VALUES (?,?)",
                        (cluster_id, obs.observation_id),
                    )
                clusters.append(
                    IdentityCluster(
                        cluster_id=cluster_id,
                        observations=members,
                        classification=classification,
                        confidence=confidence,
                        review_status=review_status,
                        reviewed_by=reviewed_by,
                        reviewed_at=reviewed_at,
                        review_note=review_note,
                        created_at=created_at,
                        updated_at=now,
                    )
                )
        return sorted(clusters, key=lambda c: (-len(c.observations), c.cluster_id))

    # ------------------------------------------------------------------
    # Review
    # ------------------------------------------------------------------
    def review(
        self,
        cluster_id: str,
        decision: str,
        analyst: str,
        note: str | None = None,
        *,
        audit: Any = None,
    ) -> dict[str, Any]:
        decision = decision.strip().upper()
        mapping = {
            REVIEW_CONFIRM: "CONFIRMED",
            REVIEW_REJECT: "REJECTED",
            REVIEW_UNVERIFIED: "UNVERIFIED",
        }
        if decision not in mapping:
            raise ValueError("Decision must be CONFIRM, REJECT, or UNVERIFIED.")
        analyst = (analyst or "").strip()
        if not analyst:
            raise ValueError("Analyst name is required for review.")
        note = (note or "").strip()[:2000] or None
        with self._conn() as conn:
            cluster = conn.execute(
                "SELECT * FROM identity_clusters WHERE cluster_id = ?", (cluster_id,)
            ).fetchone()
            if not cluster:
                raise KeyError(f"Unknown identity cluster: {cluster_id}")
            now = _utc_now()
            review_status = mapping[decision]
            conn.execute(
                """
                UPDATE identity_clusters
                SET review_status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ?, updated_at = ?
                WHERE cluster_id = ?
                """,
                (review_status, analyst, now, note, now, cluster_id),
            )
            conn.execute(
                """
                INSERT INTO identity_reviews (cluster_id, decision, analyst, note, created_at)
                VALUES (?,?,?,?,?)
                """,
                (cluster_id, decision, analyst, note, now),
            )
            if review_status == "CONFIRMED":
                new_classification = CLASSIFICATION_CONFIRMED
                new_confidence = max(float(cluster["confidence"] or 0.0), 0.95)
            elif review_status == "REJECTED":
                new_classification = CLASSIFICATION_UNVERIFIED
                new_confidence = None
            else:
                new_classification = CLASSIFICATION_UNVERIFIED
                new_confidence = None
            conn.execute(
                "UPDATE identity_clusters SET classification = ?, confidence = ? WHERE cluster_id = ?",
                (new_classification, new_confidence, cluster_id),
            )
        if audit is not None:
            audit.log(
                cluster_id,
                "identity_cluster_review",
                "identity",
                "success",
                decision=decision,
                analyst=analyst,
                note=note,
            )
        result = self.get_cluster(cluster_id)
        if result is None:
            raise KeyError(cluster_id)
        return result

    def get_cluster(self, cluster_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM identity_clusters WHERE cluster_id = ?", (cluster_id,)
            ).fetchone()
            if not row:
                return None
            member_rows = conn.execute(
                """
                SELECT o.* FROM identity_observations o
                JOIN identity_cluster_members m ON m.observation_id = o.observation_id
                WHERE m.cluster_id = ?
                ORDER BY o.observed_at
                """,
                (cluster_id,),
            ).fetchall()
            reviews = conn.execute(
                "SELECT decision, analyst, note, created_at FROM identity_reviews WHERE cluster_id = ? ORDER BY review_id",
                (cluster_id,),
            ).fetchall()
        observations = []
        for member in member_rows:
            try:
                metadata = json.loads(member["metadata"] or "{}")
            except ValueError:
                metadata = {}
            observations.append(
                {
                    "observation_id": member["observation_id"],
                    "entity_type": member["entity_type"],
                    "value": member["value"],
                    "normalized": member["normalized"],
                    "source": member["source"],
                    "method": member["method"],
                    "confidence": member["confidence"],
                    "classification": member["classification"],
                    "authoritative": bool(member["authoritative"]),
                    "correlation_key": member["correlation_key"],
                    "evidence_hash": member["evidence_hash"],
                    "observed_at": member["observed_at"],
                    "metadata": metadata,
                }
            )
        return {
            "cluster_id": row["cluster_id"],
            "classification": row["classification"],
            "confidence": row["confidence"],
            "review_status": row["review_status"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "review_note": row["review_note"],
            "member_count": row["member_count"],
            "observations": observations,
            "values": sorted({f"{o['entity_type']}:{o['normalized']}" for o in observations}),
            "reviews": [dict(r) for r in reviews],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_clusters(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT cluster_id FROM identity_clusters ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        clusters = [self.get_cluster(row["cluster_id"]) for row in rows]
        return [c for c in clusters if c is not None]

    def list_reviews(self, cluster_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM identity_reviews"
        params: list[Any] = []
        if cluster_id:
            query += " WHERE cluster_id = ?"
            params.append(cluster_id)
        query += " ORDER BY review_id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def _confidence(members: list[IdentityObservation], floor: float) -> float:
    values = [float(o.confidence) for o in members if isinstance(o.confidence, (int, float))]
    if not values:
        return floor
    return round(max(floor, min(0.95, max(values))), 4)


_default_store: IdentityCorrelationStore | None = None


def get_identity_correlation_store(db_path: str | Path | None = None) -> IdentityCorrelationStore:
    global _default_store
    if db_path is not None:
        return IdentityCorrelationStore(db_path)
    if _default_store is None:
        _default_store = IdentityCorrelationStore()
    return _default_store


__all__ = [
    "CLASSIFICATION_CONFIRMED",
    "CLASSIFICATION_CONFLICTING",
    "CLASSIFICATION_NOT_PUBLIC",
    "CLASSIFICATION_POSSIBLE",
    "CLASSIFICATION_STRONG",
    "CLASSIFICATION_UNVERIFIED",
    "IdentityCluster",
    "IdentityCorrelationStore",
    "IdentityObservation",
    "REVIEW_CONFIRM",
    "REVIEW_REJECT",
    "REVIEW_UNVERIFIED",
    "get_identity_correlation_store",
]
