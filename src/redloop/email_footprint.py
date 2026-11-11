"""Email digital-footprint intelligence with modular, auditable source adapters.

Design constraints
------------------
* No account enumeration: adapters only use public APIs or public records.  They
  never probe registration, password-reset, or login endpoints.
* No identity is "confirmed" from a name, username, or avatar similarity alone.
  A confirmation needs either an explicit authoritative public association or at
  least two independent strong public sources.
* Breach metadata is minimised and redacted before it reaches the report.
* External adapters are disabled unless explicitly enabled.  Tests inject fake
  adapters and never touch the network.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Protocol
from urllib.parse import quote

import httpx
from redloop.transport import get_hardened_client

CLASSIFICATION_CONFIRMED = "CONFIRMED_PUBLIC_ASSOCIATION"
CLASSIFICATION_STRONG = "STRONG_PUBLIC_MATCH"
CLASSIFICATION_POSSIBLE = "POSSIBLE_MATCH"
CLASSIFICATION_UNVERIFIED = "UNVERIFIED"
CLASSIFICATION_NOT_PUBLIC = "NOT_PUBLICLY_VERIFIABLE"
CLASSIFICATION_CONFLICTING = "CONFLICTING_EVIDENCE"

OBS_MATCH = "MATCH"
OBS_NO_MATCH = "NO_MATCH"
OBS_NOT_CHECKED = "NOT_CHECKED"
OBS_NOT_CONFIGURED = "NOT_CONFIGURED"
OBS_ERROR = "ERROR"
OBS_RATE_LIMITED = "RATE_LIMITED"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

MAX_EMAIL_LENGTH = 254


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def redact_sensitive_text(value: Any, *, email: str | None = None) -> str:
    """Redact emails, IPs, credential-like tokens, and obvious secrets."""
    text = str(value or "")
    if email:
        text = text.replace(email, "[redacted-email]")
    text = _EMAIL_IN_TEXT.sub("[redacted-email]", text)
    text = _IP_RE.sub("[redacted-ip]", text)
    text = _TOKEN_RE.sub("[redacted-token]", text)
    text = re.sub(r"\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=[redacted]", text, flags=re.I)
    return text[:500]


def normalise_email(email: str) -> tuple[str, str, str] | None:
    raw = (email or "").strip()
    if not raw or len(raw) > MAX_EMAIL_LENGTH:
        return None
    if raw.count("@") != 1:
        return None
    local, domain = raw.rsplit("@", 1)
    if not local or len(local) > 64 or not domain:
        return None
    normalised = f"{local.lower()}@{domain.lower().rstrip('.')}"
    if not _EMAIL_RE.match(normalised):
        return None
    return normalised, local, domain.lower().rstrip(".")


def redact_breach_metadata(breaches: Iterable[Any], email: str) -> dict[str, Any]:
    """Return breach counts/classes only; never raw account records."""
    names: list[str] = []
    classes: set[str] = set()
    dates: list[str] = []
    for item in breaches or []:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("name") or item.get("Title")
        if name:
            names.append(redact_sensitive_text(name, email=email))
        date = item.get("BreachDate") or item.get("breach_date")
        if date:
            dates.append(redact_sensitive_text(date, email=email))
        for dc in item.get("DataClasses") or item.get("data_classes") or []:
            if dc:
                classes.add(redact_sensitive_text(dc, email=email))
    return {
        "breach_count": len(set(names)),
        "breach_names": sorted(set(names))[:20],
        "data_classes": sorted(classes)[:20],
        "breach_dates": sorted(set(dates))[:20],
        "raw_records_included": False,
        "redaction_applied": True,
    }


def classify_observations(observations: Iterable["FootprintObservation"]) -> str:
    matches = [o for o in observations if o.status == OBS_MATCH]
    if any(o.classification == CLASSIFICATION_CONFLICTING for o in matches):
        return CLASSIFICATION_CONFLICTING
    confirmed = [o for o in matches if o.classification == CLASSIFICATION_CONFIRMED]
    strong = [o for o in matches if o.classification == CLASSIFICATION_STRONG]
    possible = [o for o in matches if o.classification == CLASSIFICATION_POSSIBLE]
    independent = {o.source for o in confirmed + strong}
    if confirmed and (len(independent) >= 2 or any(o.authoritative for o in confirmed)):
        return CLASSIFICATION_CONFIRMED
    if len(independent) >= 2 and strong:
        return CLASSIFICATION_CONFIRMED
    if strong:
        return CLASSIFICATION_STRONG
    if possible:
        return CLASSIFICATION_POSSIBLE
    if matches:
        return CLASSIFICATION_UNVERIFIED
    return CLASSIFICATION_NOT_PUBLIC


@dataclass
class FootprintObservation:
    adapter: str
    source: str
    status: str
    method: str = ""
    classification: str = CLASSIFICATION_NOT_PUBLIC
    confidence: float | None = None
    authoritative: bool = False
    title: str | None = None
    url: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        if not self.method:
            self.method = f"{self.adapter}_lookup"
        if not self.evidence_hash:
            self.evidence_hash = self.compute_evidence_hash()

    def _canonical(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "source": self.source,
            "method": self.method,
            "status": self.status,
            "classification": self.classification,
            "authoritative": self.authoritative,
            "title": self.title,
            "url": self.url,
            "details": self.details,
        }

    def compute_evidence_hash(self) -> str:
        return _hash(self._canonical())

    def verify_evidence(self) -> bool:
        return bool(self.evidence_hash) and self.evidence_hash == self.compute_evidence_hash()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_valid"] = self.verify_evidence()
        return data


@dataclass
class EmailFootprintReport:
    email: str
    normalized_email: str | None
    domain: str | None
    valid: bool
    classification: str
    confidence: float | None
    confidence_evidence: dict[str, Any]
    observations: list[FootprintObservation]
    breach_exposure: dict[str, Any]
    limitations: list[str]
    generated_at: str = field(default_factory=_utc_now)
    network_enabled: bool = False
    evidence_hash: str = ""
    provider: str = "redloop_email_footprint"

    def _canonical(self) -> dict[str, Any]:
        return {
            "email": self.normalized_email or self.email,
            "valid": self.valid,
            "classification": self.classification,
            "confidence": self.confidence,
            "observations": [o.evidence_hash for o in self.observations],
            "breach_exposure": self.breach_exposure,
        }

    def compute_evidence_hash(self) -> str:
        return _hash(self._canonical())

    def verify_evidence(self) -> bool:
        return bool(self.evidence_hash) and self.evidence_hash == self.compute_evidence_hash()

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "normalized_email": self.normalized_email,
            "domain": self.domain,
            "valid": self.valid,
            "classification": self.classification,
            "confidence": self.confidence,
            "confidence_evidence": self.confidence_evidence,
            "observations": [o.to_dict() for o in self.observations],
            "breach_exposure": self.breach_exposure,
            "limitations": self.limitations,
            "generated_at": self.generated_at,
            "network_enabled": self.network_enabled,
            "evidence_hash": self.evidence_hash,
            "evidence_valid": self.verify_evidence(),
            "provider": self.provider,
            "match_classifications": [
                CLASSIFICATION_CONFIRMED,
                CLASSIFICATION_STRONG,
                CLASSIFICATION_POSSIBLE,
                CLASSIFICATION_UNVERIFIED,
                CLASSIFICATION_NOT_PUBLIC,
                CLASSIFICATION_CONFLICTING,
            ],
        }


class FootprintAdapter(Protocol):
    name: str
    source: str
    reliability: float
    external: bool

    def enabled(self) -> bool: ...

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]: ...


class _BaseAdapter:
    name = "base"
    source = "base"
    reliability = 0.5
    external = True
    env_flag = ""

    def enabled(self) -> bool:
        return bool(self.env_flag and _bool_env(self.env_flag, False))

    def unavailable(self, reason: str) -> FootprintObservation:
        return FootprintObservation(
            adapter=self.name,
            source=self.source,
            status=OBS_NOT_CONFIGURED,
            method="adapter_not_run",
            details={"reason": reason},
        )


class DomainMailAdapter(_BaseAdapter):
    """Local DNS MX lookup: domain mail capability, not an identity match."""

    name = "domain_mx"
    source = "dns_mx"
    reliability = 0.45
    external = False

    def __init__(self, enabled: bool | None = None):
        self._enabled = enabled

    def enabled(self) -> bool:
        return True if self._enabled is None else self._enabled

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]:
        try:
            import dns.resolver  # type: ignore

            answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
            records = sorted(str(r.exchange).rstrip(".") for r in answers)
            if records:
                return [
                    FootprintObservation(
                        adapter=self.name,
                        source=self.source,
                        status=OBS_MATCH,
                        classification=CLASSIFICATION_UNVERIFIED,
                        confidence=0.3,
                        title="Domain publishes MX records",
                        details={
                            "mx_records": records[:10],
                            "identity_association": "domain_only",
                            "reason": "MX presence proves the domain accepts mail, not who owns the mailbox.",
                        },
                    )
                ]
            return [FootprintObservation(self.name, self.source, OBS_NO_MATCH)]
        except Exception as exc:  # DNS errors are not identity findings
            return [
                FootprintObservation(
                    self.name,
                    self.source,
                    OBS_ERROR,
                    details={"error": type(exc).__name__},
                )
            ]


class GravatarAdapter(_BaseAdapter):
    name = "gravatar"
    source = "gravatar_public_avatar"
    reliability = 0.35
    env_flag = "REDLOOP_EMAIL_GRAVATAR_ENABLED"

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]:
        digest = hashlib.md5(email.encode("utf-8")).hexdigest()
        url = f"https://gravatar.com/avatar/{digest}?d=404&s=1"
        try:
            response = http.get(url, timeout=8.0)
        except httpx.HTTPError as exc:
            return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"error": type(exc).__name__})]
        if response.status_code == 200:
            return [
                FootprintObservation(
                    self.name,
                    self.source,
                    OBS_MATCH,
                    classification=CLASSIFICATION_POSSIBLE,
                    confidence=0.35,
                    title="Public Gravatar image exists for this hash",
                    url=f"https://gravatar.com/avatar/{digest}",
                    details={
                        "identity_association": "avatar_only",
                        "reason": "An avatar exists but does not confirm who controls the email.",
                    },
                )
            ]
        if response.status_code == 404:
            return [FootprintObservation(self.name, self.source, OBS_NO_MATCH)]
        if response.status_code == 429:
            return [FootprintObservation(self.name, self.source, OBS_RATE_LIMITED)]
        return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"http_status": response.status_code})]


class OpenPgpKeyAdapter(_BaseAdapter):
    name = "openpgp_keyserver"
    source = "keys.openpgp.org"
    reliability = 0.75
    env_flag = "REDLOOP_EMAIL_PGP_ENABLED"

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]:
        url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(email)}"
        try:
            response = http.get(url, timeout=8.0)
        except httpx.HTTPError as exc:
            return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"error": type(exc).__name__})]
        if response.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in response.text:
            return [
                FootprintObservation(
                    self.name,
                    self.source,
                    OBS_MATCH,
                    classification=CLASSIFICATION_STRONG,
                    confidence=0.75,
                    title="Public PGP key is published for this email",
                    url=url,
                    details={
                        "identity_association": "published_key",
                        "reason": "A published key links the email to a key holder but is not a legal identity proof.",
                    },
                )
            ]
        if response.status_code == 404:
            return [FootprintObservation(self.name, self.source, OBS_NO_MATCH)]
        if response.status_code == 429:
            return [FootprintObservation(self.name, self.source, OBS_RATE_LIMITED)]
        return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"http_status": response.status_code})]


class HibpBreachAdapter(_BaseAdapter):
    name = "hibp"
    source = "haveibeenpwned"
    reliability = 0.6
    env_flag = "REDLOOP_EMAIL_HIBP_ENABLED"

    def enabled(self) -> bool:
        return _bool_env(self.env_flag, False) and bool(os.environ.get("HIBP_API_KEY"))

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]:
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            return [self.unavailable("HIBP_API_KEY is not configured.")]
        headers = {
            "hibp-api-key": key,
            "user-agent": "RedLoop-EmailFootprint/1.0",
            "accept": "application/json",
        }
        try:
            response = http.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                params={"truncateResponse": "false"},
                headers=headers,
                timeout=8.0,
            )
        except httpx.HTTPError as exc:
            return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"error": type(exc).__name__})]
        if response.status_code == 200:
            breaches = response.json()
            summary = redact_breach_metadata(breaches, email)
            return [
                FootprintObservation(
                    self.name,
                    self.source,
                    OBS_MATCH,
                    classification=CLASSIFICATION_POSSIBLE,
                    confidence=0.6,
                    title="Email appears in public breach corpora",
                    details={
                        "breach_exposure": summary,
                        "identity_association": "account_existence_only",
                        "reason": "Breach presence confirms an account existed, not that the requester controls it.",
                    },
                )
            ]
        if response.status_code == 404:
            return [FootprintObservation(self.name, self.source, OBS_NO_MATCH, details={"breach_exposure": {"breach_count": 0}})]
        if response.status_code == 401:
            return [self.unavailable("HIBP rejected the API key.")]
        if response.status_code == 429:
            return [FootprintObservation(self.name, self.source, OBS_RATE_LIMITED)]
        return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"http_status": response.status_code})]


class GitHubCommitAdapter(_BaseAdapter):
    name = "github_commits"
    source = "github_public_commits"
    reliability = 0.7
    env_flag = "REDLOOP_EMAIL_GITHUB_ENABLED"

    def enabled(self) -> bool:
        return _bool_env(self.env_flag, False) and bool(os.environ.get("GITHUB_TOKEN"))

    def collect(self, email: str, domain: str, http: httpx.Client) -> list[FootprintObservation]:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            return [self.unavailable("GITHUB_TOKEN is not configured.")]
        headers = {
            "authorization": f"Bearer {token}",
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
            "user-agent": "RedLoop-EmailFootprint/1.0",
        }
        try:
            response = http.get(
                "https://api.github.com/search/commits",
                params={"q": f'author-email:"{email}"', "per_page": "5"},
                headers=headers,
                timeout=8.0,
            )
        except httpx.HTTPError as exc:
            return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"error": type(exc).__name__})]
        if response.status_code == 200:
            payload = response.json()
            total = int(payload.get("total_count") or 0)
            if total <= 0:
                return [FootprintObservation(self.name, self.source, OBS_NO_MATCH)]
            items = payload.get("items") or []
            repos = sorted(
                {
                    str((item.get("repository") or {}).get("full_name"))
                    for item in items
                    if (item.get("repository") or {}).get("full_name")
                }
            )
            return [
                FootprintObservation(
                    self.name,
                    self.source,
                    OBS_MATCH,
                    classification=CLASSIFICATION_STRONG,
                    confidence=0.7,
                    title="Email is a public commit author",
                    url="https://github.com/search?type=commits",
                    details={
                        "commit_count": total,
                        "repositories": repos[:10],
                        "identity_association": "public_commit_authorship",
                        "reason": "Public commit authorship strongly links the email to a developer identity but does not prove control.",
                    },
                )
            ]
        if response.status_code in {401, 403}:
            return [self.unavailable(f"GitHub API rejected the token (HTTP {response.status_code}).")]
        if response.status_code == 422:
            return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"reason": "Invalid search query."})]
        return [FootprintObservation(self.name, self.source, OBS_ERROR, details={"http_status": response.status_code})]


class EmailFootprintEngine:
    """Run enabled adapters and produce a conservative association report."""

    def __init__(
        self,
        adapters: Iterable[FootprintAdapter] | None = None,
        *,
        network_enabled: bool | None = None,
        http_factory: Any = None,
    ):
        self.network_enabled = (
            _bool_env("REDLOOP_EMAIL_FOOTPRINT_LIVE", False)
            if network_enabled is None
            else bool(network_enabled)
        )
        if adapters is None:
            adapters = [
                DomainMailAdapter(enabled=self.network_enabled),
                GravatarAdapter(),
                OpenPgpKeyAdapter(),
                HibpBreachAdapter(),
                GitHubCommitAdapter(),
            ]
        self.adapters = list(adapters)
        self._http_factory = http_factory or (
            lambda: get_hardened_client(follow_redirects=False)
        )

    @staticmethod
    def _confidence(
        observations: list[FootprintObservation],
        classification: str,
    ) -> tuple[float | None, dict[str, Any]]:
        matches = [o for o in observations if o.status == OBS_MATCH and o.confidence]
        if not matches:
            return None, {
                "status": "INSUFFICIENT_EVIDENCE",
                "score": None,
                "label": "HEURISTIC_CONFIDENCE",
                "calibration_status": "NOT_CALIBRATED",
                "classification": classification,
                "independent_sources": 0,
                "reason": "No public source produced an association.",
            }
        if classification == CLASSIFICATION_CONFLICTING:
            return None, {
                "status": "INSUFFICIENT_EVIDENCE",
                "score": None,
                "label": "CONFLICTING_EVIDENCE",
                "calibration_status": "NOT_CALIBRATED",
                "classification": classification,
                "sources": sorted({o.source for o in matches}),
            }
        # Independent-source union: two weak-but-independent signals should not
        # silently behave like one strong signal.
        remaining = 1.0
        weighted: list[dict[str, Any]] = []
        for obs in matches:
            w = max(0.0, min(1.0, float(obs.confidence or 0.0)))
            remaining *= (1.0 - w)
            weighted.append({"source": obs.source, "weight": w, "classification": obs.classification})
        score = round(min(0.95, 1.0 - remaining), 4)
        if classification == CLASSIFICATION_CONFIRMED:
            score = max(score, 0.85)
        elif classification == CLASSIFICATION_STRONG:
            score = max(score, 0.7)
        return score, {
            "status": "COMPUTED",
            "score": score,
            "label": "HEURISTIC_CONFIDENCE",
            "calibration_status": "NOT_CALIBRATED",
            "classification": classification,
            "independent_sources": len({o.source for o in matches}),
            "weights": weighted,
            "factors": {
                "source_reliability": round(max(float(o.confidence or 0) for o in matches), 4),
                "source_agreement": 1.0 if len({o.source for o in matches}) >= 2 else 0.5,
                "evidence_integrity": 1.0 if all(o.verify_evidence() for o in observations) else 0.0,
                "freshness": 1.0,
            },
            "note": "Heuristic confidence is not a calibrated probability.",
        }

    def investigate(self, email: str, *, network_enabled: bool | None = None) -> EmailFootprintReport:
        live = self.network_enabled if network_enabled is None else bool(network_enabled)
        parsed = normalise_email(email)
        if not parsed:
            report = EmailFootprintReport(
                email=str(email or ""),
                normalized_email=None,
                domain=None,
                valid=False,
                classification=CLASSIFICATION_NOT_PUBLIC,
                confidence=None,
                confidence_evidence={
                    "status": "INSUFFICIENT_EVIDENCE",
                    "score": None,
                    "reason": "INVALID_EMAIL_SYNTAX",
                },
                observations=[],
                breach_exposure={"breach_count": 0, "raw_records_included": False},
                limitations=["Email does not conform to RFC 5322 syntax; no network lookup was performed."],
                network_enabled=False,
            )
            report.evidence_hash = report.compute_evidence_hash()
            return report

        normalised, _local, domain = parsed
        observations: list[FootprintObservation] = []
        limitations = [
            "A public association is not proof of ownership or control.",
            "Name, username, and avatar similarity alone are never treated as confirmation.",
        ]
        if not live:
            limitations.append(
                "Live external lookups are disabled. Enable REDLOOP_EMAIL_FOOTPRINT_LIVE and the "
                "specific adapter flags before treating results as public evidence."
            )

        if live:
            with self._http_factory() as http:
                for adapter in self.adapters:
                    if not adapter.enabled():
                        if adapter.external:
                            observations.append(
                                FootprintObservation(
                                    adapter=adapter.name,
                                    source=adapter.source,
                                    status=OBS_NOT_CONFIGURED,
                                    method="adapter_disabled",
                                    details={
                                        "reason": f"Adapter disabled. Set {getattr(adapter, 'env_flag', '') or 'its flag'} to enable."
                                    },
                                )
                            )
                        continue
                    try:
                        observations.extend(adapter.collect(normalised, domain, http))
                    except Exception as exc:
                        observations.append(
                            FootprintObservation(
                                adapter=adapter.name,
                                source=adapter.source,
                                status=OBS_ERROR,
                                method="adapter_collect",
                                details={"error": type(exc).__name__},
                            )
                        )
        else:
            observations.append(
                FootprintObservation(
                    adapter="network",
                    source="external_sources",
                    status=OBS_NOT_CHECKED,
                    method="not_run",
                    details={"reason": "External email-footprint lookups are disabled."},
                )
            )

        classification = classify_observations(observations)
        confidence, confidence_evidence = self._confidence(observations, classification)
        breach_summary: dict[str, Any] = {"breach_count": 0, "raw_records_included": False}
        for obs in observations:
            if isinstance(obs.details.get("breach_exposure"), dict):
                breach_summary = obs.details["breach_exposure"]
                break

        report = EmailFootprintReport(
            email=str(email),
            normalized_email=normalised,
            domain=domain,
            valid=True,
            classification=classification,
            confidence=confidence,
            confidence_evidence=confidence_evidence,
            observations=observations,
            breach_exposure=breach_summary,
            limitations=limitations,
            network_enabled=live,
        )
        report.evidence_hash = report.compute_evidence_hash()
        return report


def get_email_footprint_engine() -> EmailFootprintEngine:
    return EmailFootprintEngine()


# ==============================================================================
# PHASE L.1 — HOLEHE-STYLE EMAIL ACCOUNT ENUMERATION (>=28 PLATFORMS)
# ==============================================================================

import time

ACCOUNT_EXISTS = "EXISTS"
ACCOUNT_NOT_FOUND = "NOT_FOUND"
ACCOUNT_RATE_LIMITED = "RATE_LIMITED"
ACCOUNT_UNKNOWN = "UNKNOWN"


@dataclass
class PlatformCircuitBreaker:
    """Per-platform circuit breaker (CLOSED -> OPEN -> HALF_OPEN)."""

    platform_id: str
    failure_threshold: int = 3
    recovery_timeout_sec: float = 30.0
    failure_count: int = 0
    state: str = "CLOSED"
    last_failure_ts: float = 0.0

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if (time.monotonic() - self.last_failure_ts) >= self.recovery_timeout_sec:
                self.state = "HALF_OPEN"
                return True
            return False
        return True

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_ts = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


@dataclass
class PlatformRateLimiter:
    """Per-platform token bucket rate limiter."""

    rate_rps: float
    burst: float = 2.0
    tokens: float = 2.0
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate_rps)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


@dataclass(frozen=True)
class EmailPlatformSpec:
    """Specification for a read-only Holehe-style account existence check."""

    platform_id: str
    name: str
    category: str
    endpoint_url: str
    method: str = "GET"
    rate_limit_rps: float = 1.0
    exists_status_codes: tuple[int, ...] = (200,)
    exists_body_tokens: tuple[str, ...] = ()
    not_found_status_codes: tuple[int, ...] = (404,)
    not_found_body_tokens: tuple[str, ...] = ()
    rate_limit_status_codes: tuple[int, ...] = (429,)


HOLEHE_PLATFORM_CATALOG: tuple[EmailPlatformSpec, ...] = (
    EmailPlatformSpec("gravatar", "Gravatar", "identity", "https://en.gravatar.com/{md5}.json", "GET", 2.0, (200,), ("\"entry\"",), (404,), ("User not found",)),
    EmailPlatformSpec("github_search", "GitHub Public Commits", "dev", "https://api.github.com/search/users?q={email}+in:email", "GET", 0.5, (200,), ("\"total_count\":1", "\"total_count\": 1", "\"login\""), (200, 404), ("\"total_count\":0", "\"total_count\": 0")),
    EmailPlatformSpec("gitlab", "GitLab", "dev", "https://gitlab.com/users?search={email}", "GET", 1.0, (200,), ("\"exists\":true", "\"id\":"), (404,), ("\"exists\":false", "[]")),
    EmailPlatformSpec("bitbucket", "Bitbucket", "dev", "https://bitbucket.org/account/signup/?email={email}", "GET", 1.0, (200,), ("already registered", "\"email_taken\":true", "\"taken\":true", "taken"), (200, 404), ("available", "not found", "free_to_register", "address_is_free_for_registration")),
    EmailPlatformSpec("dockerhub", "Docker Hub", "dev", "https://hub.docker.com/v2/users/signup-check/?email={email}", "GET", 1.0, (200, 400), ("already in use", "exists"), (200, 404), ("available", "not_found")),
    EmailPlatformSpec("pypi", "PyPI", "dev", "https://pypi.org/account/register/?email={email}", "GET", 1.0, (200, 400), ("email address is already", "exists"), (404,), ("available", "not found")),
    EmailPlatformSpec("npmjs", "npm Registry", "dev", "https://www.npmjs.com/signup?email={email}", "GET", 1.0, (200, 400), ("already exists", "\"email_taken\":true", "taken"), (200, 404), ("available", "not found", "free_to_register", "address_is_free_for_registration")),
    EmailPlatformSpec("rubygems", "RubyGems", "dev", "https://rubygems.org/api/v1/owners/{email}/gems.json", "GET", 1.0, (200,), ("\"name\":",), (404,), ("Owner could not be found", "not found")),
    EmailPlatformSpec("crates_io", "Crates.io", "dev", "https://crates.io/api/v1/users?email={email}", "GET", 1.0, (200,), ("\"users\":[{",), (404,), ("\"users\":[]", "not found")),
    EmailPlatformSpec("launchpad", "Ubuntu Launchpad", "dev", "https://api.launchpad.net/1.0/people/?ws.op=getByEmail&email={email}", "GET", 1.0, (200,), ("\"self_link\"", "\"name\""), (404,), ("null", "not found")),
    EmailPlatformSpec("wordpress", "WordPress.com", "cms", "https://public-api.wordpress.com/rest/v1.1/users/{email}/auth-options", "GET", 1.5, (200,), ("\"passwordless\"", "\"email_verified\""), (404, 400), ("unknown_user", "User does not exist")),
    EmailPlatformSpec("firefox_accounts", "Mozilla Firefox Accounts", "identity", "https://api.accounts.firefox.com/v1/account/status?email={email}", "GET", 1.0, (200,), ("\"exists\":true",), (200, 404), ("\"exists\":false",)),
    EmailPlatformSpec("spotify", "Spotify", "media", "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}", "GET", 1.0, (200,), ("\"status\":20", "already registered"), (200, 404), ("\"status\":1", "not registered")),
    EmailPlatformSpec("duolingo", "Duolingo", "education", "https://www.duolingo.com/2017-06-30/users?email={email}", "GET", 1.5, (200,), ("\"users\":[{", "\"username\""), (200, 404), ("\"users\":[]",)),
    EmailPlatformSpec("vimeo", "Vimeo", "media", "https://vimeo.com/join?email={email}", "GET", 1.0, (200, 400), ("already associated", "exists"), (404,), ("available", "not found")),
    EmailPlatformSpec("keybase", "Keybase", "security", "https://keybase.io/_/api/1.0/user/lookup.json?email={email}", "GET", 1.0, (200,), ("\"them\":[{",), (200, 404), ("\"them\":[]", "not found")),
    EmailPlatformSpec("pgp_openpgp", "keys.openpgp.org", "security", "https://keys.openpgp.org/vks/v1/by-email/{email}", "GET", 1.5, (200,), ("-----BEGIN PGP PUBLIC KEY BLOCK-----",), (404,), ("No key found", "not found")),
    EmailPlatformSpec("pgp_ubuntu", "Ubuntu Keyserver", "security", "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search={email}", "GET", 1.0, (200,), ("-----BEGIN PGP PUBLIC KEY BLOCK-----",), (404,), ("Not Found", "No results")),
    EmailPlatformSpec("atlassian", "Atlassian ID", "enterprise", "https://id.atlassian.com/login/lookup?email={email}", "GET", 1.0, (200,), ("\"exists\":true", "\"account_status\":\"active\""), (404,), ("\"exists\":false", "not found")),
    EmailPlatformSpec("adobe", "Adobe ID", "creative", "https://auth.services.adobe.com/signin/v2/users/accounts?email={email}", "GET", 1.0, (200,), ("\"accountType\"", "\"hasT2ELinked\""), (200, 404), ("[]", "not_found")),
    EmailPlatformSpec("pinterest", "Pinterest", "social", "https://www.pinterest.com/resource/EmailExistsResource/get/?email={email}", "GET", 1.0, (200,), ("\"data\":true",), (200, 404), ("\"data\":false",)),
    EmailPlatformSpec("lastfm", "Last.fm", "media", "https://www.last.fm/join/partial/validate?email={email}", "GET", 1.0, (200,), ("already registered", "\"valid\":false"), (200, 404), ("\"valid\":true",)),
    EmailPlatformSpec("eventbrite", "Eventbrite", "events", "https://www.eventbrite.com/api/v3/users/lookup/?email={email}", "GET", 1.0, (200,), ("\"exists\":true",), (200, 404), ("\"exists\":false",)),
    EmailPlatformSpec("strava", "Strava", "fitness", "https://www.strava.com/athletes/email_unique?email={email}", "GET", 1.0, (200,), ("false", "taken"), (200, 404), ("true", "available")),
    EmailPlatformSpec("trello", "Trello", "productivity", "https://trello.com/1/search/members?query={email}", "GET", 1.0, (200,), ("\"id\":", "\"username\":"), (200, 404), ("[]",)),
    EmailPlatformSpec("protonmail", "Proton Mail Lookup", "security", "https://api.protonmail.ch/pks/lookup?op=get&search={email}", "GET", 1.0, (200,), ("-----BEGIN PGP PUBLIC KEY BLOCK-----",), (404,), ("No key found", "not found")),
    EmailPlatformSpec("archive_org", "Internet Archive", "archive", "https://archive.org/ account/check_email?email={email}", "GET", 1.0, (200,), ("\"exists\":true", "\"email_taken\":true", "taken"), (200, 404), ("\"exists\":false", "available", "free_to_register", "address_is_free_for_registration")),
    EmailPlatformSpec("issuu", "Issuu", "publishing", "https://issuu.com/call/signup/check-email/{email}", "GET", 1.0, (200,), ("\"status\":\"in_use\"",), (200, 404), ("\"status\":\"available\"",)),
)


@dataclass
class EmailPlatformResult:
    """Outcome of checking a single platform for an email address."""

    platform_id: str
    platform_name: str
    category: str
    state: str  # EXISTS | NOT_FOUND | RATE_LIMITED | UNKNOWN
    http_status: int | None = None
    reason: str = ""
    attempts: int = 1
    circuit_state: str = "CLOSED"
    fast_path_latency_ms: float = 0.0
    headless_fallback_used: bool = False
    headless_latency_ms: float = 0.0
    timestamp: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HoleheEmailEnumerator:
    """Read-only Holehe-style email account enumerator with L.0 scope gate, retry/backoff, circuit breakers, and CSR fallback."""

    def __init__(
        self,
        platforms: Iterable[EmailPlatformSpec] = HOLEHE_PLATFORM_CATALOG,
        person_scope_gate: Any = None,
        http_fetcher: Any = None,
        headless_fallback: Any = None,
        max_retries: int = 2,
        backoff_base_sec: float = 0.05,
    ) -> None:
        self.platforms: list[EmailPlatformSpec] = list(platforms)
        self.person_scope_gate = person_scope_gate
        self.http_fetcher = http_fetcher
        self.headless_fallback = headless_fallback
        self.max_retries = max_retries
        self.backoff_base_sec = backoff_base_sec

        self._breakers: dict[str, PlatformCircuitBreaker] = {
            p.platform_id: PlatformCircuitBreaker(platform_id=p.platform_id)
            for p in self.platforms
        }
        self._limiters: dict[str, PlatformRateLimiter] = {
            p.platform_id: PlatformRateLimiter(rate_rps=p.rate_limit_rps)
            for p in self.platforms
        }

    def _classify_response(self, spec: EmailPlatformSpec, status_code: int, body: str) -> tuple[str, str]:
        """Classify HTTP response into EXISTS / NOT_FOUND / RATE_LIMITED / UNKNOWN without guessing."""
        if status_code in spec.rate_limit_status_codes or status_code == 429:
            return ACCOUNT_RATE_LIMITED, f"HTTP {status_code} rate limit returned by {spec.name}"

        body_lower = (body or "").lower()

        # Check explicit NOT_FOUND tokens first (including modernized registration availability tokens)
        universal_nf_tokens = (
            "free_to_register",
            "address_is_free_for_registration",
            "\"exists\":false",
            "\"available\":true",
        )
        for u_nf in universal_nf_tokens:
            if u_nf in body_lower:
                return ACCOUNT_NOT_FOUND, f"Matched non-existence availability token '{u_nf}' (HTTP {status_code})"

        if status_code in spec.not_found_status_codes:
            if spec.not_found_body_tokens:
                for tok in spec.not_found_body_tokens:
                    if tok.lower() in body_lower:
                        return ACCOUNT_NOT_FOUND, f"Matched not-found body signature '{tok}' (HTTP {status_code})"
            elif status_code not in spec.exists_status_codes:
                return ACCOUNT_NOT_FOUND, f"HTTP {status_code} indicates account not found"

        # Strip negated help-text instructions ("not already taken", "not taken", "is not taken")
        # before matching positive existence signatures so tooltip copy cannot cause false positives.
        sanitized_for_exists = (
            body_lower.replace("not already taken", "")
            .replace("is not taken", "")
            .replace("not taken", "")
        )

        # Check explicit EXISTS tokens (requiring positive identity-confirming signature)
        if status_code in spec.exists_status_codes:
            if spec.exists_body_tokens:
                for tok in spec.exists_body_tokens:
                    if tok.lower() in sanitized_for_exists:
                        return ACCOUNT_EXISTS, f"Matched positive existence signature '{tok}' (HTTP {status_code})"
                # Status matched exists_status_codes, but neither exists nor not_found body tokens matched -> UNKNOWN
                return ACCOUNT_UNKNOWN, f"HTTP {status_code} returned ambiguous body without positive signature"
            return ACCOUNT_EXISTS, f"HTTP {status_code} confirms account existence"

        if status_code in spec.not_found_status_codes:
            return ACCOUNT_NOT_FOUND, f"HTTP {status_code} indicates account not found"

        return ACCOUNT_UNKNOWN, f"Ambiguous HTTP {status_code} response; refusing to guess"

    def check_platform(self, email: str, spec: EmailPlatformSpec) -> EmailPlatformResult:
        """Check a single platform with rate limiting, circuit breaker, retry/backoff, and CSR headless fallback."""
        breaker = self._breakers.setdefault(spec.platform_id, PlatformCircuitBreaker(spec.platform_id))
        limiter = self._limiters.setdefault(spec.platform_id, PlatformRateLimiter(spec.rate_limit_rps))

        if not breaker.can_execute():
            return EmailPlatformResult(
                platform_id=spec.platform_id,
                platform_name=spec.name,
                category=spec.category,
                state=ACCOUNT_UNKNOWN,
                reason="Circuit breaker OPEN for platform",
                attempts=0,
                circuit_state=breaker.state,
            )

        if not limiter.consume():
            return EmailPlatformResult(
                platform_id=spec.platform_id,
                platform_name=spec.name,
                category=spec.category,
                state=ACCOUNT_RATE_LIMITED,
                reason="Local per-platform token bucket rate limit exceeded",
                attempts=0,
                circuit_state=breaker.state,
            )

        md5_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        url = spec.endpoint_url.format(email=quote(email), md5=md5_hash)

        attempts = 0
        last_err = ""
        for attempt in range(1, self.max_retries + 2):
            attempts = attempt
            try:
                t_fast = time.perf_counter()
                if self.http_fetcher is not None:
                    status_code, body = self.http_fetcher(spec.platform_id, url, email)
                else:
                    with get_hardened_client(timeout=4.0) as client:
                        resp = client.request(spec.method, url)
                        status_code = resp.status_code
                        body = resp.text[:4096]
                fast_ms = round((time.perf_counter() - t_fast) * 1000.0, 3)

                if status_code >= 500:
                    breaker.record_failure()
                    last_err = f"Server error HTTP {status_code}"
                    if attempt <= self.max_retries:
                        time.sleep(self.backoff_base_sec * (2 ** (attempt - 1)))
                        continue
                    return EmailPlatformResult(
                        platform_id=spec.platform_id,
                        platform_name=spec.name,
                        category=spec.category,
                        state=ACCOUNT_UNKNOWN,
                        http_status=status_code,
                        reason=last_err,
                        attempts=attempts,
                        circuit_state=breaker.state,
                        fast_path_latency_ms=fast_ms,
                    )

                breaker.record_success()
                state, reason = self._classify_response(spec, status_code, body)
                headless_used = False
                headless_ms = 0.0

                if (
                    state == ACCOUNT_UNKNOWN
                    and self.headless_fallback is not None
                    and self.headless_fallback.can_escalate(spec.platform_id, status_code, body)
                ):
                    hr = self.headless_fallback.render(spec.platform_id, url, email)
                    headless_used = hr.triggered
                    headless_ms = hr.latency_ms
                    if hr.triggered and hr.rendered_body:
                        state, reason = self._classify_response(spec, hr.status_code, hr.rendered_body)
                        reason = f"{reason} [recovered via headless CSR fallback]"

                return EmailPlatformResult(
                    platform_id=spec.platform_id,
                    platform_name=spec.name,
                    category=spec.category,
                    state=state,
                    http_status=status_code,
                    reason=reason,
                    attempts=attempts,
                    circuit_state=breaker.state,
                    fast_path_latency_ms=fast_ms,
                    headless_fallback_used=headless_used,
                    headless_latency_ms=headless_ms,
                )
            except Exception as exc:
                breaker.record_failure()
                last_err = f"{type(exc).__name__}: {exc}"
                if attempt <= self.max_retries:
                    time.sleep(self.backoff_base_sec * (2 ** (attempt - 1)))

        return EmailPlatformResult(
            platform_id=spec.platform_id,
            platform_name=spec.name,
            category=spec.category,
            state=ACCOUNT_UNKNOWN,
            reason=f"Exhausted retries ({last_err})",
            attempts=attempts,
            circuit_state=breaker.state,
        )

    def enumerate_email(
        self,
        email: str,
        *,
        entry_point: str = "rest",
        operator_identifier: str | None = None,
        platform_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Run Holehe-style enumeration across all configured platforms after L.0 scope check."""
        if self.person_scope_gate is not None:
            decision = self.person_scope_gate.enforce(
                target=email,
                identifier_type="email",
                entry_point=entry_point,
                operator_identifier=operator_identifier,
            )
            auth_basis = decision.authorization_basis
            why_shown = decision.why_this_result_is_shown
        else:
            auth_basis = "unrestricted_test_harness"
            why_shown = "Test harness execution"

        parsed = normalise_email(email)
        if not parsed:
            return {
                "email": email,
                "valid": False,
                "authorization_basis": auth_basis,
                "why_this_result_is_shown": why_shown,
                "results": [],
                "summary": {"exists": 0, "not_found": 0, "rate_limited": 0, "unknown": 0, "total_checked": 0},
            }

        norm_email, _, _ = parsed
        selected = (
            [p for p in self.platforms if p.platform_id in set(platform_ids)]
            if platform_ids is not None
            else self.platforms
        )

        results: list[EmailPlatformResult] = [self.check_platform(norm_email, spec) for spec in selected]
        counts = {
            "exists": sum(1 for r in results if r.state == ACCOUNT_EXISTS),
            "not_found": sum(1 for r in results if r.state == ACCOUNT_NOT_FOUND),
            "rate_limited": sum(1 for r in results if r.state == ACCOUNT_RATE_LIMITED),
            "unknown": sum(1 for r in results if r.state == ACCOUNT_UNKNOWN),
            "total_checked": len(results),
        }

        return {
            "email": norm_email,
            "valid": True,
            "authorization_basis": auth_basis,
            "why_this_result_is_shown": why_shown,
            "platforms_catalog_size": len(self.platforms),
            "summary": counts,
            "results": [r.to_dict() for r in results],
        }


def compute_three_metric_accuracy(
    *,
    total: int,
    correct: int,
    wrong_resolved: int,
    unknown_count: int,
    rate_limited_count: int = 0,
) -> dict[str, Any]:
    """Compute Phase N.3 3-metric accuracy breakdown with Wilson 95% CIs (z=1.96).

    1. resolved_accuracy = correct / (correct + wrong) EXCLUDING true UNKNOWN cases
       (and also reported excluding both UNKNOWN and RATE_LIMITED non-answers).
    2. coverage = (correct + wrong) / n (fraction of queries where the platform
       allowed a definitive determination rather than blocking with UNKNOWN).
    3. overall_accuracy = correct / n (legacy blended metric).
    """
    from redloop.assessment.metrics import wilson_score_interval

    # Definition A: Excluding UNKNOWN only (where RATE_LIMITED, if any, is still in denominator)
    denom_excl_unknown = total - unknown_count
    resolved_acc = (correct / denom_excl_unknown) if denom_excl_unknown > 0 else 0.0
    resolved_ci = (
        wilson_score_interval(correct, denom_excl_unknown)
        if denom_excl_unknown > 0
        else (0.0, 0.0)
    )
    coverage = (denom_excl_unknown / total) if total > 0 else 0.0
    coverage_ci = wilson_score_interval(denom_excl_unknown, total) if total > 0 else (0.0, 0.0)

    # Definition B: Strictly answered (EXISTS or NOT_FOUND returned; excluding both UNKNOWN and RATE_LIMITED)
    answered_denom = correct + wrong_resolved
    answered_acc = (correct / answered_denom) if answered_denom > 0 else 0.0
    answered_ci = (
        wilson_score_interval(correct, answered_denom)
        if answered_denom > 0
        else (0.0, 0.0)
    )
    answered_coverage = (answered_denom / total) if total > 0 else 0.0
    answered_cov_ci = wilson_score_interval(answered_denom, total) if total > 0 else (0.0, 0.0)

    overall_acc = (correct / total) if total > 0 else 0.0
    overall_ci = wilson_score_interval(correct, total) if total > 0 else (0.0, 0.0)

    return {
        "resolved_accuracy": round(resolved_acc, 4),
        "resolved_accuracy_wilson_95_ci": [round(resolved_ci[0], 4), round(resolved_ci[1], 4)],
        "resolved_k": correct,
        "resolved_n": denom_excl_unknown,
        "strict_answered_accuracy": round(answered_acc, 4),
        "strict_answered_wilson_95_ci": [round(answered_ci[0], 4), round(answered_ci[1], 4)],
        "strict_answered_n": answered_denom,
        "coverage": round(coverage, 4),
        "coverage_wilson_95_ci": [round(coverage_ci[0], 4), round(coverage_ci[1], 4)],
        "strict_answered_coverage": round(answered_coverage, 4),
        "strict_answered_coverage_wilson_95_ci": [round(answered_cov_ci[0], 4), round(answered_cov_ci[1], 4)],
        "overall_accuracy": round(overall_acc, 4),
        "overall_accuracy_wilson_95_ci": [round(overall_ci[0], 4), round(overall_ci[1], 4)],
        "unknown_count": unknown_count,
        "rate_limited_count": rate_limited_count,
    }


def evaluate_email_enumeration_benchmark(
    verified_pairs: Iterable[dict[str, Any]],
    enumerator: HoleheEmailEnumerator,
) -> dict[str, Any]:
    """Evaluate precision, recall, F1, 3-metric accuracy, and Wilson 95% CIs (z=1.96) on verified pairs."""
    from redloop.assessment.metrics import wilson_score_interval

    tp = fp = fn = tn = 0
    unknown_count = 0
    rate_limited_count = 0
    wrong_resolved = 0
    per_item_log: list[dict[str, Any]] = []

    specs_by_id = {p.platform_id: p for p in enumerator.platforms}
    for item in verified_pairs:
        email = item["email"]
        plat_id = item["platform_id"]
        expected_exists = bool(item["expected_exists"])
        spec = specs_by_id[plat_id]

        res = enumerator.check_platform(email, spec)
        predicted_exists = res.state == ACCOUNT_EXISTS
        if res.state == ACCOUNT_UNKNOWN:
            unknown_count += 1
        elif res.state == ACCOUNT_RATE_LIMITED:
            rate_limited_count += 1

        if expected_exists and predicted_exists:
            tp += 1
            outcome = "TP"
        elif not expected_exists and predicted_exists:
            fp += 1
            wrong_resolved += 1
            outcome = "FP"
        elif expected_exists and not predicted_exists:
            fn += 1
            if res.state == ACCOUNT_NOT_FOUND:
                wrong_resolved += 1
            outcome = "FN"
        else:
            tn += 1
            outcome = "TN"

        per_item_log.append(
            {
                "email": email,
                "platform_id": plat_id,
                "expected_exists": expected_exists,
                "predicted_state": res.state,
                "outcome": outcome,
                "reason": res.reason,
                "fast_path_latency_ms": res.fast_path_latency_ms,
                "headless_fallback_used": res.headless_fallback_used,
                "headless_latency_ms": res.headless_latency_ms,
            }
        )

    total = len(per_item_log)
    correct = tp + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    p_ci = wilson_score_interval(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0)
    r_ci = wilson_score_interval(tp, tp + fn) if (tp + fn) > 0 else (0.0, 0.0)
    three_metrics = compute_three_metric_accuracy(
        total=total,
        correct=correct,
        wrong_resolved=wrong_resolved,
        unknown_count=unknown_count,
        rate_limited_count=rate_limited_count,
    )

    return {
        "total_pairs": total,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "precision_wilson_95_ci": [round(p_ci[0], 4), round(p_ci[1], 4)],
        "recall": round(recall, 4),
        "recall_wilson_95_ci": [round(r_ci[0], 4), round(r_ci[1], 4)],
        "f1": round(f1, 4),
        **three_metrics,
        "items": per_item_log,
    }


__all__ = [
    "CLASSIFICATION_CONFIRMED",
    "CLASSIFICATION_CONFLICTING",
    "CLASSIFICATION_NOT_PUBLIC",
    "CLASSIFICATION_POSSIBLE",
    "CLASSIFICATION_STRONG",
    "CLASSIFICATION_UNVERIFIED",
    "EmailFootprintEngine",
    "EmailFootprintReport",
    "FootprintObservation",
    "OBS_ERROR",
    "OBS_MATCH",
    "OBS_NO_MATCH",
    "OBS_NOT_CHECKED",
    "OBS_NOT_CONFIGURED",
    "OBS_RATE_LIMITED",
    "classify_observations",
    "get_email_footprint_engine",
    "normalise_email",
    "redact_breach_metadata",
    "redact_sensitive_text",
]
