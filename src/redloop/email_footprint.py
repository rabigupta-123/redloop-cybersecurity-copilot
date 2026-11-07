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
