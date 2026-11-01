"""VirusTotal API v3 client for RedLoop.

This module replaces ad-hoc VirusTotal calls with one normalised client covering
IP addresses, domains, URLs, file hashes, and (consent-gated) file uploads.

Truthfulness rules
------------------
* A missing API key, disabled provider, auth failure, rate limit, or transport
  failure is never reported as a clean result.
* ``detection_ratio`` is the share of *verdict-returning* engines that flagged an
  indicator.  It is **not** a probability that the indicator is malicious.
* ``engine_coverage`` is the share of applicable engines that returned any
  verdict, so a 1/1 ratio on one engine is visibly different from 60/70.
* Only successful observations and explicit ``NOT_FOUND`` responses are cached.
* File uploads require the exact consent token and are opt-in.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from redloop.config import settings

DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
MAX_FILE_BYTES = 32 * 1024 * 1024
UPLOAD_CONSENT_TOKEN = "UPLOAD_TO_VIRUSTOTAL"

ST_LIVE = "LIVE_RESULT"
ST_CACHED = "CACHED_RESULT"
ST_RATE_LIMITED = "RATE_LIMITED"
ST_API_UNAVAILABLE = "API_UNAVAILABLE"
ST_INVALID_INPUT = "INVALID_INPUT"
ST_ANALYSIS_PENDING = "ANALYSIS_PENDING"
ST_NOT_FOUND = "NOT_FOUND"

VERDICT_MALICIOUS = "MALICIOUS_DETECTIONS_PRESENT"
VERDICT_SUSPICIOUS = "SUSPICIOUS_DETECTIONS_PRESENT"
VERDICT_CLEAN = "NO_SECURITY_VENDOR_DETECTIONS"
VERDICT_UNKNOWN = "UNKNOWN"

RATIO_AVAILABLE = "AVAILABLE"
RATIO_NOT_AVAILABLE = "NOT_AVAILABLE"

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "169.254.169.254",
    "fd00:ec2::254",
    "instance-data",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _mask_key(key: str | None) -> str | None:
    if not key:
        return None
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"


def _json_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class VirusTotalResult:
    indicator: str
    indicator_type: str
    status: str
    source_status: str | None = None
    source: str = "virustotal"
    live: bool = False
    from_cache: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    failure: int = 0
    type_unsupported: int = 0
    total_engines: int = 0
    verdict_engines: int = 0
    detection_ratio: float | None = None
    detection_ratio_status: str = RATIO_NOT_AVAILABLE
    engine_coverage: dict[str, Any] = field(default_factory=dict)
    verdict: str = VERDICT_UNKNOWN
    reputation: int | None = None
    categories: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    last_analysis_date: str | None = None
    meaningful_name: str | None = None
    type_description: str | None = None
    permalink: str | None = None
    file_hashes: dict[str, str] = field(default_factory=dict)
    reason: str | None = None
    error: str | None = None
    observed_at: str = field(default_factory=_now)
    fetched_at: str | None = None
    cache_expires_at: str | None = None
    evidence_hash: str | None = None
    raw_available: bool = False
    provider: str = "virustotal_api_v3"

    def __post_init__(self) -> None:
        if self.source_status is None:
            self.source_status = self.status
        if self.evidence_hash is None:
            self.evidence_hash = self.compute_evidence_hash()

    def _canonical_evidence(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "status": self.source_status or self.status,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "timeout": self.timeout,
            "failure": self.failure,
            "type_unsupported": self.type_unsupported,
            "total_engines": self.total_engines,
            "verdict_engines": self.verdict_engines,
            "detection_ratio": self.detection_ratio,
            "detection_ratio_status": self.detection_ratio_status,
            "engine_coverage": self.engine_coverage,
            "reputation": self.reputation,
            "verdict": self.verdict,
            "categories": self.categories,
            "tags": self.tags,
            "last_analysis_date": self.last_analysis_date,
            "meaningful_name": self.meaningful_name,
            "type_description": self.type_description,
            "permalink": self.permalink,
            "file_hashes": self.file_hashes,
            "reason": self.reason,
            "error": self.error,
        }

    def compute_evidence_hash(self) -> str:
        return _json_hash(self._canonical_evidence())

    def reseal_evidence(self) -> None:
        """Recompute the evidence hash after an intentional field update."""
        self.evidence_hash = self.compute_evidence_hash()

    def verify_evidence_hash(self) -> bool:
        return bool(self.evidence_hash) and self.evidence_hash == self.compute_evidence_hash()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_valid"] = self.verify_evidence_hash()
        data["detection_ratio_note"] = (
            "Detection ratio is a vendor-flag share, not a probability of maliciousness."
        )
        return data


class VirusTotalClient:
    """Normalised, cache-aware VirusTotal v3 client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        enabled: bool | None = None,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        cache_ttl: int | None = None,
        clock: Any = time.time,
    ):
        self.api_key = (
            api_key
            if api_key is not None
            else os.environ.get("VIRUSTOTAL_API_KEY") or settings.virustotal_api_key
        ).strip() or None
        self.base_url = (
            base_url
            or os.environ.get("VIRUSTOTAL_BASE_URL")
            or settings.virustotal_base_url
            or DEFAULT_BASE_URL
        ).rstrip("/")
        self.enabled = (
            enabled
            if enabled is not None
            else _bool_env(
                "VIRUSTOTAL_ENABLED",
                bool(settings.virustotal_enabled or self.api_key),
            )
        )
        self.timeout = timeout
        self.transport = transport
        self.cache_ttl = int(
            cache_ttl
            if cache_ttl is not None
            else os.environ.get("VIRUSTOTAL_CACHE_TTL", "3600")
        )
        self._clock = clock
        self._cache: dict[str, tuple[float, VirusTotalResult]] = {}
        self._validate_base_url()

    # ------------------------------------------------------------------
    # Configuration / capability
    # ------------------------------------------------------------------
    def _validate_base_url(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("VirusTotal base URL must be a valid http(s) URL.")
        host = parsed.hostname.lower()
        if host in _BLOCKED_HOSTS or host.startswith("169.254."):
            raise ValueError("VirusTotal base URL points at a blocked metadata/link-local host.")
        if parsed.username or parsed.password:
            raise ValueError("VirusTotal base URL must not contain embedded credentials.")

    def provider_status(self) -> dict[str, Any]:
        configured = bool(self.api_key)
        if not self.enabled:
            status = "DISABLED"
            reason = "VIRUSTOTAL_ENABLED is false."
        elif not configured:
            status = "NOT_CONFIGURED"
            reason = "VIRUSTOTAL_API_KEY is not set."
        else:
            status = "CONFIGURED"
            reason = None
        return {
            "provider": "virustotal",
            "status": status,
            "configured": configured,
            "enabled": self.enabled,
            "base_url": self.base_url,
            "api_key_masked": _mask_key(self.api_key),
            "cache_ttl_seconds": self.cache_ttl,
            "reason": reason,
            "updated_at": _now(),
        }

    def clear_cache(self) -> None:
        self._cache.clear()

    # ------------------------------------------------------------------
    # Indicator handling
    # ------------------------------------------------------------------
    @staticmethod
    def detect_type(indicator: str) -> str:
        value = (indicator or "").strip()
        if not value:
            return "invalid"
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if value.lower().startswith(("http://", "https://")):
            parsed = urlsplit(value)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                return "url"
            return "invalid"
        if _HASH_RE.match(value):
            return "file"
        if _DOMAIN_RE.match(value):
            return "domain"
        return "invalid"

    @staticmethod
    def _normalise(indicator: str, indicator_type: str) -> str:
        value = indicator.strip()
        if indicator_type == "ip":
            return str(ipaddress.ip_address(value))
        if indicator_type == "domain":
            return value.lower().rstrip(".")
        if indicator_type == "file":
            return value.lower()
        if indicator_type == "url":
            return value
        return value

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _endpoint(self, indicator: str, indicator_type: str) -> str:
        if indicator_type == "ip":
            return f"{self.base_url}/ip_addresses/{indicator}"
        if indicator_type == "domain":
            return f"{self.base_url}/domains/{indicator}"
        if indicator_type == "url":
            return f"{self.base_url}/urls/{self._url_id(indicator)}"
        if indicator_type == "file":
            return f"{self.base_url}/files/{indicator}"
        raise ValueError("Unsupported indicator type.")

    def _failure(
        self,
        indicator: str,
        indicator_type: str,
        status: str,
        reason: str,
        *,
        error: str | None = None,
    ) -> VirusTotalResult:
        return VirusTotalResult(
            indicator=indicator,
            indicator_type=indicator_type,
            status=status,
            reason=reason,
            error=error,
            observed_at=_now(),
        )

    @staticmethod
    def _attach_file_hashes(
        result: VirusTotalResult, hashes: dict[str, str]
    ) -> VirusTotalResult:
        result.file_hashes = dict(hashes)
        result.reseal_evidence()
        return result

    # ------------------------------------------------------------------
    # Public lookups
    # ------------------------------------------------------------------
    def inspect(self, indicator: str, indicator_type: str | None = None) -> VirusTotalResult:
        raw = (indicator or "").strip()
        kind = (indicator_type or self.detect_type(raw)).lower()
        if kind in {"hash", "file_hash", "sha256", "md5", "sha1"}:
            kind = "file"
        if kind not in {"ip", "domain", "url", "file"}:
            return self._failure(raw, kind or "invalid", ST_INVALID_INPUT, "Unsupported indicator type.")

        try:
            normalised = self._normalise(raw, kind)
        except ValueError:
            return self._failure(raw, kind, ST_INVALID_INPUT, "Indicator is not valid for its declared type.")
        detected = self.detect_type(normalised)
        if not normalised or detected == "invalid" or detected != kind:
            return self._failure(
                raw,
                kind,
                ST_INVALID_INPUT,
                f"Indicator is not valid for its declared type ({kind}).",
            )

        if not self.enabled:
            return self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                "VirusTotal provider is disabled (VIRUSTOTAL_ENABLED is false).",
            )
        if not self.api_key:
            return self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                "VIRUSTOTAL_API_KEY is not configured; no live VirusTotal lookup was performed.",
            )

        cache_key = f"{kind}:{normalised}"
        cached = self._cache.get(cache_key)
        if cached:
            expires_at, cached_result = cached
            if self._clock() < expires_at:
                return replace(
                    deepcopy(cached_result),
                    status=ST_CACHED,
                    source_status=cached_result.status,
                    live=False,
                    from_cache=True,
                    cache_expires_at=datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
                )
            self._cache.pop(cache_key, None)

        headers = {"x-apikey": self.api_key, "accept": "application/json"}
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.get(self._endpoint(normalised, kind), headers=headers)
        except httpx.TimeoutException:
            return self._failure(normalised, kind, ST_API_UNAVAILABLE, "VirusTotal request timed out.")
        except httpx.HTTPError as exc:
            return self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                "VirusTotal transport failure.",
                error=type(exc).__name__,
            )

        now = _now()
        if response.status_code == 429:
            result = self._failure(
                normalised,
                kind,
                ST_RATE_LIMITED,
                "VirusTotal public API rate limit exceeded.",
            )
            result.fetched_at = now
            return result
        if response.status_code in {401, 403}:
            result = self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                "VirusTotal authentication failed or the key lacks access.",
            )
            result.fetched_at = now
            return result
        if response.status_code == 400:
            result = self._failure(normalised, kind, ST_INVALID_INPUT, "VirusTotal rejected the indicator.")
            result.fetched_at = now
            return result
        if response.status_code == 404:
            result = self._failure(
                normalised,
                kind,
                ST_NOT_FOUND,
                "VirusTotal has no record for this indicator.",
            )
            result.fetched_at = now
            self._cache_result(cache_key, result, ttl=min(self.cache_ttl, 300))
            return result
        if response.status_code == 409:
            result = self._failure(
                normalised,
                kind,
                ST_ANALYSIS_PENDING,
                "VirusTotal accepted the item but analysis is still pending.",
            )
            result.fetched_at = now
            return result
        if response.status_code >= 500:
            result = self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                f"VirusTotal service error (HTTP {response.status_code}).",
            )
            result.fetched_at = now
            return result
        if response.status_code != 200:
            result = self._failure(
                normalised,
                kind,
                ST_API_UNAVAILABLE,
                f"Unexpected VirusTotal response (HTTP {response.status_code}).",
            )
            result.fetched_at = now
            return result

        try:
            payload = response.json()
        except ValueError:
            return self._failure(
                normalised, kind, ST_API_UNAVAILABLE, "VirusTotal returned non-JSON data."
            )

        result = self._parse_result(normalised, kind, payload, now)
        if result.status in {ST_LIVE, ST_NOT_FOUND}:
            self._cache_result(cache_key, result)
        return result

    def _cache_result(self, key: str, result: VirusTotalResult, ttl: int | None = None) -> None:
        ttl = self.cache_ttl if ttl is None else ttl
        self._cache[key] = (self._clock() + ttl, deepcopy(result))

    def _parse_result(
        self, indicator: str, kind: str, payload: dict[str, Any], now: str
    ) -> VirusTotalResult:
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return self._failure(
                indicator, kind, ST_API_UNAVAILABLE, "VirusTotal response omitted data."
            )
        attrs = data.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        stats = attrs.get("last_analysis_stats") or {}
        if not isinstance(stats, dict):
            stats = {}

        def _int(name: str) -> int:
            try:
                return int(stats.get(name) or 0)
            except (TypeError, ValueError):
                return 0

        malicious = _int("malicious")
        suspicious = _int("suspicious")
        harmless = _int("harmless")
        undetected = _int("undetected")
        timeout = _int("timeout")
        failure = _int("failure")
        type_unsupported = _int("type-unsupported")
        verdict_engines = malicious + suspicious + harmless + undetected
        total_engines = verdict_engines + timeout + failure + type_unsupported
        detection_ratio = (
            round(malicious / verdict_engines, 6) if verdict_engines else None
        )
        coverage_ratio = (
            round(verdict_engines / total_engines, 6) if total_engines else None
        )
        if malicious:
            verdict = VERDICT_MALICIOUS
        elif suspicious:
            verdict = VERDICT_SUSPICIOUS
        elif verdict_engines:
            verdict = VERDICT_CLEAN
        else:
            verdict = VERDICT_UNKNOWN

        last_date = attrs.get("last_analysis_date")
        last_analysis_date = None
        if isinstance(last_date, (int, float)):
            try:
                last_analysis_date = datetime.fromtimestamp(last_date, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                last_analysis_date = None
        elif isinstance(last_date, str):
            last_analysis_date = last_date

        published_id = data.get("id") or indicator
        permalink = f"https://www.virustotal.com/gui/{kind}/{published_id}"
        file_hashes: dict[str, str] = {}
        for name in ("md5", "sha1", "sha256"):
            value = attrs.get(name)
            if isinstance(value, str) and value:
                file_hashes[name] = value
        if kind == "file":
            file_hashes.setdefault("sha256" if len(indicator) == 64 else "md5", indicator)

        result = VirusTotalResult(
            indicator=indicator,
            indicator_type=kind,
            status=ST_LIVE,
            live=True,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            timeout=timeout,
            failure=failure,
            type_unsupported=type_unsupported,
            total_engines=total_engines,
            verdict_engines=verdict_engines,
            detection_ratio=detection_ratio,
            detection_ratio_status=RATIO_AVAILABLE if detection_ratio is not None else RATIO_NOT_AVAILABLE,
            engine_coverage={
                "verdict_engines": verdict_engines,
                "total_engines": total_engines,
                "ratio": coverage_ratio,
                "status": RATIO_AVAILABLE if coverage_ratio is not None else RATIO_NOT_AVAILABLE,
            },
            verdict=verdict,
            reputation=attrs.get("reputation") if isinstance(attrs.get("reputation"), int) else None,
            categories=attrs.get("categories") if isinstance(attrs.get("categories"), dict) else {},
            tags=attrs.get("tags") if isinstance(attrs.get("tags"), list) else [],
            last_analysis_date=last_analysis_date,
            meaningful_name=attrs.get("meaningful_name") if isinstance(attrs.get("meaningful_name"), str) else None,
            type_description=attrs.get("type_description") if isinstance(attrs.get("type_description"), str) else None,
            permalink=permalink,
            file_hashes=file_hashes,
            observed_at=now,
            fetched_at=now,
            raw_available=bool(attrs),
        )
        return result

    # ------------------------------------------------------------------
    # File analysis
    # ------------------------------------------------------------------
    @staticmethod
    def hash_bytes(data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def analyse_file_bytes(
        self,
        filename: str,
        data: bytes,
        *,
        upload: bool = False,
        consent_token: str | None = None,
    ) -> VirusTotalResult:
        if not data:
            return self._failure(filename or "file", "file", ST_INVALID_INPUT, "File is empty.")
        if len(data) > MAX_FILE_BYTES:
            return self._failure(
                filename or "file",
                "file",
                ST_INVALID_INPUT,
                f"File exceeds the {MAX_FILE_BYTES} byte upload limit.",
            )
        hashes = self.hash_bytes(data)
        result = self._attach_file_hashes(self.inspect(hashes["sha256"], "file"), hashes)
        if result.source_status not in {ST_NOT_FOUND, ST_LIVE}:
            return result
        if result.source_status == ST_LIVE:
            return result
        if not upload:
            result.reason = (
                "No VirusTotal record exists for this hash. File upload was not requested; "
                "set upload=true and provide the explicit consent token to submit it."
            )
            result.reseal_evidence()
            return result
        if consent_token != UPLOAD_CONSENT_TOKEN:
            return self._attach_file_hashes(
                self._failure(
                    hashes["sha256"],
                    "file",
                    ST_INVALID_INPUT,
                    "File upload requires the exact UPLOAD_TO_VIRUSTOTAL consent token.",
                ),
                hashes,
            )
        if not self.api_key:
            return self._attach_file_hashes(
                self._failure(
                    hashes["sha256"],
                    "file",
                    ST_API_UNAVAILABLE,
                    "VIRUSTOTAL_API_KEY is not configured.",
                ),
                hashes,
            )

        headers = {"x-apikey": self.api_key, "accept": "application/json"}
        try:
            with httpx.Client(
                timeout=self.timeout,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    files={"file": (Path(filename or "sample.bin").name, data)},
                )
        except httpx.TimeoutException:
            return self._attach_file_hashes(
                self._failure(hashes["sha256"], "file", ST_API_UNAVAILABLE, "Upload timed out."),
                hashes,
            )
        except httpx.HTTPError as exc:
            return self._attach_file_hashes(
                self._failure(
                    hashes["sha256"],
                    "file",
                    ST_API_UNAVAILABLE,
                    "Upload transport failure.",
                    error=type(exc).__name__,
                ),
                hashes,
            )

        if response.status_code == 429:
            return self._attach_file_hashes(
                self._failure(hashes["sha256"], "file", ST_RATE_LIMITED, "Upload rate limit exceeded."),
                hashes,
            )
        if response.status_code in {401, 403}:
            return self._attach_file_hashes(
                self._failure(
                    hashes["sha256"], "file", ST_API_UNAVAILABLE, "Upload authentication failed."
                ),
                hashes,
            )
        if response.status_code in {200, 201, 202}:
            pending = VirusTotalResult(
                indicator=hashes["sha256"],
                indicator_type="file",
                status=ST_ANALYSIS_PENDING,
                reason="File submitted to VirusTotal; analysis is pending and must be re-queried later.",
                file_hashes=hashes,
                observed_at=_now(),
                fetched_at=_now(),
            )
            return pending
        if response.status_code == 409:
            return self._attach_file_hashes(self.inspect(hashes["sha256"], "file"), hashes)
        return self._attach_file_hashes(
            self._failure(
                hashes["sha256"],
                "file",
                ST_API_UNAVAILABLE,
                f"Upload failed (HTTP {response.status_code}).",
            ),
            hashes,
        )

    def analyse_file(
        self,
        path: str | Path,
        *,
        upload: bool = False,
        consent_token: str | None = None,
    ) -> VirusTotalResult:
        file_path = Path(path)
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                return self._failure(
                    file_path.name,
                    "file",
                    ST_INVALID_INPUT,
                    f"File exceeds the {MAX_FILE_BYTES} byte limit.",
                )
            data = file_path.read_bytes()
        except OSError as exc:
            return self._failure(
                file_path.name,
                "file",
                ST_INVALID_INPUT,
                "File could not be read.",
                error=type(exc).__name__,
            )
        return self.analyse_file_bytes(
            file_path.name, data, upload=upload, consent_token=consent_token
        )


_default_client: VirusTotalClient | None = None


def get_virustotal_client(force_new: bool = False) -> VirusTotalClient:
    global _default_client
    if force_new or _default_client is None:
        _default_client = VirusTotalClient()
    return _default_client


__all__ = [
    "DEFAULT_BASE_URL",
    "MAX_FILE_BYTES",
    "ST_ANALYSIS_PENDING",
    "ST_API_UNAVAILABLE",
    "ST_CACHED",
    "ST_INVALID_INPUT",
    "ST_LIVE",
    "ST_NOT_FOUND",
    "ST_RATE_LIMITED",
    "UPLOAD_CONSENT_TOKEN",
    "VirusTotalClient",
    "VirusTotalResult",
    "get_virustotal_client",
]
