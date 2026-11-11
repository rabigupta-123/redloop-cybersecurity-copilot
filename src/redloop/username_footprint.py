"""Sherlock-Style Username Enumeration Engine (Phase L.2).

Loads >=80 platform specifications from src/redloop/data/platforms.json and performs
concurrent, rate-limited, read-only existence checks using both HTTP status codes
and response body signatures (preventing soft-404 false positives).

Enforces Gate L.0 (PersonScopeGate) prior to executing any lookup.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from redloop.email_footprint import (
    ACCOUNT_EXISTS,
    ACCOUNT_NOT_FOUND,
    ACCOUNT_RATE_LIMITED,
    ACCOUNT_UNKNOWN,
    compute_three_metric_accuracy,
)
from redloop.transport import get_hardened_client

DEFAULT_PLATFORMS_PATH = Path(__file__).resolve().parent / "data" / "platforms.json"
_HEADER_CHROME_RE = re.compile(r"<header\b[^>]*>.*?</header>", flags=re.IGNORECASE | re.DOTALL)
_UNIVERSAL_SOFT_404_MARKERS: Tuple[str, ...] = (
    "this handle is currently unassigned",
    "writer profile is unavailable",
    "this profile is unavailable",
    "account unavailable",
    "user not found",
    "page not found",
    "404 page",
    "doesn't exist",
)
_POSITIVE_PROFILE_CONTAINER_MARKERS: Tuple[str, ...] = (
    "<main",
    'class="profile"',
    "class='profile'",
    'property="og:title"',
    'property="profile:username"',
    '"id":',
    '"karma":',
    '"kind":',
)


@dataclass(frozen=True)
class UsernamePlatformSpec:
    """Platform definition loaded from platforms.json."""

    platform_id: str
    name: str
    category: str
    url_template: str
    exists_status_codes: Tuple[int, ...]
    exists_body_signatures: Tuple[str, ...]
    not_found_status_codes: Tuple[int, ...]
    not_found_body_signatures: Tuple[str, ...]


@dataclass
class UsernamePlatformResult:
    """Result of checking a username on a single platform."""

    platform_id: str
    platform_name: str
    category: str
    profile_url: str
    state: str  # EXISTS | NOT_FOUND | RATE_LIMITED | UNKNOWN
    http_status: Optional[int] = None
    reason: str = ""
    fast_path_latency_ms: float = 0.0
    headless_fallback_used: bool = False
    headless_latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GlobalRateLimiter:
    """Thread-safe global token bucket rate limiter across concurrent workers."""

    def __init__(self, rate_rps: float = 25.0, burst: float = 25.0) -> None:
        self.rate_rps = rate_rps
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self.last_refill)
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate_rps)
            self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


def load_platforms_catalog(path: Optional[Path] = None) -> List[UsernamePlatformSpec]:
    """Load the >=80 platform definitions from platforms.json."""
    target_path = path or DEFAULT_PLATFORMS_PATH
    raw = json.loads(target_path.read_text(encoding="utf-8"))
    items = raw.get("platforms", [])
    specs: List[UsernamePlatformSpec] = []
    for item in items:
        specs.append(
            UsernamePlatformSpec(
                platform_id=str(item["platform_id"]),
                name=str(item["name"]),
                category=str(item.get("category", "general")),
                url_template=str(item["url_template"]),
                exists_status_codes=tuple(int(c) for c in item.get("exists_status_codes", [200])),
                exists_body_signatures=tuple(str(s) for s in item.get("exists_body_signatures", [])),
                not_found_status_codes=tuple(int(c) for c in item.get("not_found_status_codes", [404])),
                not_found_body_signatures=tuple(str(s) for s in item.get("not_found_body_signatures", [])),
            )
        )
    return specs


class SherlockUsernameEnumerator:
    """Concurrent Sherlock-style username enumerator with positive identity-confirming signature verification and CSR fallback."""

    def __init__(
        self,
        platforms: Optional[Iterable[UsernamePlatformSpec]] = None,
        person_scope_gate: Any = None,
        http_fetcher: Optional[Callable[[str, str, str], Tuple[int, str]]] = None,
        headless_fallback: Any = None,
        rate_limit_rps: float = 50.0,
        max_workers: int = 8,
    ) -> None:
        self.platforms: List[UsernamePlatformSpec] = (
            list(platforms) if platforms is not None else load_platforms_catalog()
        )
        self.person_scope_gate = person_scope_gate
        self.http_fetcher = http_fetcher
        self.headless_fallback = headless_fallback
        self.rate_limiter = GlobalRateLimiter(rate_rps=rate_limit_rps, burst=max(rate_limit_rps, 20.0))
        self.max_workers = max_workers

    def _classify_response(
        self,
        spec: UsernamePlatformSpec,
        username: str,
        status_code: int,
        body: str,
    ) -> Tuple[str, str]:
        """Classify response requiring positive identity-confirming profile markup (preventing soft-200 FPs)."""
        if status_code == 429:
            return ACCOUNT_RATE_LIMITED, f"HTTP 429 rate limit on {spec.name}"

        body_lower = (body or "").lower()
        uname_lower = username.lower()

        # 1. Check explicit NOT_FOUND body signatures first (crucial for sites returning 200 on soft-404)
        for nf_sig in spec.not_found_body_signatures:
            resolved_sig = nf_sig.replace("{username}", uname_lower).lower()
            if resolved_sig and resolved_sig in body_lower:
                return ACCOUNT_NOT_FOUND, f"Matched not-found body signature '{nf_sig}' (HTTP {status_code})"

        for soft_nf in _UNIVERSAL_SOFT_404_MARKERS:
            if soft_nf in body_lower:
                return ACCOUNT_NOT_FOUND, f"Matched soft-404 non-existence copy '{soft_nf}' (HTTP {status_code})"

        # 2. If status code is exclusively in not_found_status_codes (e.g. 404)
        if status_code in spec.not_found_status_codes and status_code not in spec.exists_status_codes:
            return ACCOUNT_NOT_FOUND, f"HTTP {status_code} indicates profile does not exist"

        # 3. Strip <header>...</header> navigation chrome before matching positive EXISTS signatures
        # so a site's header/domain token on a soft-200 deleted-user page cannot trigger EXISTS.
        content_without_header = _HEADER_CHROME_RE.sub("", body_lower)
        has_positive_profile_container = (
            any(m in content_without_header for m in _POSITIVE_PROFILE_CONTAINER_MARKERS)
            or f"@{uname_lower}" in content_without_header
        )

        if status_code in spec.exists_status_codes:
            if spec.exists_body_signatures:
                for ex_sig in spec.exists_body_signatures:
                    resolved_sig = ex_sig.replace("{username}", uname_lower).lower()
                    if (
                        resolved_sig
                        and resolved_sig in content_without_header
                        and has_positive_profile_container
                    ):
                        return ACCOUNT_EXISTS, f"Matched positive identity signature '{ex_sig}' (HTTP {status_code})"
                # Status code is 200, but no positive identity-confirming signature was found in profile body -> UNKNOWN
                return ACCOUNT_UNKNOWN, f"HTTP {status_code} returned without positive identity-confirming profile signature"
            if has_positive_profile_container:
                return ACCOUNT_EXISTS, f"HTTP {status_code} matched with positive profile container"
            return ACCOUNT_UNKNOWN, f"HTTP {status_code} lacked positive profile container"

        return ACCOUNT_UNKNOWN, f"Ambiguous HTTP {status_code}; refusing to guess"

    def check_single(self, username: str, spec: UsernamePlatformSpec) -> UsernamePlatformResult:
        """Check a single platform for `username` with optional CSR headless fallback."""
        clean_user = username.lstrip("@").strip()
        profile_url = spec.url_template.format(username=quote(clean_user))

        if not self.rate_limiter.acquire():
            return UsernamePlatformResult(
                platform_id=spec.platform_id,
                platform_name=spec.name,
                category=spec.category,
                profile_url=profile_url,
                state=ACCOUNT_RATE_LIMITED,
                reason="Global rate limiter token exhausted",
            )

        try:
            t_fast = time.perf_counter()
            if self.http_fetcher is not None:
                status_code, body = self.http_fetcher(spec.platform_id, profile_url, clean_user)
            else:
                with get_hardened_client(timeout=4.0) as client:
                    resp = client.get(profile_url)
                    status_code = resp.status_code
                    body = resp.text[:8192]
            fast_ms = round((time.perf_counter() - t_fast) * 1000.0, 3)

            if status_code >= 500:
                return UsernamePlatformResult(
                    platform_id=spec.platform_id,
                    platform_name=spec.name,
                    category=spec.category,
                    profile_url=profile_url,
                    state=ACCOUNT_UNKNOWN,
                    http_status=status_code,
                    reason=f"Server error HTTP {status_code}",
                    fast_path_latency_ms=fast_ms,
                )

            state, reason = self._classify_response(spec, clean_user, status_code, body)
            headless_used = False
            headless_ms = 0.0

            if (
                state == ACCOUNT_UNKNOWN
                and self.headless_fallback is not None
                and self.headless_fallback.can_escalate(spec.platform_id, status_code, body)
            ):
                hr = self.headless_fallback.render(spec.platform_id, profile_url, clean_user)
                headless_used = hr.triggered
                headless_ms = hr.latency_ms
                if hr.triggered and hr.rendered_body:
                    state, reason = self._classify_response(spec, clean_user, hr.status_code, hr.rendered_body)
                    reason = f"{reason} [recovered via headless CSR fallback]"

            return UsernamePlatformResult(
                platform_id=spec.platform_id,
                platform_name=spec.name,
                category=spec.category,
                profile_url=profile_url,
                state=state,
                http_status=status_code,
                reason=reason,
                fast_path_latency_ms=fast_ms,
                headless_fallback_used=headless_used,
                headless_latency_ms=headless_ms,
            )
        except Exception as exc:
            return UsernamePlatformResult(
                platform_id=spec.platform_id,
                platform_name=spec.name,
                category=spec.category,
                profile_url=profile_url,
                state=ACCOUNT_UNKNOWN,
                reason=f"{type(exc).__name__}: {exc}",
            )

    def enumerate_username(
        self,
        username: str,
        *,
        entry_point: str = "rest",
        operator_identifier: Optional[str] = None,
        platform_ids: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Concurrently enumerate `username` across platforms after enforcing Gate L.0."""
        if self.person_scope_gate is not None:
            decision = self.person_scope_gate.enforce(
                target=username,
                identifier_type="username",
                entry_point=entry_point,
                operator_identifier=operator_identifier,
            )
            auth_basis = decision.authorization_basis
            why_shown = decision.why_this_result_is_shown
            clean_user = decision.normalized_target
        else:
            clean_user = username.lstrip("@").strip().lower()
            auth_basis = "unrestricted_test_harness"
            why_shown = "Test harness execution"

        selected = (
            [p for p in self.platforms if p.platform_id in set(platform_ids)]
            if platform_ids is not None
            else self.platforms
        )

        results_map: Dict[str, UsernamePlatformResult] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_id = {
                pool.submit(self.check_single, clean_user, spec): spec.platform_id
                for spec in selected
            }
            for fut in as_completed(future_to_id):
                pid = future_to_id[fut]
                results_map[pid] = fut.result()

        ordered_results = [results_map[spec.platform_id] for spec in selected]
        summary = {
            "exists": sum(1 for r in ordered_results if r.state == ACCOUNT_EXISTS),
            "not_found": sum(1 for r in ordered_results if r.state == ACCOUNT_NOT_FOUND),
            "rate_limited": sum(1 for r in ordered_results if r.state == ACCOUNT_RATE_LIMITED),
            "unknown": sum(1 for r in ordered_results if r.state == ACCOUNT_UNKNOWN),
            "total_checked": len(ordered_results),
        }

        return {
            "username": clean_user,
            "authorization_basis": auth_basis,
            "why_this_result_is_shown": why_shown,
            "platforms_catalog_size": len(self.platforms),
            "summary": summary,
            "results": [r.to_dict() for r in ordered_results],
        }


def evaluate_username_enumeration_benchmark(
    verified_pairs: Iterable[Dict[str, Any]],
    enumerator: SherlockUsernameEnumerator,
) -> Dict[str, Any]:
    """Evaluate precision, recall, F1, 3-metric accuracy, and Wilson 95% CIs (z=1.96) across verified pairs."""
    from redloop.assessment.metrics import wilson_score_interval

    tp = fp = fn = tn = 0
    unknown_count = 0
    rate_limited_count = 0
    wrong_resolved = 0
    per_item_log: List[Dict[str, Any]] = []
    specs_by_id = {p.platform_id: p for p in enumerator.platforms}

    for item in verified_pairs:
        uname = item["username"]
        plat_id = item["platform_id"]
        expected_exists = bool(item["expected_exists"])
        spec = specs_by_id[plat_id]

        res = enumerator.check_single(uname, spec)
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
                "username": uname,
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

