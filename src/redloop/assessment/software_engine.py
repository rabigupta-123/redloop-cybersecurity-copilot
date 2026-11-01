"""Software version normalization and pluggable vulnerability intelligence engine for RedLoop.

Strictly adheres to:
- Section 16: Normalize observed software (product, version, vendor, protocol, source, confidence).
- Pluggable vulnerability intelligence feeds.
- Returns UNAVAILABLE if feed/database is not present, NEVER invents CVEs or fake vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Any, Protocol
from pydantic import BaseModel, Field

from redloop.assessment.models import Confidence, Finding, Severity


class SoftwareComponent(BaseModel):
    """Normalized software component observed from real network/banner/header evidence."""

    product: str
    version: str | None = None
    vendor: str | None = None
    protocol: str = "tcp"
    source: str = "banner"  # banner | header | html | service_probe
    confidence: Confidence = Confidence.HIGH
    raw_banner: str = ""


class VulnerabilityRecord(BaseModel):
    """Deterministic vulnerability record from an authorized intelligence feed."""

    cve_id: str
    title: str
    severity: Severity
    cvss_score: float | None = None
    summary: str
    remediation: str
    references: list[str] = Field(default_factory=list)


class VulnerabilityFeed(Protocol):
    """Interface for pluggable vulnerability intelligence databases."""

    def is_available(self) -> bool:
        ...

    def query(self, product: str, version: str) -> list[VulnerabilityRecord] | None:
        ...


class OfflineVulnerabilityFeed:
    """Default feed when no external vulnerability feed is configured."""

    def is_available(self) -> bool:
        return False

    def query(self, product: str, version: str) -> list[VulnerabilityRecord] | None:
        return None  # Triggers UNAVAILABLE status


class SoftwareEngine:
    """Extracts, normalizes, and enriches software components from assessment data."""

    def __init__(self, feed: VulnerabilityFeed | None = None):
        self.feed = feed or OfflineVulnerabilityFeed()

    def normalize_component(
        self,
        raw_string: str,
        protocol: str = "tcp",
        source: str = "banner",
    ) -> SoftwareComponent:
        """Parse raw banner or Server header into structured software component."""
        clean = raw_string.strip()
        product = clean
        version = None
        vendor = None

        # Common server patterns: e.g. "nginx/1.24.0", "Apache/2.4.58 (Ubuntu)", "OpenSSH_9.6p1"
        match = re.search(r"([A-Za-z0-9_-]+)[/_\s]([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9_-]+)?)", clean)
        if match:
            product = match.group(1)
            version = match.group(2)

        # Detect common vendors
        lower_prod = product.lower()
        if "apache" in lower_prod:
            vendor = "Apache Software Foundation"
        elif "nginx" in lower_prod:
            vendor = "F5 / NGINX"
        elif "openssh" in lower_prod:
            vendor = "OpenBSD"
        elif "microsoft" in lower_prod or "iis" in lower_prod:
            vendor = "Microsoft"

        return SoftwareComponent(
            product=product,
            version=version,
            vendor=vendor,
            protocol=protocol,
            source=source,
            confidence=Confidence.CONFIRMED if version else Confidence.MEDIUM,
            raw_banner=clean[:200],
        )

    def lookup_vulnerabilities(
        self,
        component: SoftwareComponent,
    ) -> tuple[str, list[VulnerabilityRecord]]:
        """Query vulnerability feed deterministically.

        Returns (status, records) where status is:
        - 'SUCCESS': Feed returned valid matching records
        - 'NONE_FOUND': Feed was queried, but no matching known vulnerabilities
        - 'UNAVAILABLE': Feed database is not configured or offline (Section 16 requirement)
        """
        if not self.feed.is_available():
            return "UNAVAILABLE", []

        if not component.version:
            return "NONE_FOUND", []

        results = self.feed.query(component.product, component.version)
        if results is None:
            return "UNAVAILABLE", []
        if not results:
            return "NONE_FOUND", []

        return "SUCCESS", results
