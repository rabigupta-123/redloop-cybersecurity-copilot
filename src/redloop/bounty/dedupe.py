"""Finding Deduplication and Duplicate Rate Calculation (Phase 3.6).

Rules:
1. Fingerprint = SHA-256(normalized host + path pattern + vuln class + parameter)
2. Duplicate Rate = duplicates / reported
3. Out-of-scope entries always win over in-scope wildcards.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple
from redloop.bounty.models import CandidateFinding


class FindingDeduplicator:
    def __init__(self) -> None:
        self._seen_fingerprints: Dict[str, CandidateFinding] = {}
        self._all_findings: List[CandidateFinding] = []
        self._duplicate_count: int = 0

    def process(self, finding: CandidateFinding) -> Tuple[bool, str]:
        """Calculates fingerprint and checks whether finding is a duplicate.
        
        Returns:
            Tuple[bool, str]: (is_duplicate, fingerprint_hex)
        """
        fp = finding.compute_fingerprint()
        self._all_findings.append(finding)

        if fp in self._seen_fingerprints:
            finding.is_duplicate = True
            self._duplicate_count += 1
            return True, fp

        self._seen_fingerprints[fp] = finding
        finding.is_duplicate = False
        return False, fp

    @property
    def duplicate_rate(self) -> float:
        """Duplicate rate = duplicates / reported."""
        total = len(self._all_findings)
        if total == 0:
            return 0.0
        return round(self._duplicate_count / total, 4)

    @property
    def unique_findings(self) -> List[CandidateFinding]:
        return list(self._seen_fingerprints.values())

    @property
    def total_reported(self) -> int:
        return len(self._all_findings)

    @property
    def total_duplicates(self) -> int:
        return self._duplicate_count

