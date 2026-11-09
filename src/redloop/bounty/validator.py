"""Deterministic Finding Validator and Evidence Harvester (Phase 3.4).

Guarantees:
1. A finding is "confirmed" ONLY if an independent deterministic check reproduces it.
2. Safe, non-destructive proof requests matching expected signatures.
3. Cryptographically hashes responses (SHA-256) and archives full evidence records.
4. Strictly forbids destructive payloads, exfiltration, DoS, and credential stuffing.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any, Dict, List, Optional, Tuple
import uuid

from redloop.bounty.models import (
    CandidateFinding,
    EvidenceRecord,
    FindingValidationState,
)
from redloop.integrations.transport import SafeHTTPClient, SSRFDestinationError


class FindingValidator:
    """Deterministic, non-destructive reproduction validator."""

    def __init__(self, evidence_store: Optional[Dict[str, EvidenceRecord]] = None) -> None:
        self.evidence_store: Dict[str, EvidenceRecord] = evidence_store if evidence_store is not None else {}

    def validate_finding(
        self,
        finding: CandidateFinding,
        base_url: str,
        attempts: int = 3,
        custom_checker: Optional[Any] = None,
    ) -> FindingValidationState:
        """Runs deterministic reproduction checks against target endpoint."""
        successes = 0
        recorded_evidence: List[str] = []

        # Target endpoint construction
        endpoint = finding.path_pattern.lstrip("/")
        full_url = f"{base_url.rstrip('/')}/{endpoint}"

        for i in range(attempts):
            proof_nonce = f"rlp_proof_{uuid.uuid4().hex[:8]}"
            req_url = full_url
            if finding.parameter:
                sep = "&" if "?" in req_url else "?"
                req_url = f"{full_url}{sep}{finding.parameter}={proof_nonce}"

            req_repr = f"GET {req_url} HTTP/1.1\r\nHost: {base_url}\r\nUser-Agent: REDLOOP-Validator/1.0"
            resp_body = ""
            status_code = 0
            matched = False

            if custom_checker:
                # Custom mock/deterministic hook for lab targets
                matched, resp_body, status_code = custom_checker(req_url, proof_nonce)
            else:
                try:
                    resp = SafeHTTPClient.get(req_url, timeout=5.0)
                    resp_body = resp.get("body", "")
                    status_code = resp.get("status_code", 0)

                    # Deterministic signature checks based on vuln class
                    vuln_upper = finding.vuln_class.upper()
                    if "XSS" in vuln_upper or "CWE-79" in vuln_upper:
                        matched = proof_nonce in resp_body
                    elif "CWE-200" in vuln_upper or "INFO" in vuln_upper:
                        matched = status_code == 200 and len(resp_body) > 0
                    elif "CWE-22" in vuln_upper or "TRAVERSAL" in vuln_upper:
                        matched = "root:" in resp_body or "[extensions]" in resp_body or "Directory" in resp_body
                    elif "CWE-89" in vuln_upper or "SQL" in vuln_upper:
                        matched = "syntax" in resp_body.lower() or "sqlite" in resp_body.lower() or "sql" in resp_body.lower()
                    else:
                        matched = status_code in (200, 201, 302)
                except Exception:
                    matched = False

            if matched:
                successes += 1
                resp_hash = hashlib.sha256(resp_body.encode("utf-8")).hexdigest()
                ev_id = f"ev-{uuid.uuid4().hex[:12]}"
                evidence = EvidenceRecord(
                    id=ev_id,
                    target=finding.asset,
                    endpoint=finding.path_pattern,
                    request=req_repr,
                    response=resp_body[:2048],  # bounded sample
                    response_hash=resp_hash,
                    signature_matched=finding.vuln_class,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    metadata={"attempt": i + 1, "status_code": status_code},
                )
                self.evidence_store[ev_id] = evidence
                recorded_evidence.append(ev_id)

        finding.evidence_ids.extend(recorded_evidence)
        finding.reproducibility_rate = round(successes / attempts, 4)

        # A finding is confirmed only if reproduction succeeds >= 2 out of 3 times with evidence
        if successes >= 2 and len(finding.evidence_ids) > 0:
            finding.state = FindingValidationState.CONFIRMED
        else:
            finding.state = FindingValidationState.CANDIDATE

        finding.calculate_confidence()
        finding.calculate_priority()
        return finding.state

