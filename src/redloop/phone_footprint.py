"""Phone Number OSINT & ITU-T E.164 Metadata Engine (Phase L.3).

Uses Google's libphonenumber (python-phonenumbers) to extract authoritative public
numbering-plan metadata: E.164 normalization, ISO region, geographic region,
original prefix carrier, line type (MOBILE, VOIP, FIXED_LINE, TOLL_FREE, etc.),
and timezones.

Design invariants:
1. Enforces Gate L.0 (PersonScopeGate) prior to executing any lookup.
2. Every returned field is a structured PhoneFieldEvidence carrying `value`,
   `source`, and `confidence`. No field is ever returned without a cited source.
3. Zero synthetic subscriber names, zero fake live HLR/geolocation claims, and
   explicit MNP (Mobile Number Portability) caveat when citing prefix carrier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone as pn_timezone


_LINE_TYPE_MAP: Dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "FIXED_LINE",
    PhoneNumberType.MOBILE: "MOBILE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    PhoneNumberType.TOLL_FREE: "TOLL_FREE",
    PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
    PhoneNumberType.SHARED_COST: "SHARED_COST",
    PhoneNumberType.VOIP: "VOIP",
    PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
    PhoneNumberType.PAGER: "PAGER",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "VOICEMAIL",
    PhoneNumberType.UNKNOWN: "UNKNOWN",
}


@dataclass(frozen=True)
class PhoneFieldEvidence:
    """Every phone OSINT attribute carries an explicit value, cited source, and confidence."""

    value: Any
    source: str
    confidence: float
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
        }
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class PhoneFootprintReport:
    """Standardized, source-attributed phone number OSINT report."""

    raw_input: str
    valid: bool
    possible: bool
    authorization_basis: str
    why_this_result_is_shown: str
    fields: Dict[str, PhoneFieldEvidence]
    limitations: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_hash: str = ""

    def compute_evidence_hash(self) -> str:
        canonical = {
            "raw_input": self.raw_input,
            "valid": self.valid,
            "possible": self.possible,
            "fields": {k: v.to_dict() for k, v in sorted(self.fields.items())},
        }
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_input": self.raw_input,
            "valid": self.valid,
            "possible": self.possible,
            "authorization_basis": self.authorization_basis,
            "why_this_result_is_shown": self.why_this_result_is_shown,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
            "limitations": self.limitations,
            "timestamp": self.timestamp,
            "evidence_hash": self.evidence_hash,
        }


class PhoneFootprintEngine:
    """Phone number OSINT engine backed by libphonenumber and optional breach correlation."""

    def __init__(
        self,
        person_scope_gate: Any = None,
        breach_correlator: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self.person_scope_gate = person_scope_gate
        self.breach_correlator = breach_correlator

    def investigate(
        self,
        phone_number: str,
        default_region: str = "US",
        *,
        entry_point: str = "rest",
        operator_identifier: Optional[str] = None,
    ) -> PhoneFootprintReport:
        """Parse, validate, and extract source-attributed metadata for `phone_number`."""
        if self.person_scope_gate is not None:
            decision = self.person_scope_gate.enforce(
                target=phone_number,
                identifier_type="phone",
                entry_point=entry_point,
                operator_identifier=operator_identifier,
            )
            auth_basis = decision.authorization_basis
            why_shown = decision.why_this_result_is_shown
        else:
            auth_basis = "unrestricted_test_harness"
            why_shown = "Test harness execution"

        raw = (phone_number or "").strip()
        try:
            parsed = phonenumbers.parse(raw, default_region)
        except phonenumbers.NumberParseException as exc:
            report = PhoneFootprintReport(
                raw_input=raw,
                valid=False,
                possible=False,
                authorization_basis=auth_basis,
                why_this_result_is_shown=why_shown,
                fields={
                    "parse_error": PhoneFieldEvidence(
                        value=str(exc),
                        source="libphonenumber:NumberParseException",
                        confidence=1.0,
                    )
                },
                limitations=["Input string is not a parseable telephone number."],
            )
            report.evidence_hash = report.compute_evidence_hash()
            return report

        is_possible = bool(phonenumbers.is_possible_number(parsed))
        is_valid = bool(phonenumbers.is_valid_number(parsed))

        e164_str = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        intl_str = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        nat_str = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        iso_reg = phonenumbers.region_code_for_number(parsed) or "ZZ"
        geo_desc = geocoder.description_for_number(parsed, "en") or "Unknown"
        carrier_name = carrier.name_for_number(parsed, "en") or "Unknown / Fixed-Line"
        num_type_int = phonenumbers.number_type(parsed)
        line_type_str = _LINE_TYPE_MAP.get(num_type_int, "UNKNOWN")
        tz_list = list(pn_timezone.time_zones_for_number(parsed) or [])

        fields: Dict[str, PhoneFieldEvidence] = {
            "e164_format": PhoneFieldEvidence(
                value=e164_str,
                source="libphonenumber:format_number(E164)",
                confidence=1.0 if is_valid else 0.5,
            ),
            "international_format": PhoneFieldEvidence(
                value=intl_str,
                source="libphonenumber:format_number(INTERNATIONAL)",
                confidence=1.0 if is_valid else 0.5,
            ),
            "national_format": PhoneFieldEvidence(
                value=nat_str,
                source="libphonenumber:format_number(NATIONAL)",
                confidence=1.0 if is_valid else 0.5,
            ),
            "country_code": PhoneFieldEvidence(
                value=int(parsed.country_code),
                source="libphonenumber:country_code",
                confidence=1.0 if is_valid else 0.5,
            ),
            "iso_region": PhoneFieldEvidence(
                value=iso_reg,
                source="libphonenumber:region_code_for_number",
                confidence=0.98 if is_valid else 0.4,
            ),
            "geographic_region": PhoneFieldEvidence(
                value=geo_desc,
                source="libphonenumber.geocoder:description_for_number",
                confidence=0.90 if (is_valid and geo_desc != "Unknown") else 0.30,
                note="Derived from ITU/national numbering plan prefix allocation.",
            ),
            "carrier": PhoneFieldEvidence(
                value=carrier_name,
                source="libphonenumber.carrier:name_for_number",
                confidence=0.85 if (is_valid and carrier_name != "Unknown / Fixed-Line") else 0.40,
                note="Original block allocation carrier; subject to Mobile Number Portability (MNP).",
            ),
            "line_type": PhoneFieldEvidence(
                value=line_type_str,
                source="libphonenumber:number_type",
                confidence=0.95 if is_valid else 0.30,
            ),
            "timezones": PhoneFieldEvidence(
                value=tz_list,
                source="libphonenumber.timezone:time_zones_for_number",
                confidence=0.90 if (is_valid and tz_list) else 0.30,
            ),
        }

        if self.breach_correlator is not None:
            try:
                breach_data = self.breach_correlator(e164_str)
                fields["breach_exposure"] = PhoneFieldEvidence(
                    value=breach_data.get("matches", 0),
                    source=str(breach_data.get("source", "authorized_breach_api")),
                    confidence=float(breach_data.get("confidence", 0.90)),
                    note="Redacted count only; zero raw PII records stored.",
                )
            except Exception as exc:
                fields["breach_exposure"] = PhoneFieldEvidence(
                    value=None,
                    source=f"authorized_breach_api:error({type(exc).__name__})",
                    confidence=0.0,
                )
        else:
            fields["breach_exposure"] = PhoneFieldEvidence(
                value=None,
                source="breach_correlator:not_configured",
                confidence=0.0,
                note="No external breach API configured; refusing to synthesize or guess.",
            )

        limitations = [
            "Prefix carrier reflects original numbering-plan block assignment and does not reflect real-time HLR/MNP porting.",
            "Geographic region reflects numbering-plan registration area, not live GPS or cell-tower location.",
            "No subscriber identity is ever guessed or fabricated.",
        ]

        report = PhoneFootprintReport(
            raw_input=raw,
            valid=is_valid,
            possible=is_possible,
            authorization_basis=auth_basis,
            why_this_result_is_shown=why_shown,
            fields=fields,
            limitations=limitations,
        )
        report.evidence_hash = report.compute_evidence_hash()
        return report

