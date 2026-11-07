"""Pytest root configuration and fixture definitions."""
from __future__ import annotations

# Preload heavy modules during test runner initialization so individual test
# timeouts are not consumed by lazy module imports under coverage tracing.
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
    _sample = phonenumbers.parse("+14155552671", None)
    _ = carrier.name_for_number(_sample, "en")
    _ = geocoder.description_for_number(_sample, "en")
except Exception:
    pass

