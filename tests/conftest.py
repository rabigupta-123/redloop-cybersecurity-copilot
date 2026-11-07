"""Pytest root configuration and fixture definitions."""
from __future__ import annotations

# Preload heavy modules during test runner initialization so individual test
# timeouts are not consumed by lazy module imports under coverage tracing.
try:
    import phonenumbers
    from phonenumbers import geocoder
except Exception:
    pass

