"""Assert WCAG AA contrast for the shared REDLOOP theme tokens.

Reads the single source of truth (``redloop.dashboard.THEME_TOKENS_CSS``) so the
check can never drift from the shipped palette. Exits non-zero on failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redloop.dashboard import THEME_TOKENS_CSS  # noqa: E402

TOKEN_RE = re.compile(r"(--[a-z0-9-]+)\s*:\s*([^;]+);")


def parse_block(selector: str, css: str) -> dict[str, str]:
    match = re.search(re.escape(selector) + r"\s*\{(.*?)\}", css, re.S)
    if not match:
        raise SystemExit(f"missing token block: {selector}")
    return {name: value.strip() for name, value in TOKEN_RE.findall(match.group(1))}


def hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.strip()
    if value.startswith("rgb"):
        parts = [int(float(p)) for p in re.findall(r"[\d.]+", value)[:3]]
        return parts[0], parts[1], parts[2]
    value = value.lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def channel_luminance(channel: int) -> float:
    srgb = channel / 255
    return srgb / 12.92 if srgb <= 0.04045 else ((srgb + 0.055) / 1.055) ** 2.4


def luminance(value: str) -> float:
    r, g, b = (channel_luminance(c) for c in hex_to_rgb(value))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    high, low = max(a, b), min(a, b)
    return (high + 0.05) / (low + 0.05)


PAIRS = [
    ("text", "--fg", "--bg", 4.5),
    ("text", "--fg", "--surface", 4.5),
    ("text", "--fg", "--surface-2", 4.5),
    ("text muted", "--fg-muted", "--bg", 4.5),
    ("text muted", "--fg-muted", "--surface", 4.5),
    ("text muted", "--fg-muted", "--surface-2", 4.5),
    ("placeholder", "--fg-subtle", "--surface", 4.5),
    ("accent strong (UI/large)", "--accent-strong", "--surface", 3.0),
    ("accent ink (text)", "--accent-ink", "--surface", 4.5),
    ("primary button label", "#FFFFFF", "--accent-button", 4.5),
    ("primary button label hover", "#FFFFFF", "--accent-button-hover", 4.5),
    ("critical badge text", "--critical", "--surface", 4.5),
    ("warning badge text", "--warning-strong", "--surface", 4.5),
    ("success badge text", "--success-strong", "--surface", 4.5),
    ("info badge text", "--info-strong", "--surface", 4.5),
    ("focus ring", "--accent-strong", "--surface", 3.0),
]


def main() -> int:
    themes = {
        "dark": parse_block(":root", THEME_TOKENS_CSS),
        "light": parse_block(':root[data-theme="light"]', THEME_TOKENS_CSS),
    }
    failures: list[str] = []
    for theme, tokens in themes.items():
        print(f"\n{theme} theme")
        for label, fg_key, bg_key, minimum in PAIRS:
            fg = tokens.get(fg_key, fg_key)
            bg = tokens.get(bg_key, bg_key)
            if fg is None or bg is None:
                failures.append(f"{theme}: {label} missing token")
                continue
            value = ratio(fg, bg)
            status = "PASS" if value >= minimum else "FAIL"
            if status == "FAIL":
                failures.append(f"{theme}: {label} {fg} on {bg} = {value:.2f} (< {minimum})")
            print(f"  {status}  {label:<30} {value:5.2f}  (min {minimum})")
    if failures:
        print("\nCONTRAST FAILURES:")
        for item in failures:
            print(" -", item)
        return 1
    print("\nAll contrast pairs pass WCAG AA.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
