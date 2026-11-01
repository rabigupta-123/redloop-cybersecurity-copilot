"""Tier 1: Fast, deterministic, local decoders for CTF artifacts.

Attempts common encodings in Python without LLM calls:
- Base64 (standard and URL-safe, with padding correction)
- Base32
- Base16 / Hex
- ROT13 and all 25 Caesar shifts
- Gzip, Zlib, and Bzip2 decompression
- Single-byte XOR brute force across all 256 keys
- URL decoding

Checks find_flags() after each step and returns as soon as a flag matches.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import re
import urllib.parse
import zlib
from typing import Callable, Iterable

from redloop.ctf_files import find_flags

_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_BASE32_PATTERN = re.compile(r"[A-Z2-7]{16,}={0,6}", re.IGNORECASE)


def try_base64_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt direct and token-based Base64 decoding."""
    flags: set[str] = set()

    # 1. Direct decode of whole payload (stripped)
    text = data.strip().decode("ascii", errors="ignore")
    if text:
        padded = text + "=" * (-len(text) % 4)
        for alt in (None, b"-_"):
            try:
                decoded = base64.b64decode(padded.encode("ascii"), altchars=alt, validate=False)
                flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
                flags.update(find_flags(decoded.decode("latin-1", errors="ignore"), custom_prefixes))
            except Exception:
                pass

    # 2. Extract base64 candidate substrings
    raw_text = data.decode("utf-8", errors="ignore")
    for match in _BASE64_PATTERN.finditer(raw_text):
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        for alt in (None, b"-_"):
            try:
                decoded = base64.b64decode(padded.encode("ascii"), altchars=alt, validate=False)
                flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
            except Exception:
                pass

    return sorted(flags)


def try_base32_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt Base32 decoding."""
    flags: set[str] = set()
    text = data.strip().decode("ascii", errors="ignore")
    if text:
        padded = text + "=" * (-len(text) % 8)
        try:
            decoded = base64.b32decode(padded.encode("ascii"), casefold=True)
            flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
        except Exception:
            pass

    raw_text = data.decode("utf-8", errors="ignore")
    for match in _BASE32_PATTERN.finditer(raw_text):
        token = match.group(0)
        padded = token + "=" * (-len(token) % 8)
        try:
            decoded = base64.b32decode(padded.encode("ascii"), casefold=True)
            flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
        except Exception:
            pass

    return sorted(flags)


def try_hex_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt hex decoding."""
    flags: set[str] = set()
    text = "".join(data.decode("ascii", errors="ignore").split())
    if len(text) % 2 == 0 and len(text) >= 8:
        try:
            decoded = bytes.fromhex(text)
            flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
        except ValueError:
            pass

    raw_text = data.decode("utf-8", errors="ignore")
    for match in _HEX_PATTERN.finditer(raw_text):
        token = match.group(0)
        if len(token) % 2 == 0:
            try:
                decoded = bytes.fromhex(token)
                flags.update(find_flags(decoded.decode("utf-8", errors="ignore"), custom_prefixes))
            except ValueError:
                pass

    return sorted(flags)


def try_rot_and_caesar_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt ROT13 and all 25 Caesar shifts."""
    flags: set[str] = set()
    raw_text = data.decode("utf-8", errors="ignore")
    if not raw_text.strip():
        return []

    valid_prefixes = tuple(["flag{", "ctf{"] + [p.lower() + "{" for p in (custom_prefixes or [])])

    # ROT13
    rot13_text = codecs.encode(raw_text, "rot_13")
    for f in find_flags(rot13_text, custom_prefixes):
        if f.lower().startswith(valid_prefixes):
            flags.add(f)

    # All Caesar shifts 1-25
    for shift in range(1, 26):
        if shift == 13:
            continue
        shifted = []
        for ch in raw_text:
            if "a" <= ch <= "z":
                shifted.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            elif "A" <= ch <= "Z":
                shifted.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            else:
                shifted.append(ch)
        caesar_text = "".join(shifted)
        for f in find_flags(caesar_text, custom_prefixes):
            if f.lower().startswith(valid_prefixes):
                flags.add(f)

    return sorted(flags)


def try_compression_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt gzip, zlib, and bzip2 decompression."""
    flags: set[str] = set()

    # 1. Gzip
    if data.startswith(b"\x1f\x8b") or b"\x1f\x8b" in data[:1024]:
        offset = data.find(b"\x1f\x8b")
        try:
            decompressed = gzip.decompress(data[offset:])
            flags.update(find_flags(decompressed.decode("utf-8", errors="ignore"), custom_prefixes))
        except Exception:
            pass

    # 2. Zlib
    try:
        decompressed = zlib.decompress(data)
        flags.update(find_flags(decompressed.decode("utf-8", errors="ignore"), custom_prefixes))
    except Exception:
        # Scan for zlib header \x78\x9c, \x78\xda, \x78\x01
        for marker in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):
            idx = data.find(marker)
            if idx >= 0:
                try:
                    decompressed = zlib.decompress(data[idx:])
                    flags.update(find_flags(decompressed.decode("utf-8", errors="ignore"), custom_prefixes))
                except Exception:
                    pass

    # 3. Bzip2
    if data.startswith(b"BZh") or b"BZh" in data[:1024]:
        idx = data.find(b"BZh")
        try:
            decompressed = bz2.decompress(data[idx:])
            flags.update(find_flags(decompressed.decode("utf-8", errors="ignore"), custom_prefixes))
        except Exception:
            pass

    return sorted(flags)


def try_single_byte_xor_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Brute force single-byte XOR against all 256 keys."""
    flags: set[str] = set()
    # Limit XOR testing to first 64KB for speed
    chunk = data[:65_536]
    for key in range(1, 256):
        xored = bytes(b ^ key for b in chunk)
        # Fast check: see if flag prefix occurs in xored bytes
        if b"flag{" in xored.lower() or b"ctf{" in xored.lower() or (
            custom_prefixes and any(p.encode("ascii", errors="ignore").lower() in xored.lower() for p in custom_prefixes)
        ):
            decoded_text = xored.decode("utf-8", errors="ignore")
            found = find_flags(decoded_text, custom_prefixes)
            if found:
                flags.update(found)
    return sorted(flags)


def try_url_decode(data: bytes, custom_prefixes: list[str] | None = None) -> list[str]:
    """Attempt URL unquoting."""
    flags: set[str] = set()
    text = data.decode("utf-8", errors="ignore")
    if "%" in text:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            flags.update(find_flags(unquoted, custom_prefixes))
        unquoted_plus = urllib.parse.unquote_plus(text)
        if unquoted_plus != text and unquoted_plus != unquoted:
            flags.update(find_flags(unquoted_plus, custom_prefixes))
    return sorted(flags)


class Tier1Decoders:
    """Orchestrates all Tier 1 deterministic decoders in sequence."""

    DECODERS: list[tuple[str, Callable[[bytes, list[str] | None], list[str]]]] = [
        ("base64", try_base64_decode),
        ("hex", try_hex_decode),
        ("rot13_caesar", try_rot_and_caesar_decode),
        ("compression", try_compression_decode),
        ("single_byte_xor", try_single_byte_xor_decode),
        ("url_decode", try_url_decode),
        ("base32", try_base32_decode),
    ]

    @classmethod
    def execute(
        cls,
        data: bytes,
        custom_prefixes: list[str] | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Run all Tier 1 decoders on data, returning (flags_found, methods_used)."""
        methods_used: list[str] = []
        all_flags: set[str] = set()

        # Check raw content
        raw_text = data.decode("utf-8", errors="ignore")
        initial_flags = find_flags(raw_text, custom_prefixes)
        if initial_flags:
            all_flags.update(initial_flags)
            methods_used.append("raw")
            if on_progress:
                on_progress(f"Tier 1 matched flag directly in raw content: {initial_flags[0]}")

        # Check all Tier 1 deterministic decoders
        for name, decoder_fn in cls.DECODERS:
            try:
                flags = decoder_fn(data, custom_prefixes)
                if flags:
                    methods_used.append(name)
                    all_flags.update(flags)
                    if on_progress:
                        on_progress(f"Tier 1 strategy '{name}' matched flag: {flags[0]}")
            except Exception:
                continue

        return sorted(all_flags), methods_used
