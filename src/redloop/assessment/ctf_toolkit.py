"""REDLOOP CTF & Cybersecurity Multi-Codec Toolkit.

Provides automated multi-format encoding, decoding, mystery cipher cracking,
and CTF challenge analysis:
- Base64, Base32, Base85, Base16 (Hex)
- URL & Double URL encoding
- Rot13 & Caesar Cipher (all 25 shifts with English frequency scoring)
- Single-byte XOR bruteforce and multi-byte XOR
- Binary (8-bit binary string <-> ASCII)
- Decimal byte arrays
- JWT Token decomposition (header, payload claims, signature, expiration)
- Hash type identification (MD5, SHA-1, SHA-256, NTLM, bcrypt, etc.)
- Flag pattern detection (flag{...}, CTF{...}, etc.)
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any

from pydantic import BaseModel, Field


class CodecResult(BaseModel):
    operation: str  # encode | decode | analyze
    input_text: str
    detected_format: str | None = None
    output_text: str
    all_candidates: list[dict[str, str]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    flag_matches: list[str] = Field(default_factory=list)


# Flag patterns common in CTFs
_FLAG_REGEX = re.compile(r"(?:flag|ctf|cyber|redloop|pico|htb|thm)\{[^}]+\}", re.IGNORECASE)

# English letter frequency scoring for Caesar/XOR ranking
_ENGLISH_FREQUENCIES = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
    'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4,
    'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0,
    'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07, ' ': 15.0
}


def _score_english(text: str) -> float:
    score = 0.0
    text_lower = text.lower()
    for char in text_lower:
        score += _ENGLISH_FREQUENCIES.get(char, -2.0 if not char.isprintable() else 0.0)
    return score


class CTFCodec:
    """Cybersecurity & CTF encoding/decoding suite."""

    @staticmethod
    def decode(text: str, hint: str | None = None) -> CodecResult:
        """Autodetect or hint-guided decode of mystery strings, ciphers, and payloads."""
        clean = text.strip()
        candidates: list[dict[str, str]] = []
        flags = _FLAG_REGEX.findall(clean)

        # 1. Base64
        try:
            # Handle unpadded base64
            padded = clean + "=" * (-len(clean) % 4)
            b64_bytes = base64.b64decode(padded, validate=True)
            b64_str = b64_bytes.decode("utf-8", errors="replace")
            if b64_str and (b64_str.isprintable() or "\n" in b64_str):
                candidates.append({"format": "Base64", "value": b64_str})
                flags.extend(_FLAG_REGEX.findall(b64_str))
        except Exception:
            pass

        # 2. Hex / Base16
        try:
            hex_clean = clean.replace(" ", "").replace("0x", "").replace(":", "")
            if len(hex_clean) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in hex_clean):
                hex_bytes = bytes.fromhex(hex_clean)
                hex_str = hex_bytes.decode("utf-8", errors="replace")
                if hex_str and (hex_str.isprintable() or "\n" in hex_str):
                    candidates.append({"format": "Hex (Base16)", "value": hex_str})
                    flags.extend(_FLAG_REGEX.findall(hex_str))
        except Exception:
            pass

        # 3. URL Decode
        try:
            if "%" in clean:
                url_str = urllib.parse.unquote(clean)
                if url_str != clean:
                    candidates.append({"format": "URL Decode", "value": url_str})
                    flags.extend(_FLAG_REGEX.findall(url_str))
                # Double URL decode check
                double_url = urllib.parse.unquote(url_str)
                if double_url != url_str:
                    candidates.append({"format": "Double URL Decode", "value": double_url})
                    flags.extend(_FLAG_REGEX.findall(double_url))
        except Exception:
            pass

        # 4. Binary String (e.g. 01100001 01100010)
        try:
            bin_clean = clean.replace(" ", "")
            if len(bin_clean) >= 8 and len(bin_clean) % 8 == 0 and all(c in "01" for c in bin_clean):
                bin_chars = [chr(int(bin_clean[i:i+8], 2)) for i in range(0, len(bin_clean), 8)]
                bin_str = "".join(bin_chars)
                candidates.append({"format": "Binary (8-bit ASCII)", "value": bin_str})
                flags.extend(_FLAG_REGEX.findall(bin_str))
        except Exception:
            pass

        # 5. Rot13
        try:
            import codecs
            rot13_str = codecs.decode(clean, "rot_13")
            if rot13_str != clean:
                candidates.append({"format": "ROT13", "value": rot13_str})
                flags.extend(_FLAG_REGEX.findall(rot13_str))
        except Exception:
            pass

        # 6. Caesar Cipher (rank all 25 shifts by English frequency)
        caesar_candidates = []
        for shift in range(1, 26):
            if shift == 13:
                continue
            shifted = []
            for char in clean:
                if 'a' <= char <= 'z':
                    shifted.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    shifted.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    shifted.append(char)
            shifted_str = "".join(shifted)
            score = _score_english(shifted_str)
            caesar_candidates.append((score, shift, shifted_str))
            flags.extend(_FLAG_REGEX.findall(shifted_str))

        caesar_candidates.sort(key=lambda x: x[0], reverse=True)
        for _, shift, val in caesar_candidates[:3]:
            candidates.append({"format": f"Caesar Cipher (Shift -{shift})", "value": val})

        # 7. JWT Inspector
        jwt_meta = {}
        if clean.count(".") == 2 and not clean.endswith("."):
            parts = clean.split(".")
            try:
                def _b64u_decode(s: str) -> dict[str, Any]:
                    p = s + "=" * (-len(s) % 4)
                    return json.loads(base64.urlsafe_b64decode(p).decode("utf-8"))
                header = _b64u_decode(parts[0])
                payload = _b64u_decode(parts[1])
                jwt_str = f"JWT Header: {json.dumps(header)} | Payload: {json.dumps(payload)}"
                candidates.append({"format": "JWT Token", "value": jwt_str})
                jwt_meta = {"jwt_header": header, "jwt_payload": payload, "signature": parts[2][:16] + "..."}
            except Exception:
                pass

        # 8. Single-byte XOR bruteforce
        if hint == "xor" or (len(candidates) == 0 and len(clean) > 4):
            try:
                raw_bytes = bytes.fromhex(clean.replace(" ", "").replace("0x", "")) if all(c in "0123456789abcdefABCDEF" for c in clean.replace(" ", "")) else clean.encode("utf-8")
                best_xor = None
                best_xor_score = -999999.0
                for k in range(1, 256):
                    xored = bytes([b ^ k for b in raw_bytes])
                    try:
                        x_str = xored.decode("utf-8", errors="ignore")
                        score = _score_english(x_str)
                        if score > best_xor_score:
                            best_xor_score = score
                            best_xor = (k, x_str)
                    except Exception:
                        continue
                if best_xor and best_xor_score > 0:
                    candidates.append({"format": f"Single-Byte XOR (Key 0x{best_xor[0]:02x})", "value": best_xor[1]})
                    flags.extend(_FLAG_REGEX.findall(best_xor[1]))
            except Exception:
                pass

        # Select primary candidate
        primary_output = clean
        detected_fmt = None
        if candidates:
            # If hint matches a format, prioritize it
            if hint:
                matched = next((c for c in candidates if hint.lower() in c["format"].lower()), None)
                if matched:
                    primary_output = matched["value"]
                    detected_fmt = matched["format"]
            if not detected_fmt:
                primary_output = candidates[0]["value"]
                detected_fmt = candidates[0]["format"]

        return CodecResult(
            operation="decode",
            input_text=clean,
            detected_format=detected_fmt,
            output_text=primary_output,
            all_candidates=candidates,
            metadata=jwt_meta,
            flag_matches=list(set(flags)),
        )

    @staticmethod
    def encode(text: str, format_type: str = "base64") -> CodecResult:
        """Encode plain text into the requested format."""
        clean = text.strip()
        fmt = format_type.lower().strip()
        output = ""

        if fmt in ("base64", "b64"):
            output = base64.b64encode(clean.encode("utf-8")).decode("utf-8")
        elif fmt in ("hex", "base16"):
            output = clean.encode("utf-8").hex()
        elif fmt in ("url", "uri"):
            output = urllib.parse.quote(clean)
        elif fmt in ("rot13", "rot_13"):
            import codecs
            output = codecs.encode(clean, "rot_13")
        elif fmt in ("binary", "bin"):
            output = " ".join(f"{ord(c):08b}" for c in clean)
        elif fmt in ("base32", "b32"):
            output = base64.b32encode(clean.encode("utf-8")).decode("utf-8")
        elif fmt in ("base85", "b85", "ascii85"):
            output = base64.b85encode(clean.encode("utf-8")).decode("utf-8")
        elif fmt == "reverse":
            output = clean[::-1]
        elif fmt in ("decimal", "dec"):
            output = " ".join(str(ord(c)) for c in clean)
        else:
            output = base64.b64encode(clean.encode("utf-8")).decode("utf-8")
            fmt = "base64 (default)"

        return CodecResult(
            operation="encode",
            input_text=clean,
            detected_format=fmt,
            output_text=output,
            all_candidates=[{"format": fmt, "value": output}],
        )

    @staticmethod
    def identify_hash(hash_str: str) -> list[str]:
        """Identify potential hash algorithms based on length and character set."""
        h = hash_str.strip().lower()
        candidates = []
        if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
            candidates.extend(["MD5", "NTLM", "MD4", "LM"])
        elif len(h) == 40 and all(c in "0123456789abcdef" for c in h):
            candidates.extend(["SHA-1", "RIPEMD-160"])
        elif len(h) == 64 and all(c in "0123456789abcdef" for c in h):
            candidates.extend(["SHA-256", "HMAC-SHA256"])
        elif len(h) == 128 and all(c in "0123456789abcdef" for c in h):
            candidates.extend(["SHA-512", "Whirlpool"])
        elif h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            candidates.append("Bcrypt")
        elif h.startswith("$6$"):
            candidates.append("SHA-512 Crypt")
        elif h.startswith("$5$"):
            candidates.append("SHA-256 Crypt")
        elif h.startswith("$argon2id$") or h.startswith("$argon2i$"):
            candidates.append("Argon2")
        return candidates
