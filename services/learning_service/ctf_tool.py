import asyncio
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root and modules are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


class CTFTool:
    """Bridge between Self-Learning Agent and RedLoop CTF module."""

    VERIFIED_FLAG_PATTERNS = [
        r"CTF\{[^}]+\}",
        r"flag\{[^}]+\}",
        r"[Cc][Tt][Ff]\{[^}]+\}",
        r"KEY\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"secreT\{[^}]+\}",
        r"\{[^}]+flag[^}]*\}",
    ]

    def __init__(self):
        self.max_file_size_mb = 100
        self._init_ctf_module()

    def _init_ctf_module(self):
        """Initialize CTF module imports."""
        ctf_path = str(PROJECT_ROOT / "modules" / "ctf")
        if ctf_path not in sys.path:
            sys.path.insert(0, ctf_path)

    async def analyze_file_stream(
        self,
        file_stream: bytes,
        filename: str,
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze uploaded file bytes with the full CTF pipeline."""
        try:
            if len(file_stream) > self.max_file_size_mb * 1024 * 1024:
                return {
                    "success": False,
                    "error": f"File too large. Max {self.max_file_size_mb}MB",
                }

            safe_filename = Path(filename.replace("\\", "/")).name
            if not safe_filename:
                return {"success": False, "error": "A file name is required."}

            orchestrator_result = await self._run_orchestrator(
                safe_filename, file_stream
            )
            findings = self._extract_findings(orchestrator_result, safe_filename)
            return {"success": True, "result": findings}

        except Exception as e:
            return {"success": False, "error": f"CTF analysis failed: {str(e)}"}

    async def solve_file(self, file_path: str | Path) -> Dict[str, Any]:
        """Solve a CTF file given a local path."""
        p = Path(file_path)
        if not p.is_file():
            return {"success": False, "error": f"File not found: {file_path}"}
        if p.stat().st_size > self.max_file_size_mb * 1024 * 1024:
            return {
                "success": False,
                "error": f"File too large. Max {self.max_file_size_mb}MB",
            }
        with p.open("rb") as source:
            data = source.read(self.max_file_size_mb * 1024 * 1024 + 1)
        return await self.analyze_file_stream(data, p.name)

    async def _run_orchestrator(self, archive_name: str, archive_bytes: bytes):
        """Invoke CTFOrchestrator in an executor to avoid blocking the event loop."""
        from redloop.ctf_orchestrator import CTFOrchestrator

        orchestrator = CTFOrchestrator()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, orchestrator.solve_archive, archive_name, archive_bytes
        )

    def _extract_findings(self, result, filename: str) -> Dict[str, Any]:
        """Extract structured findings from orchestrator result."""
        findings = {
            "filename": filename,
            "flag_found": False,
            "flag": None,
            "category": "unknown",
            "steps": [],
            "confidence": 0.0,
            "decoding_attempts": [],
            "extracted_files": [],
            "flags": [],
        }

        # Check for flags directly
        flags = getattr(result, "flags", [])
        if flags:
            findings["flag_found"] = True
            findings["flag"] = flags[0]
            findings["flags"] = list(flags)
            findings["confidence"] = 95.0

        # Reports
        reports = getattr(result, "reports", [])
        for rep in reports:
            if hasattr(rep, "category") and rep.category:
                findings["category"] = rep.category
            if hasattr(rep, "extracted_files") and rep.extracted_files:
                findings["extracted_files"].extend(rep.extracted_files)
            if hasattr(rep, "attempts") and rep.attempts:
                for att in rep.attempts:
                    desc = f"Tier {att.tier} ({att.theory_name}): {'success' if att.success else 'failed'}"
                    findings["steps"].append(desc)
                    findings["decoding_attempts"].append(
                        {
                            "tier": att.tier,
                            "theory": att.theory_name,
                            "success": att.success,
                            "output_preview": (att.output or "")[:200],
                        }
                    )

        if not findings["flag_found"] and findings["steps"]:
            findings["confidence"] = 50.0

        if findings["flag_found"] and findings["flag"]:
            flag_ver = self.verify_flag(findings["flag"])
            findings["flag_verified"] = flag_ver.get("is_flag", False)

        return findings

    def verify_flag(self, text: str) -> Dict[str, Any]:
        """Check if text matches standard CTF flag formats."""
        for pattern in self.VERIFIED_FLAG_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return {
                    "is_flag": True,
                    "flag": match.group(0),
                    "pattern_matched": pattern,
                }
        return {
            "is_flag": False,
            "flag": text,
            "pattern_matched": None,
        }

    async def solve_text_challenge(self, challenge_text: str) -> Dict[str, Any]:
        """Solve text-based cryptography/encoding challenges."""
        try:
            detection = await self._detect_challenge_type(challenge_text)
            c_type = detection.get("type")

            if c_type == "base64":
                result = await self._decode_base64(challenge_text)
            elif c_type == "hex":
                result = await self._decode_hex(challenge_text)
            elif c_type == "xor":
                result = await self._analyze_xor(challenge_text)
            elif c_type == "rsa":
                result = await self._analyze_rsa(challenge_text)
            else:
                result = await self._general_crypto_analysis(challenge_text)

            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _detect_challenge_type(self, text: str) -> Dict[str, Any]:
        """Heuristic detection of challenge type."""
        combined = text.lower()
        if "xor" in combined:
            return {"type": "xor"}
        cleaned_hex = text.replace("0x", "").strip()
        if len(cleaned_hex) >= 8 and len(cleaned_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in cleaned_hex):
            return {"type": "hex"}
        if "base64" in combined or re.search(r"^[A-Za-z0-9+/=]{16,}$", text.strip()):
            return {"type": "base64"}
        if "rsa" in combined or "modulus" in combined or "n=" in combined:
            return {"type": "rsa"}
        if "aes" in combined:
            return {"type": "aes"}
        return {"type": "unknown", "sub_type": "general_crypto"}

    async def _decode_base64(self, text: str) -> Dict[str, Any]:
        """Attempt base64 decoding."""
        import base64

        try:
            cleaned = re.sub(r"\s+", "", text)
            decoded = base64.b64decode(cleaned).decode("utf-8", errors="replace")
            return {
                "success": True,
                "method": "base64",
                "decoded": decoded,
                "flag_check": self.verify_flag(decoded),
            }
        except Exception as exc:
            return {"success": False, "method": "base64", "error": str(exc)}

    async def _decode_hex(self, text: str) -> Dict[str, Any]:
        """Attempt hex decoding."""
        import binascii

        try:
            cleaned = text.replace("0x", "").strip()
            decoded = binascii.unhexlify(cleaned).decode("utf-8", errors="replace")
            return {
                "success": True,
                "method": "hex",
                "decoded": decoded,
                "flag_check": self.verify_flag(decoded),
            }
        except Exception as exc:
            return {"success": False, "method": "hex", "error": str(exc)}

    async def _analyze_xor(self, text: str) -> Dict[str, Any]:
        """Analyze single-byte XOR challenge."""
        import binascii

        try:
            cleaned = text.replace("0x", "").strip()
            data = binascii.unhexlify(cleaned)
            results = []
            for key in range(256):
                decrypted = bytes([b ^ key for b in data])
                try:
                    decoded = decrypted.decode("utf-8")
                    if self._looks_like_meaningful(decoded):
                        results.append(
                            {
                                "key": key,
                                "key_hex": hex(key),
                                "decoded": decoded,
                                "score": self._score_decryption(decoded),
                            }
                        )
                except UnicodeDecodeError:
                    continue

            results.sort(key=lambda x: x["score"], reverse=True)
            return {
                "success": True,
                "method": "single_byte_xor",
                "attempts": len(results),
                "top_results": results[:5],
            }
        except Exception as e:
            return {"success": False, "method": "xor", "error": str(e)}

    async def _analyze_rsa(self, text: str) -> Dict[str, Any]:
        """Analyze RSA parameters."""
        n_match = re.search(r"n\s*[=:]\s*([0-9a-fA-Fx]+)", text)
        e_match = re.search(r"e\s*[=:]\s*([0-9]+)", text)
        return {
            "success": True,
            "method": "rsa_analysis",
            "found_n": bool(n_match),
            "found_e": bool(e_match),
            "hints": [
                "Check if N is small or factorable via factordb",
                "Check for small exponent attack (e=3)",
                "Check for common modulus attack",
                "Check for Wiener's small private key attack",
            ],
        }

    async def _general_crypto_analysis(self, text: str) -> Dict[str, Any]:
        """General crypto heuristic analysis."""
        return {
            "success": True,
            "method": "general_analysis",
            "suggestions": [
                "Check encoding formats (base64, hex, base32, base58, urlencode)",
                "Check frequency analysis or rotation ciphers (Caesar / ROT13 / Vigenere)",
                "Look for embedded keys, IVs, or known plaintext flags (CTF{...})",
            ],
        }

    def _looks_like_meaningful(self, text: str) -> bool:
        if len(text) < 4:
            return False
        common_words = [
            "the", "and", "for", "are", "but", "not", "you", "all",
            "can", "flag", "ctf", "key", "password", "admin", "secret",
        ]
        words = re.findall(r"[a-zA-Z]+", text.lower())
        if not words:
            return False
        matches = sum(1 for w in words if w in common_words)
        return (matches / len(words)) > 0.15 or any(w in text.lower() for w in ("flag", "ctf"))

    def _score_decryption(self, text: str) -> float:
        score = 0.0
        if not text:
            return score
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        score += (printable / len(text)) * 40
        common_words = ["the", "and", "flag", "ctf", "key", "secret"]
        words = re.findall(r"[a-zA-Z]+", text.lower())
        found = sum(1 for w in words if w in common_words)
        score += min(found * 10, 30)
        if re.search(r"flag|ctf", text, re.IGNORECASE):
            score += 30
        return min(score, 100.0)
