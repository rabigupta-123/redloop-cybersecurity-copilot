import re
from typing import Any, Dict, Optional

from utils.helpers import LLMClient, get_llm_client


class VerificationEngine:
    """Verify and self-critique agent outputs."""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or get_llm_client()

    async def verify(self, answer: str, problem: str) -> Dict[str, Any]:
        """Verify answer correctness and consistency with cybersecurity principles."""
        try:
            critique = await self.llm.generate(
                system_prompt="You are a rigorous verification engine for cybersecurity solutions. Critique this answer objectively.",
                user_prompt=(
                    f"PROBLEM: {problem}\n\n"
                    f"ANSWER: {answer}\n\n"
                    "Provide:\n"
                    "1. PASS or FAIL\n"
                    "2. Brief reason\n"
                    "3. Confidence in assessment (0-100)"
                ),
            )

            first_line = critique.strip().splitlines()[0].strip()
            is_pass = bool(re.match(r"^PASS(?:\b|:)", first_line, re.IGNORECASE))

            return {
                "passed": is_pass,
                "critique": critique,
                "confidence": self._extract_confidence(critique),
            }
        except Exception as e:
            return {
                "passed": False,
                "status": "unavailable",
                "error": type(e).__name__,
                "confidence": 0.0,
            }

    def _extract_confidence(self, text: str) -> float:
        """Extract confidence score from verification text."""
        match = re.search(r"confidence[:\s]+(\d+)", text.lower())
        if match:
            return float(match.group(1)) / 100.0
        return 0.85


# Singleton instance
verification_engine = VerificationEngine()
