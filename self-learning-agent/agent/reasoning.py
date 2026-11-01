"""Reasoning engine implementing structured 4-step cybersecurity problem decomposition."""

from typing import Any, Dict, List, Optional

from utils.helpers import LLMClient, get_llm_client


class ReasoningEngine:
    """Multi-step reasoning pipeline for cybersecurity problem solving."""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or get_llm_client()

    async def reason(
        self,
        problem: str,
        experiences: List[Dict[str, Any]],
        errors: List[Any],
    ) -> Dict[str, Any]:
        """Execute a 4-step reasoning process: match, hypothesize, solve, critique."""
        exp_summary = "\n".join(
            f"- {e.get('experience').pattern}" for e in experiences if e.get("experience")
        ) if experiences else "None"

        err_summary = "\n".join(
            f"- Avoid {err.wrong_answer[:80]} because {err.learned_lesson[:80]}"
            for err in errors[:3]
        ) if errors else "None"

        system_prompt = (
            "You are an analytical cybersecurity reasoning engine.\n"
            "Decompose the problem systematically into:\n"
            "1. Pattern Recognition\n"
            "2. Attack Surface / Cipher Formulation\n"
            "3. Step-by-step Solution Path\n"
            "4. Edge Case Verification"
        )

        user_prompt = (
            f"TARGET PROBLEM: {problem}\n\n"
            f"PAST SIMILAR EXPERIENCES:\n{exp_summary}\n\n"
            f"KNOWN PITFALLS TO AVOID:\n{err_summary}\n"
        )

        raw_reasoning = await self.llm.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=1500,
        )

        return {
            "analysis": raw_reasoning,
            "steps": [line.strip("- ") for line in raw_reasoning.splitlines() if line.strip().startswith("-")],
        }


# Singleton instance
reasoning_engine = ReasoningEngine()
