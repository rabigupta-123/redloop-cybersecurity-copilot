import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class BaseAgent(ABC):
    """Base agent with common parsing and context-building functionality."""

    def __init__(self, mode: str = "general"):
        self.mode = mode
        self.last_response: Optional[Dict[str, Any]] = None
        self.response_time_ms: float = 0.0
        self.tokens_used: int = 0

    @abstractmethod
    async def solve(self, problem: str, **kwargs) -> Dict[str, Any]:
        """Solve a problem - implement in subclass."""
        pass

    def get_tools(self) -> List[str]:
        """Return available security tool names."""
        return [
            "experience_retrieval",
            "pattern_matcher",
            "verification_engine",
            "error_checker",
        ]

    def build_context(self, problem: str) -> Dict[str, Any]:
        """Build standard context structure."""
        return {
            "problem": problem,
            "agent_mode": self.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def format_response(
        self,
        answer: str,
        reasoning: List[str],
        confidence: float,
        learning: str = "",
        uncertainty: str = "NONE",
    ) -> str:
        """Format response into the standard structured format."""
        reasoning_str = "\n".join(f"- {r}" for r in reasoning)
        return (
            f"ANSWER: {answer}\n\n"
            f"REASONING:\n{reasoning_str}\n\n"
            f"CONFIDENCE: {confidence}\n"
            f"LEARNING: {learning}\n"
            f"UNCERTAINTY: {uncertainty}"
        )

    def analyze_response(self, response: str) -> Dict[str, Any]:
        """Parse formatted structured response."""
        result: Dict[str, Any] = {
            "answer": "",
            "reasoning": [],
            "confidence": 0.0,
            "learning": "",
            "uncertainty": "NONE",
        }

        try:
            lines = response.split("\n")
            current = None
            for line in lines:
                sline = line.strip()
                if line.startswith("ANSWER:"):
                    current = "answer"
                    result["answer"] = line[len("ANSWER:"):].strip()
                elif line.startswith("REASONING:"):
                    current = "reasoning"
                elif line.startswith("CONFIDENCE:"):
                    current = "confidence"
                    raw_val = line.split(":", 1)[1].strip().replace("%", "")
                    try:
                        result["confidence"] = float(raw_val)
                    except ValueError:
                        result["confidence"] = 75.0
                elif line.startswith("LEARNING:"):
                    current = "learning"
                    result["learning"] = line[len("LEARNING:"):].strip()
                elif line.startswith("UNCERTAINTY:"):
                    current = "uncertainty"
                    result["uncertainty"] = line[len("UNCERTAINTY:"):].strip()
                elif current == "reasoning" and sline.startswith("-"):
                    result["reasoning"].append(sline[1:].strip())
                elif current == "answer" and sline and not sline.startswith(("REASONING:", "CONFIDENCE:", "LEARNING:", "UNCERTAINTY:")):
                    if result["answer"]:
                        result["answer"] += " " + sline
                    else:
                        result["answer"] = sline
        except Exception:
            result["answer"] = response

        if not result["answer"]:
            result["answer"] = response

        return result
