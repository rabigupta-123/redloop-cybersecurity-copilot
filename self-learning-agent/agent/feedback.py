"""Feedback processor: extracts insights from user praise or corrections."""

from typing import Any, Dict, Optional

from memory.error_store import error_store
from memory.experience_store import experience_store
from utils.helpers import LLMClient, get_llm_client


class FeedbackProcessor:
    """Processes user ratings, corrections, and reviews to drive agent self-learning."""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or get_llm_client()

    def is_positive(self, feedback: str) -> bool:
        low = feedback.lower()
        positive_cues = ["correct", "yes", "success", "accurate", "good", "perfect", "well done", "nice", "+1"]
        negative_cues = ["wrong", "incorrect", "no", "false", "failed", "error", "bad", "-1"]

        has_pos = any(cue in low for cue in positive_cues)
        has_neg = any(cue in low for cue in negative_cues)

        if has_pos and not has_neg:
            return True
        if has_neg and not has_pos:
            return False
        return not has_neg

    async def process(
        self,
        problem: str,
        answer: str,
        feedback: str,
        experience_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Process feedback and update memory stores accordingly."""
        if self.is_positive(feedback):
            if experience_id:
                await experience_store.increment_success(experience_id)
            return {"status": "positive", "action": "reinforced_experience"}
        else:
            return {"status": "negative", "action": "needs_error_logging"}


# Singleton instance
feedback_processor = FeedbackProcessor()
