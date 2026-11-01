from datetime import timedelta
from typing import List, Optional

from database.models import ErrorExample, utc_now
from database.repositories import error_repo


class ErrorStore:
    """Manage and learn from mistakes to prevent recurrence."""

    async def add(
        self,
        problem: str,
        wrong_answer: str,
        correct_answer: str,
        error_category: str,
        lesson: str,
    ) -> ErrorExample:
        """Log a mistake with root cause and lesson learned."""
        return error_repo.create(
            problem=problem,
            wrong_answer=wrong_answer,
            correct_answer=correct_answer,
            error_category=error_category,
            learned_lesson=lesson,
        )

    async def increment_occurrence(self, error_id: int) -> None:
        """Track recurring error occurrences."""
        error_repo.increment_occurrence(error_id)

    async def mark_fixed(self, error_id: int) -> None:
        """Mark an error as resolved in subsequent iterations."""
        error_repo.mark_fixed(error_id)

    async def get_recent_unfixed(self, days: int = 7) -> List[ErrorExample]:
        """Get recent unfixed errors for inclusion in system prompts."""
        cutoff = utc_now() - timedelta(days=days)
        return error_repo.get_unfixed_after(cutoff)

    async def get_by_category(self, category: str) -> List[ErrorExample]:
        """Get errors filtered by security category."""
        return error_repo.get_by_category(category)

    async def get_all(self) -> List[ErrorExample]:
        """Get all logged errors."""
        return error_repo.get_all()


# Singleton instance
error_store = ErrorStore()
