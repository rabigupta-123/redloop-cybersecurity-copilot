from typing import List

from database.models import Experience
from database.repositories import experience_repo


class ExperienceStore:
    """Manage successful problem-solving experiences."""

    async def add(
        self,
        problem_type: str,
        tags: List[str],
        pattern: str,
        approach: str,
        example_prompt: str,
        confidence: float = 0.0,
    ) -> Experience:
        """Store a new experience for offline lexical retrieval."""
        exp = experience_repo.create(
            problem_type=problem_type,
            tags=tags,
            pattern=pattern,
            approach=approach,
            example_prompt=example_prompt,
            confidence=confidence,
        )
        return exp

    async def increment_success(self, experience_id: int) -> None:
        """Increment success count when an experience is successfully reused."""
        experience_repo.increment_success(experience_id)

    async def get_by_type(self, problem_type: str, limit: int = 10) -> List[Experience]:
        """Get top experiences by category."""
        return experience_repo.get_by_type(problem_type, limit)

    async def get_all(self) -> List[Experience]:
        """Get all stored experiences."""
        return experience_repo.get_all()

    async def update_confidence(self, experience_id: int, new_confidence: float) -> None:
        """Update confidence based on user feedback or verification."""
        experience_repo.update_confidence(experience_id, new_confidence)


# Singleton instance
experience_store = ExperienceStore()
