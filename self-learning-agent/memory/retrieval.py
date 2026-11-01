"""Offline lexical retrieval for stored cybersecurity experiences."""

import re
from typing import Any, Dict, List

from database.repositories import experience_repo


class RetrievalEngine:
    """Rank stored experiences by Jaccard overlap of normalized word tokens."""

    def retrieve_similar(self, problem: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if top_k <= 0:
            return []

        query_tokens = self._tokens(problem)
        if not query_tokens:
            return []

        ranked = []
        for experience in experience_repo.get_all():
            content = " ".join(
                (
                    experience.problem_type or "",
                    " ".join(str(tag) for tag in (experience.tags or [])),
                    experience.example_prompt or "",
                    experience.pattern or "",
                    experience.approach or "",
                )
            )
            experience_tokens = self._tokens(content)
            union = query_tokens | experience_tokens
            overlap = query_tokens & experience_tokens
            if not overlap or not union:
                continue

            ranked.append(
                {
                    "experience": experience,
                    "similarity": round(len(overlap) / len(union), 4),
                    "approach": experience.approach,
                }
            )

        ranked.sort(
            key=lambda result: (
                -result["similarity"],
                result["experience"].id,
            )
        )
        return ranked[:top_k]

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9]+", text.casefold())
            if len(token) > 1
        }


retrieval_engine = RetrievalEngine()
