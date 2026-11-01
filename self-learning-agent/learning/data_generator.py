"""Generate training data from successful experiences and negative error examples."""

from typing import Any, Dict, List, Optional

from database.repositories import error_repo, experience_repo, training_example_repo


class DataGenerator:
    """Generate fine-tuning and DPO training examples from experiences and errors."""

    async def generate_from_experiences(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Generate positive training examples from verified problem solutions."""
        experiences = experience_repo.get_all()[:limit]
        examples = []
        for exp in experiences:
            examples.append({
                "prompt": exp.example_prompt or f"How do I solve this {exp.problem_type} challenge?",
                "completion": exp.approach or exp.pattern,
                "source": f"experience_{exp.id}",
                "quality_score": (
                    exp.confidence if exp.confidence is not None else 0.0
                ),
            })
        return examples

    async def generate_from_errors(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Generate negative/contrastive training examples from mistakes."""
        errors = error_repo.get_all()[:limit]
        examples = []
        for err in errors:
            examples.append({
                "prompt": err.problem,
                "completion": err.correct_answer or "Avoid previous incorrect assumption.",
                "warning": err.learned_lesson,
                "source": f"error_{err.id}",
                "quality_score": 0.0,
            })
        return examples

    async def save_to_db(self, examples: List[Dict[str, Any]]) -> int:
        """Persist generated training examples to database."""
        saved = 0
        for example in examples:
            try:
                training_example_repo.create(
                    prompt=example["prompt"],
                    completion=example["completion"],
                    quality_score=example.get("quality_score", 0.9),
                    source_experience_id=self._extract_id(example.get("source", ""), "experience"),
                    source_error_id=self._extract_id(example.get("source", ""), "error"),
                )
                saved += 1
            except Exception as e:
                print(f"Failed to save training example: {e}")
        return saved

    @staticmethod
    def _extract_id(source: str, prefix: str) -> Optional[int]:
        try:
            if source.startswith(prefix):
                return int(source.split("_")[-1])
        except Exception:
            pass
        return None
