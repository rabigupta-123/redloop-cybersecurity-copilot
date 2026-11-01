"""Fine-tuning availability for the optional learning service."""


class FineTuningPipeline:
    """Reports that fine-tuning is unavailable until a real training backend exists."""

    async def create_finetune_job(self) -> int:
        raise RuntimeError(
            "Fine-tuning is unavailable: no training backend is implemented."
        )
