"""Audit and performance logging for the self-learning agent."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

os.makedirs("./logs", exist_ok=True)
logging.basicConfig(
    filename="./logs/agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("SelfLearningAgent")


class AuditLogger:
    """Structured audit and telemetry logging."""

    @staticmethod
    def log_interaction(
        problem: str,
        answer: str,
        confidence: float,
        response_time_ms: float,
        verified: bool,
        mode: str = "general",
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "interaction",
            "mode": mode,
            "problem": problem[:200],
            "answer_preview": answer[:200],
            "confidence": confidence,
            "response_time_ms": response_time_ms,
            "verified": verified,
        }
        logger.info(json.dumps(entry))

    @staticmethod
    def log_learning(experience_id: int, problem_type: str, pattern: str) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "experience_stored",
            "experience_id": experience_id,
            "problem_type": problem_type,
            "pattern": pattern,
        }
        logger.info(json.dumps(entry))

    @staticmethod
    def log_error(error_id: int, category: str, lesson: str) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "error_logged",
            "error_id": error_id,
            "category": category,
            "lesson": lesson,
        }
        logger.warning(json.dumps(entry))


audit_logger = AuditLogger()
