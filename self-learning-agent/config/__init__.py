"""Configuration package for self-learning agent."""

from config.settings import Settings, get_settings
from config.prompts import (
    EFFICIENCY_SYSTEM_PROMPT,
    SELF_LEARNING_SYSTEM_PROMPT,
    AFTER_ACTION_REVIEW,
    SELF_CORRECTION,
    EXPERIENCE_STORAGE,
    BAD_EXAMPLE_LEARNER,
    DATA_GENERATOR,
)

__all__ = [
    "Settings",
    "get_settings",
    "EFFICIENCY_SYSTEM_PROMPT",
    "SELF_LEARNING_SYSTEM_PROMPT",
    "AFTER_ACTION_REVIEW",
    "SELF_CORRECTION",
    "EXPERIENCE_STORAGE",
    "BAD_EXAMPLE_LEARNER",
    "DATA_GENERATOR",
]
