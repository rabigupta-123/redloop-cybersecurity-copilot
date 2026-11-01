import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Self-Learning Cyber Agent"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./self_learning.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # LLM
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    MAX_TOKENS: int = 4096

    # Self-Learning
    LEARNING_ENABLED: bool = True
    MIN_EXPERIENCES_FOR_FT: int = 100
    RETAIN_ERRORS_DAYS: int = 90
    WEEKLY_FINETUNE: bool = True

    # Retrieval
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    RETRIEVE_TOP_K: int = 3
    MIN_CONFIDENCE_FOR_REUSE: float = 0.8

    # Fine-tuning
    FINETUNE_BASE_MODEL: str = "meta-llama/Meta-Llama-3.1-8B"
    FINETUNE_OUTPUT_DIR: str = "./fine_tuned_models"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
