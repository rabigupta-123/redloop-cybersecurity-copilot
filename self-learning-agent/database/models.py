from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String, Text

from database.connection import Base


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Experience(Base):
    """Successful problem-solving memories."""
    __tablename__ = "experiences"

    id = Column(Integer, primary_key=True, index=True)
    problem_type = Column(String(50), index=True)  # crypto, web, pwn, recon, etc.
    tags = Column(JSON, default=list)  # List of tags
    pattern = Column(String(500))  # Brief pattern description
    approach = Column(Text)  # Step-by-step approach
    example_prompt = Column(String(1000))  # Short example
    embedding = Column(Text, nullable=True)  # Vector embedding (Chroma ID or serialized vector)
    confidence = Column(Float, default=0.0)
    success_count = Column(Integer, default=1)
    last_used = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)

    def __repr__(self):
        return f"<Experience(type={self.problem_type}, confidence={self.confidence})>"


class ErrorExample(Base):
    """Mistakes to learn from."""
    __tablename__ = "error_examples"

    id = Column(Integer, primary_key=True, index=True)
    problem = Column(Text)
    wrong_answer = Column(Text)
    correct_answer = Column(Text)
    error_category = Column(String(50), index=True)
    learned_lesson = Column(Text)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)
    occurrence_count = Column(Integer, default=1)
    is_fixed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)

    def __repr__(self):
        return f"<ErrorExample(category={self.error_category}, count={self.occurrence_count})>"


class TrainingExample(Base):
    """Generated training data for fine-tuning."""
    __tablename__ = "training_examples"

    id = Column(Integer, primary_key=True, index=True)
    prompt = Column(Text)
    completion = Column(Text)
    quality_score = Column(Float, default=0.0)  # AI-evaluated quality
    source_experience_id = Column(Integer, nullable=True)
    source_error_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    def __repr__(self):
        return f"<TrainingExample(id={self.id}, quality={self.quality_score})>"


class AgentStats(Base):
    """Performance tracking."""
    __tablename__ = "agent_stats"

    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime, default=utc_now, index=True)
    total_interactions = Column(Integer, default=0)
    correct_interactions = Column(Integer, default=0)
    experiences_added = Column(Integer, default=0)
    errors_logged = Column(Integer, default=0)
    avg_confidence = Column(Float, default=0.0)
    avg_response_time_ms = Column(Float, default=0.0)
    tokens_used = Column(Integer, default=0)

    @property
    def success_rate(self) -> float:
        if not self.total_interactions:
            return 0.0
        return self.correct_interactions / self.total_interactions


class FineTuneJob(Base):
    """Fine-tuning job tracking."""
    __tablename__ = "finetune_jobs"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(20), default="pending")  # pending/running/completed/failed
    base_model = Column(String(100))
    output_dir = Column(String(200))
    training_examples_count = Column(Integer, default=0)
    loss = Column(Float, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)
