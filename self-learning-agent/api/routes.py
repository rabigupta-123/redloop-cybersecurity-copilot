"""FastAPI router for self-learning agent endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent.self_learning_agent import SelfLearningAgent
from database.connection import get_db
from database.repositories import (
    agent_stats_repo,
    error_repo,
    experience_repo,
    finetune_job_repo,
)
from learning.data_generator import DataGenerator
from learning.finetune import FineTuningPipeline

router = APIRouter()
agent_instance = SelfLearningAgent(mode="general")


class ChatRequest(BaseModel):
    message: str
    mode: str = "general"
    feedback: Optional[str] = None


class FeedbackRequest(BaseModel):
    problem: str
    answer: str
    feedback: str
    experience_id: Optional[int] = None


@router.get("/health")
async def health_check():
    return {"status": "healthy", "service": "self-learning-agent"}


@router.post("/chat")
async def chat_endpoint(request: ChatRequest, db: Session = Depends(get_db)):
    """Solve cybersecurity query or process learning feedback."""
    agent = SelfLearningAgent(mode=request.mode)

    if request.feedback:
        last_answer = agent.last_response.get("answer", "") if agent.last_response else ""
        result = await agent.learn_from_feedback(
            request.message,
            last_answer,
            request.feedback,
        )
        return {"learning": result, "status": "learned"}

    result = await agent.solve(request.message)
    return result


@router.post("/feedback")
async def feedback_endpoint(request: FeedbackRequest):
    """Explicitly submit feedback on an answer to reinforce learning."""
    agent = SelfLearningAgent()
    result = await agent.learn_from_feedback(
        problem=request.problem,
        answer=request.answer,
        feedback=request.feedback,
    )
    return {"result": result, "status": "processed"}


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Retrieve recent agent interaction and accuracy stats."""
    recent = agent_stats_repo.get_recent(limit=7, db=db)
    return {
        "stats": [
            {
                "date": s.date.isoformat(),
                "total_interactions": s.total_interactions,
                "correct_interactions": s.correct_interactions,
                "success_rate": s.success_rate,
                "avg_confidence": s.avg_confidence,
                "avg_response_time_ms": s.avg_response_time_ms,
            }
            for s in recent
        ]
    }


@router.get("/experiences")
async def list_experiences(db: Session = Depends(get_db)):
    """List all accumulated problem-solving experiences."""
    experiences = experience_repo.get_all(db=db)
    return {
        "experiences": [
            {
                "id": e.id,
                "type": e.problem_type,
                "pattern": e.pattern,
                "confidence": e.confidence,
                "success_count": e.success_count,
                "tags": e.tags,
            }
            for e in experiences
        ]
    }


@router.get("/errors")
async def list_errors(db: Session = Depends(get_db)):
    """List logged mistakes and lessons learned."""
    errors = error_repo.get_all(db=db)
    return {
        "errors": [
            {
                "id": err.id,
                "category": err.error_category,
                "problem": err.problem[:150],
                "lesson": err.learned_lesson,
                "occurrence_count": err.occurrence_count,
                "is_fixed": err.is_fixed,
            }
            for err in errors
        ]
    }


@router.post("/generate-training-data")
async def generate_training_data():
    """Generate fine-tuning examples from accumulated experiences."""
    generator = DataGenerator()
    positives = await generator.generate_from_experiences()
    negatives = await generator.generate_from_errors()
    total_saved = await generator.save_to_db(positives + negatives)
    return {"generated_examples": total_saved}


@router.post("/finetune")
async def trigger_finetune():
    """Return an explicit unavailable response until a training backend exists."""
    pipeline = FineTuningPipeline()
    try:
        await pipeline.create_finetune_job()
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    raise HTTPException(status_code=500, detail="Fine-tuning returned an invalid result.")
