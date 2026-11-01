from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent.self_learning_agent import SelfLearningAgent
from api.routes import router
from database.connection import get_db, init_db
from database.repositories import agent_stats_repo, experience_repo
from learning.data_generator import DataGenerator


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    init_db()
    print("Self-Learning Cyber Agent initialized.")
    yield
    print("Self-Learning Cyber Agent shutting down.")


app = FastAPI(
    title="Self-Learning Cyber Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(?:localhost|127\.0\.0\.1)(?::\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Include API v1 router
app.include_router(router, prefix="/api/v1")


class RootChatRequest(BaseModel):
    message: str
    mode: str = "general"
    feedback: Optional[str] = None


@app.post("/chat")
async def chat_root(request: RootChatRequest, db: Session = Depends(get_db)):
    """Direct root chat endpoint matching prompt specification."""
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


@app.get("/stats")
async def get_stats_root(db: Session = Depends(get_db)):
    """Get agent statistics at root."""
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


@app.post("/generate-training-data")
async def generate_training_data_root():
    """Generate training data from accumulated experiences at root."""
    generator = DataGenerator()
    positives = await generator.generate_from_experiences()
    negatives = await generator.generate_from_errors()
    count = await generator.save_to_db(positives + negatives)
    return {"generated": count}


@app.get("/experiences")
async def list_experiences_root(db: Session = Depends(get_db)):
    """List stored experiences at root."""
    experiences = experience_repo.get_all(db=db)
    return {
        "experiences": [
            {
                "id": e.id,
                "type": e.problem_type,
                "pattern": e.pattern,
                "confidence": e.confidence,
                "success_count": e.success_count,
            }
            for e in experiences
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
