import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Add project root and self-learning-agent root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
AGENT_ROOT = PROJECT_ROOT / "self-learning-agent"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from agent.self_learning_agent import SelfLearningAgent
from config.settings import get_settings
from database.connection import init_db
from database.repositories import experience_repo
from services.learning_service.ctf_tool import CTFTool
from services.learning_service.performance import metrics_collector

settings = get_settings()

agent: Optional[SelfLearningAgent] = None
agent_lock = asyncio.Lock()


class ChatRequest(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    message_id: Optional[str] = None


class FeedbackRequest(BaseModel):
    message_id: str
    feedback: str


class CTFAnalyzeRequest(BaseModel):
    source: str = "text"  # "file" | "text"
    filename: Optional[str] = None
    content: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global agent
    init_db()
    agent = SelfLearningAgent(mode="mythos")
    await agent.initialize()
    print("=" * 60)
    print("🧠 MYTHOS LEARNING SERVICE INITIALIZED")
    print(f"Model: {settings.LLM_MODEL}")
    print(f"Learning Enabled: {settings.LEARNING_ENABLED}")
    print("=" * 60)
    yield
    print("Mythos Learning Service shut down.")


app = FastAPI(
    title="Mythos Learning Service",
    version="2.0.0",
    description="Autonomous self-learning cybersecurity service with CTF module integration",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(?:localhost|127\.0\.0\.1)(?::\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Mythos Learning Service",
        "version": "2.0.0",
        "model": settings.LLM_MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/ask")
async def ask(request: ChatRequest):
    """Main ask endpoint with real-time Server-Sent Events (SSE) streaming."""
    global agent
    if agent is None:
        agent = SelfLearningAgent(mode="mythos")
        await agent.initialize()

    async def event_generator():
        try:
            message_id = request.message_id or f"msg_{int(datetime.now().timestamp() * 1000)}"

            # 1. Message start event
            start_payload = {
                "type": "message_start",
                "data": {"id": message_id, "timestamp": datetime.now(timezone.utc).isoformat()},
            }
            yield f"data: {json.dumps(start_payload)}\n\n"

            # 2. Stream answer chunks
            async for chunk in agent.stream_answer(request.message, request.context):
                data = {
                    "id": message_id,
                    "type": chunk.get("type", "text"),
                    "data": chunk.get("data", ""),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(0)

            # 3. Message end event
            end_payload = {
                "type": "message_end",
                "data": {"id": message_id},
            }
            yield f"data: {json.dumps(end_payload)}\n\n"

        except Exception as e:
            err_data = {
                "type": "error",
                "data": f"Inference error: {str(e)}",
                "error_type": type(e).__name__,
            }
            yield f"data: {json.dumps(err_data)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    """Real-time WebSocket chat endpoint."""
    global agent
    if agent is None:
        agent = SelfLearningAgent(mode="mythos")
        await agent.initialize()

    await websocket.accept()
    session_id = None

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                req_data = json.loads(raw)
                req = ChatRequest(**req_data)
            except Exception:
                req = ChatRequest(message=raw)

            session_id = req.session_id or session_id

            async for chunk in agent.stream_answer(req.message, req.context):
                ws_chunk = {
                    "type": chunk.get("type", "text"),
                    "data": chunk.get("data", ""),
                    "session_id": session_id,
                }
                await websocket.send_json(ws_chunk)

            await websocket.send_json({"type": "done", "session_id": session_id})
    except Exception as exc:
        print(f"WebSocket session closed: {exc}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.post("/api/v1/feedback")
async def feedback(request: FeedbackRequest):
    """Learn from user feedback (positive / negative / corrections)."""
    global agent
    if agent is None:
        agent = SelfLearningAgent(mode="mythos")
        await agent.initialize()

    result = await agent.learn_from_feedback(request.message_id, request.feedback)
    return {
        "status": "learned",
        "message_id": request.message_id,
        "learning_type": result.get("type", "feedback_recorded"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/ctf/analyze")
async def ctf_analyze(request: CTFAnalyzeRequest):
    """Analyze CTF text or file challenges."""
    tool = CTFTool()
    if request.source == "text" and request.content:
        res = await tool.solve_text_challenge(request.content)
        return res
    elif request.source == "file":
        return {
            "success": False,
            "error": "Use /api/v1/ctf/upload for multipart file uploads.",
        }
    return {"success": False, "error": "Invalid source or missing content."}


@app.post("/api/v1/ctf/upload")
async def ctf_upload(file: UploadFile = File(...)):
    """Upload CTF challenge file for autonomous deep analysis."""
    tool = CTFTool()
    content = await file.read()
    result = await tool.analyze_file_stream(content, file.filename or "challenge.bin", file.content_type)
    return result


@app.get("/api/v1/stats")
async def get_stats():
    """Get aggregate performance and learning metrics."""
    global agent
    if agent is None:
        agent = SelfLearningAgent(mode="mythos")
        await agent.initialize()

    stats = agent.get_overall_stats()
    return {
        "success": True,
        "stats": stats,
        "uptime": "running",
        "model": settings.LLM_MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/experiences")
async def list_experiences(limit: int = 50, type_filter: Optional[str] = None):
    """List stored learning memories and successful patterns."""
    if type_filter:
        experiences = experience_repo.get_by_type(type_filter, limit=limit)
    else:
        experiences = experience_repo.get_all()[:limit]

    return {
        "success": True,
        "count": len(experiences),
        "experiences": [
            {
                "id": exp.id,
                "type": exp.problem_type,
                "pattern": exp.pattern,
                "confidence": exp.confidence,
                "success_count": exp.success_count,
                "tags": exp.tags,
            }
            for exp in experiences
        ],
    }


# ============ PERFORMANCE DASHBOARD ENDPOINTS ============

@app.get("/api/v1/performance/summary")
async def performance_summary():
    """Overall real-time performance summary (latency, confidence, learning rate)."""
    return {
        "success": True,
        "summary": metrics_collector.get_summary(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/performance/modes")
async def performance_by_mode():
    """Per-mode performance breakdown."""
    return {
        "success": True,
        "modes": metrics_collector.get_mode_breakdown(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/performance/trends")
async def performance_trends(hours: int = 24):
    """Hourly trend data for performance visualization charts."""
    return {
        "success": True,
        "hours": hours,
        "trends": metrics_collector.get_trend_data(hours),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/performance/errors")
async def performance_errors(limit: int = 10):
    """Recent failed queries and root cause telemetry."""
    return {
        "success": True,
        "errors": metrics_collector.get_recent_errors(limit),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/performance/live")
async def performance_live():
    """Live streaming metrics via Server-Sent Events (SSE)."""
    async def generate():
        while True:
            yield f"data: {json.dumps(metrics_collector.get_summary())}\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )



if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8080,
        log_level="info",
    )
