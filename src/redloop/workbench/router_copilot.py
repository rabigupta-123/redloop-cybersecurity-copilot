"""Copilot, Chat, and Terminal Execution Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/copilot", tags=["copilot"])


@router.get("/status")
async def copilot_status(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "status": "ready",
        "primary_provider": "ollama",
        "primary_model": "qwen3:8b",
        "fallback_chain": ["groq", "openrouter", "offline_deterministic"],
    })

