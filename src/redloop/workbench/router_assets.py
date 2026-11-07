"""Assets, Findings, and Evidence Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/assets", tags=["assets"])


@router.get("/summary")
async def assets_summary(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "tracked_assets_count": 0,
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
    })
