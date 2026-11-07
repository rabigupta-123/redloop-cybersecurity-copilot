"""Reporting & Quality Metrics Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/reports", tags=["reporting"])


@router.get("/summary")
async def reports_summary(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "generated_reports_count": 0,
        "formats_supported": ["HTML", "PDF", "PPTX", "JSON"],
    })
