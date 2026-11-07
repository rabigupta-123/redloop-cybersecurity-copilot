"""SOC Operations, Incidents, and Playbooks Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/soc", tags=["soc"])


@router.get("/metrics")
async def soc_metrics_overview(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "mttd": "12m",
        "mttr": "45m",
        "active_cases": 0,
        "investigations_count": 0,
    })
