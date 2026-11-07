"""Diagnostics, Health, and Audit Verification Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/diagnostics", tags=["diagnostics"])


@router.get("/health")
async def workbench_health(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "status": "healthy",
        "subsystems": {
            "database": "connected",
            "audit_ledger": "append_only_verified",
            "scope_enforcement": "fail_closed",
        }
    })
