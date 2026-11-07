"""Investigations & Attack Reconstruction Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/investigations", tags=["investigations"])


@router.get("")
async def list_workbench_investigations(request: Request) -> JSONResponse:
    require_same_origin(request)
    from redloop.investigation import get_investigation_store
    store = get_investigation_store()
    invs = store.list_all() if hasattr(store, "list_all") else []
    return JSONResponse({"investigations": [i.to_dict() if hasattr(i, "to_dict") else i for i in invs]})


@router.get("/{investigation_id}")
async def get_workbench_investigation(investigation_id: str, request: Request) -> JSONResponse:
    require_same_origin(request)
    from redloop.investigation import get_investigation_store
    store = get_investigation_store()
    inv = store.get(investigation_id) if hasattr(store, "get") else None
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return JSONResponse({"investigation": inv.to_dict() if hasattr(inv, "to_dict") else inv})

