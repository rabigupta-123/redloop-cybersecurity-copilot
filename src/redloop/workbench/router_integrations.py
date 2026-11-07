"""Integrations, SIEM, and EDR Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/integrations", tags=["integrations"])


@router.get("/status")
async def integrations_status(request: Request) -> JSONResponse:
    require_same_origin(request)
    return JSONResponse({
        "integrations": [
            {"id": "wazuh", "name": "Wazuh EDR", "status": "AVAILABLE"},
            {"id": "splunk", "name": "Splunk Enterprise", "status": "AVAILABLE"},
            {"id": "elastic", "name": "Elasticsearch SIEM", "status": "AVAILABLE"},
        ]
    })
