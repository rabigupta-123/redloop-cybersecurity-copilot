"""Integrations, SIEM, EDR, and MCP/API Connector Registry Router (Phase 2)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.connectors import (
    CircuitBreakerOpenError,
    ConnectorManifest,
    ConnectorNotFoundError,
    ConnectorSecurityError,
)
from redloop.connectors.registry import get_connector_registry
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


# ==============================================================================
# MCP / API CONNECTOR REGISTRY ENDPOINTS (Phase 2.2)
# ==============================================================================

@router.get("/connectors")
async def list_connectors(request: Request) -> JSONResponse:
    """List all registered MCP and API connectors with manifests and telemetry."""
    require_same_origin(request)
    registry = get_connector_registry()
    connectors = registry.list_all()
    return JSONResponse({
        "status": "success",
        "count": len(connectors),
        "connectors": [c.model_dump() for c in connectors],
    })


@router.post("/connectors")
async def create_connector(request: Request) -> JSONResponse:
    """Register a new MCP or API connector."""
    require_same_origin(request)
    payload = await request.json()
    try:
        manifest = ConnectorManifest(**payload)
        registry = get_connector_registry()
        registered = registry.register(manifest)
        return JSONResponse({"status": "success", "connector": registered.model_dump()}, status_code=201)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/connectors/telemetry")
async def get_all_connectors_telemetry(request: Request) -> JSONResponse:
    """Retrieve telemetry for the SPA Connector Health Panel (Phase 2.3)."""
    require_same_origin(request)
    registry = get_connector_registry()
    connectors = registry.list_all()
    telemetry_list = [registry.get_telemetry(c.id).model_dump() for c in connectors if c.id]
    return JSONResponse({
        "status": "success",
        "count": len(telemetry_list),
        "telemetry": telemetry_list,
    })


@router.get("/connectors/{connector_id}")
async def get_connector(connector_id: str, request: Request) -> JSONResponse:
    """Get connector details by ID."""
    require_same_origin(request)
    registry = get_connector_registry()
    try:
        conn = registry.get(connector_id)
        tel = registry.get_telemetry(connector_id)
        return JSONResponse({
            "status": "success",
            "connector": conn.model_dump(),
            "telemetry": tel.model_dump(),
        })
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")


@router.put("/connectors/{connector_id}")
async def update_connector(connector_id: str, request: Request) -> JSONResponse:
    """Update an existing connector manifest."""
    require_same_origin(request)
    payload = await request.json()
    registry = get_connector_registry()
    try:
        updated = registry.update(connector_id, payload)
        return JSONResponse({"status": "success", "connector": updated.model_dump()})
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/connectors/{connector_id}")
async def delete_connector(connector_id: str, request: Request) -> JSONResponse:
    """Delete a connector (built-ins cannot be deleted)."""
    require_same_origin(request)
    registry = get_connector_registry()
    try:
        deleted = registry.delete(connector_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")
        return JSONResponse({"status": "success", "deleted": connector_id})
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/connectors/{connector_id}/enable")
async def enable_connector(connector_id: str, request: Request) -> JSONResponse:
    """Enable a connector."""
    require_same_origin(request)
    registry = get_connector_registry()
    try:
        updated = registry.update(connector_id, {"enabled": True})
        return JSONResponse({"status": "success", "connector": updated.model_dump()})
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")


@router.post("/connectors/{connector_id}/disable")
async def disable_connector(connector_id: str, request: Request) -> JSONResponse:
    """Disable a connector."""
    require_same_origin(request)
    registry = get_connector_registry()
    try:
        updated = registry.update(connector_id, {"enabled": False})
        return JSONResponse({"status": "success", "connector": updated.model_dump()})
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")


@router.post("/connectors/{connector_id}/test")
async def test_connector(connector_id: str, request: Request) -> JSONResponse:
    """Health check / connectivity test for a connector."""
    require_same_origin(request)
    registry = get_connector_registry()
    try:
        conn = registry.get(connector_id)
        tel = registry.get_telemetry(connector_id)
        return JSONResponse({
            "status": "success",
            "health": conn.last_health,
            "telemetry": tel.model_dump(),
        })
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")


@router.post("/connectors/{connector_id}/execute")
async def execute_connector_tool(connector_id: str, request: Request) -> JSONResponse:
    """Execute a tool through the connector gate (SSRF, circuit breaker, untrusted output)."""
    require_same_origin(request)
    payload = await request.json()
    tool_name = payload.get("tool")
    arguments = payload.get("arguments", {})
    operator_token = payload.get("operator_token")

    if not tool_name:
        raise HTTPException(status_code=400, detail="Missing 'tool' parameter.")

    registry = get_connector_registry()
    try:
        res = registry.execute_tool(
            connector_id=connector_id,
            tool_name=tool_name,
            arguments=arguments,
            operator_token=operator_token,
        )
        return JSONResponse(res)
    except ConnectorNotFoundError:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")
    except CircuitBreakerOpenError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except ConnectorSecurityError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
