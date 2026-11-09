"""Workbench REST router for Engagement-Scoped Profiles (Phase B.5).

Provides single-call fast switching, listing, importing, and self-authorization
of signed engagement profiles with audit logging.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from redloop.engagement import (
    EngagementManager,
    EngagementScope,
    EngagementTarget,
    EngagementOutOfScope,
    parse_engagement_scope_text,
    create_self_authorized_scope,
    sign_engagement_scope,
    UnauthorizedEngagementError,
)
from redloop.config import settings
from redloop.audit import AuditLogger

router = APIRouter(prefix="/api/workbench/engagements", tags=["engagements"])

_GLOBAL_ENGAGEMENT_MANAGER: EngagementManager | None = None


def get_global_engagement_manager() -> EngagementManager:
    global _GLOBAL_ENGAGEMENT_MANAGER
    if _GLOBAL_ENGAGEMENT_MANAGER is None:
        secret = settings.scope_secret or "engagement-secret-key"
        audit = AuditLogger()
        _GLOBAL_ENGAGEMENT_MANAGER = EngagementManager(secret=secret, audit=audit)
    return _GLOBAL_ENGAGEMENT_MANAGER


class ImportScopeRequest(BaseModel):
    name: str = "Imported Program Scope"
    scope_text: str
    program_url: str | None = None
    sign_now: bool = True
    signer_identity: str = "operator"


class SelfAuthorizeRequest(BaseModel):
    name: str = "Self-Authorized Lab Scope"
    targets: list[dict[str, Any]]
    out_of_scope: list[dict[str, Any]] = Field(default_factory=list)
    rate_limit: int | None = None
    rules_text: str = ""
    i_own_or_authorized: bool
    signer_identity: str = "operator"


class ActivateScopeRequest(BaseModel):
    operator: str = "operator"


@router.get("")
def list_engagements() -> dict[str, Any]:
    mgr = get_global_engagement_manager()
    return {
        "active_id": mgr.active_id,
        "engagements": mgr.list_engagements(),
    }


@router.post("/import")
def import_scope(req: ImportScopeRequest) -> dict[str, Any]:
    mgr = get_global_engagement_manager()
    parsed = parse_engagement_scope_text(
        text=req.scope_text,
        name=req.name,
        program_url=req.program_url,
    )
    if req.sign_now:
        parsed["signed_by"] = req.signer_identity
        from datetime import datetime, timezone
        parsed["signed_at"] = datetime.now(timezone.utc).isoformat()
        sig = sign_engagement_scope(parsed, mgr.secret)
        parsed["signature"] = sig

    eng = EngagementScope(**parsed)
    mgr.register_engagement(eng)
    return {
        "status": "success",
        "engagement_id": eng.id,
        "name": eng.name,
        "targets_count": len(eng.targets),
        "out_of_scope_count": len(eng.out_of_scope),
        "signed": bool(eng.signature),
        "signature": eng.signature,
    }


@router.post("/self-authorize")
def self_authorize(req: SelfAuthorizeRequest) -> dict[str, Any]:
    mgr = get_global_engagement_manager()
    if not req.i_own_or_authorized:
        raise HTTPException(
            status_code=400,
            detail="Ownership or authorization checkbox must be confirmed.",
        )
    try:
        eng = create_self_authorized_scope(
            name=req.name,
            targets=req.targets,
            out_of_scope=req.out_of_scope,
            rate_limit=req.rate_limit,
            rules_text=req.rules_text,
            secret=mgr.secret,
            signer_identity=req.signer_identity,
            i_own_or_authorized=req.i_own_or_authorized,
            audit=mgr.audit,
        )
        mgr.register_engagement(eng)
        return {
            "status": "success",
            "engagement_id": eng.id,
            "name": eng.name,
            "signature": eng.signature,
            "signed_by": eng.signed_by,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{engagement_id}/activate")
def activate_engagement(engagement_id: str, req: ActivateScopeRequest = ActivateScopeRequest()) -> dict[str, Any]:
    mgr = get_global_engagement_manager()
    try:
        eng = mgr.set_active_engagement(engagement_id=engagement_id, operator=req.operator)
        return {
            "status": "success",
            "active_engagement_id": eng.id,
            "name": eng.name,
            "targets_count": len(eng.targets),
            "signature": eng.signature,
        }
    except UnauthorizedEngagementError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

