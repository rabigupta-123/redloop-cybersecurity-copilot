"""CTF & Challenge Operations Router."""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from redloop.workbench.shared import require_same_origin

router = APIRouter(prefix="/api/workbench/ctf", tags=["ctf"])


@router.post("/decode")
async def decode_ctf_payload(request: Request) -> JSONResponse:
    require_same_origin(request)
    body = await request.json()
    raw = body.get("payload", "")
    from redloop.assessment.ctf_toolkit import CTFCodec
    codec = CTFCodec()
    res = codec.auto_decode(raw) if hasattr(codec, "auto_decode") else {"raw": raw}
    return JSONResponse({"result": res})

