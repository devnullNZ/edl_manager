"""Administrative API (authenticated with the management X-API-Key, never a host token).

Follows the existing /v1 convention. Secrets are never returned: a secret setting is
reported only as configured / not configured with a mask.
"""
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from . import audit, runtime, service, settings_store
from .auth import require_api_key
from .db import get_db

router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_api_key)])
ACTOR = "api-key"


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    values: dict[str, Any] = Field(default_factory=dict, description="setting key -> new value "
                                   "(lists as arrays). Secret settings: omit or send an empty string to keep.")
    clear_secrets: list[str] = Field(default_factory=list, description="secret settings to remove")
    confirm: bool = Field(False, description="must be true to apply changes flagged as disruptive")


class PanoramaTest(BaseModel):
    """Optional overrides to test unsaved values. With no body the saved settings are tested."""
    model_config = ConfigDict(extra="forbid")

    mode: Literal["live", "mock"] | None = None
    host: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    api_key: str | None = Field(None, repr=False)
    verify_tls: bool | None = None
    connect_timeout: float | None = Field(None, ge=1, le=120)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _apply(db: Session, request: Request, body: SettingsUpdate, section_id: str | None) -> dict:
    section = settings_store.SECTION_BY_ID.get(section_id) if section_id else None
    allowed = {f.key for f in section.fields} if section else set(settings_store.EDITABLE)

    updates: dict[str, str] = {}
    for key, value in body.values.items():
        if key not in settings_store.EDITABLE:
            raise HTTPException(422, detail={"errors": [f"unknown setting: {key}"]})
        if key not in allowed:
            raise HTTPException(422, detail={"errors": [f"{key} does not belong to section '{section_id}'"]})
        if value is None:
            if key in settings_store.SECRET_KEYS:
                continue
            raise HTTPException(422, detail={"errors": [f"{key}: null is not allowed"]})
        updates[key] = settings_store.to_str(value)
    stray = [k for k in body.clear_secrets if k not in allowed]
    if stray:
        raise HTTPException(422, detail={"errors": [f"cannot clear: {', '.join(stray)}"]})

    touched = set(updates) | set(body.clear_secrets)
    strict = any(settings_store.SECTION_OF.get(k) in settings_store.STRICT_SECTIONS for k in touched)
    plan = settings_store.plan_updates(updates, body.clear_secrets, strict=strict)
    if plan.errors:
        raise HTTPException(422, detail={"errors": plan.errors})
    if plan.disruptive and not body.confirm:
        raise HTTPException(409, detail={"message": "These changes are disruptive. Repeat the request with "
                                                    "\"confirm\": true to apply them.",
                                         "requires_confirmation": plan.disruptive})
    changed = settings_store.apply_plan(db, plan)
    runtime.on_settings_changed(db, changed)
    if changed:
        audit.record(db, actor=ACTOR, action="settings.update", target=section_id or "all",
                     detail=settings_store.redacted_changes(plan), ip=_ip(request))
    return {"changed": sorted(changed),
            "sections": settings_store.describe(section=section_id)}


@router.get("/settings")
def get_settings_all():
    return {"sections": settings_store.describe()}


@router.put("/settings")
def put_settings(body: SettingsUpdate, request: Request, db: Annotated[Session, Depends(get_db)]):
    return _apply(db, request, body, None)


@router.get("/settings/{section}")
def get_settings_section(section: str):
    if section not in settings_store.SECTION_BY_ID:
        raise HTTPException(404, f"no such section: {section}")
    return settings_store.describe(section=section)[0]


@router.put("/settings/{section}")
def put_settings_section(section: str, body: SettingsUpdate, request: Request,
                         db: Annotated[Session, Depends(get_db)]):
    if section not in settings_store.SECTION_BY_ID:
        raise HTTPException(404, f"no such section: {section}")
    result = _apply(db, request, body, section)
    return {"changed": result["changed"], **result["sections"][0]}


@router.post("/panorama/test-connection")
def test_connection(request: Request, db: Annotated[Session, Depends(get_db)], body: PanoramaTest | None = None):
    """Verify connectivity and authentication. 200 on success, 502 if Panorama cannot be
    reached or rejects the key. The API key is never echoed."""
    overrides: dict[str, str] = {}
    if body:
        mapping = {"mode": "panorama_mode", "host": "panorama_host", "port": "panorama_port",
                   "api_key": "panorama_api_key", "verify_tls": "panorama_verify_tls",
                   "connect_timeout": "panorama_connect_timeout"}
        for field_name, key in mapping.items():
            value = getattr(body, field_name)
            if value is not None:
                overrides[key] = settings_store.to_str(value)
    try:
        result, saved = runtime.connection_test(db, overrides)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, detail={"errors": settings_store._format_exc(exc)}) from None
    audit.record(db, actor=ACTOR, action="panorama.test", ip=_ip(request),
                 detail=f"{'ok' if result['ok'] else 'failed'} ({'saved' if saved else 'unsaved'} settings)")
    return JSONResponse(result, status_code=200 if result["ok"] else 502)


@router.get("/audit")
def get_audit(db: Annotated[Session, Depends(get_db)],
              kind: Annotated[Literal["admin", "api"] | None, Query()] = None,
              limit: Annotated[int, Query(ge=1, le=500)] = 50,
              offset: Annotated[int, Query(ge=0)] = 0):
    total, rows = audit.recent(db, kind=kind, limit=limit, offset=offset)
    return {"total": total, "records": [
        {"id": r.id, "ts": r.ts, "kind": r.kind, "actor": r.actor, "action": r.action,
         "target": r.target, "detail": r.detail, "ip": r.ip} for r in rows]}


@router.get("/edl")
def get_edl_status(db: Annotated[Session, Depends(get_db)]):
    """For each list: what is being published versus what is currently eligible, and whether the
    previous list is being retained (keep-previous) or the last rebuild failed."""
    return {"lists": service.snapshot_statuses(db)}
