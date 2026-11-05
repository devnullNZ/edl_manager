"""Server-rendered admin UI: sign-in, settings (one page per section), hosts, audit log.

Security notes: the session cookie is signed, SameSite=Strict (and Secure unless
ADMIN_COOKIE_SECURE=false); every POST carries a per-session CSRF token; pages are served
no-store with a CSP that forbids scripts; sign-in attempts are throttled per IP. Secret
values are never rendered: password inputs are always empty and only "configured" is shown.
Newly generated host tokens are rendered directly in the response (never put in the session
cookie or a redirect URL). Changes flagged as disruptive need a second, explicit confirmation;
the pending change is held server-side so secrets never travel through the browser twice.
"""
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, ratelimit, runtime, security_checks, service, settings_store
from . import hosts as hosts_mod
from .config import get_bootstrap, get_settings
from .db import AllowedHost, EdlSnapshot, get_db
from .engine import processing_engine

router = APIRouter(prefix="/admin", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

_FAILS = ratelimit.SlidingWindow()  # failed admin logins per source address (expired entries are removed)
_MAX_FAILS, _WINDOW = 5, 300
_PENDING: dict[str, dict] = {}  # confirmation token -> held change
_PENDING_TTL = 300


def _localtime(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if not dt:
        return "never"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZoneInfo(get_settings().app_timezone)).strftime(f"{fmt} %Z")


templates.env.filters["localtime"] = _localtime
templates.env.globals["host_expired"] = hosts_mod.is_expired


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _actor() -> str:
    return f"admin:{get_bootstrap().admin_user}"


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]


def _flash(request: Request, kind: str, message: str) -> None:
    request.session.setdefault("flash", []).append([kind, message])


def render(request: Request, name: str, status_code: int = 200, active: str = "", **ctx):
    s = get_settings()
    ctx.update(
        csrf=_csrf_token(request),
        admin=bool(request.session.get("admin")),
        flashes=request.session.pop("flash", []),
        mock_mode=s.panorama_mode == "mock" and s.classification_enabled,
        system_warnings=security_checks.system_warnings() if request.session.get("admin") else [],
        app_name=s.app_name,
        app_description=s.app_description,
        sections=settings_store.SECTIONS,
        active=active,
    )
    resp = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(f"/admin{path}", status_code=303)


def require_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(303, headers={"Location": "/admin/login"})


def check_csrf(request: Request, csrf_token: Annotated[str, Form()] = ""):
    expected = request.session.get("csrf", "")
    if not expected or not secrets.compare_digest(expected.encode(), csrf_token.encode()):
        raise HTTPException(403, "invalid CSRF token")


Authed = [Depends(require_admin), Depends(check_csrf)]


def _throttled(ip: str) -> bool:
    return _FAILS.peek(ratelimit.source_key(ip), _MAX_FAILS, _WINDOW) > 0


def _section(section_id: str) -> settings_store.Section:
    section = settings_store.SECTION_BY_ID.get(section_id)
    if section is None:
        raise HTTPException(404, "no such settings section")
    return section


# --------------------------------------------------------------------------- #
# sign in / out
# --------------------------------------------------------------------------- #
@router.get("/login")
def login_page(request: Request):
    return render(request, "login.html")


@router.post("/login", dependencies=[Depends(check_csrf)])
def login(request: Request, db: Annotated[Session, Depends(get_db)],
          username: Annotated[str, Form()] = "", password: Annotated[str, Form()] = ""):
    ip = _ip(request) or "unknown"
    if _throttled(ip):
        return render(request, "login.html", status_code=429,
                      error="Too many failed attempts. Try again in a few minutes.")
    b = get_bootstrap()
    ok = bool(b.admin_password) \
        and secrets.compare_digest(username.encode(), b.admin_user.encode()) \
        and secrets.compare_digest(password.encode(), b.admin_password.encode())
    if not ok:
        _FAILS.hit(ratelimit.source_key(ip), _MAX_FAILS, _WINDOW)
        audit.record(db, actor=f"admin:{username[:60]}", action="login.failed", ip=ip)
        return render(request, "login.html", status_code=401, error="Incorrect username or password.")
    _FAILS.discard(ratelimit.source_key(ip))
    csrf = request.session.get("csrf")
    request.session.clear()  # fresh session on sign-in
    request.session.update(admin=True, csrf=csrf or secrets.token_urlsafe(32))
    audit.record(db, actor=_actor(), action="login", ip=ip)
    return redirect("/settings")


@router.post("/logout", dependencies=Authed)
def logout(request: Request, db: Annotated[Session, Depends(get_db)]):
    audit.record(db, actor=_actor(), action="logout", ip=_ip(request))
    request.session.clear()
    return redirect("/login")


@router.get("", dependencies=[Depends(require_admin)])
def index():
    return redirect("/settings")


# --------------------------------------------------------------------------- #
# settings: overview and section pages
# --------------------------------------------------------------------------- #
def _panorama_status(db: Session, s) -> dict:
    if not s.classification_enabled:
        return {"kind": "muted", "text": "Classification disabled", "detail": "Panorama is not queried."}
    if s.panorama_mode == "mock":
        return {"kind": "warn", "text": "Mock mode", "detail": "Categories are simulated."}
    if not (s.panorama_host and s.panorama_api_key):
        return {"kind": "err", "text": "Not configured",
                "detail": "Host and API key are required. New entries are held back until classification works."}
    state = settings_store.get_state(db, "panorama_test")
    if not state:
        return {"kind": "muted", "text": "Configured, not tested", "detail": "Use Test connection."}
    when = _localtime(datetime.fromisoformat(state["tested_at"]))
    if state.get("ok"):
        bits = [b for b in (state.get("devicename"), state.get("sw_version")) if b]
        return {"kind": "ok", "text": f"Connected (tested {when})", "detail": ", ".join(bits)}
    return {"kind": "err", "text": f"Last test failed ({when})", "detail": state.get("message", "")}


def _snapshots(db: Session):
    return service.snapshot_statuses(db)


def _extras(section_id: str, db: Session, s) -> dict:
    if section_id == "panorama":
        return {"status": _panorama_status(db, s)}
    if section_id == "edl":
        return {"snapshots": _snapshots(db)}
    if section_id == "processing":
        return {"engine": processing_engine.status, "pending": service.pending_count(db),
                "last_reclass": settings_store.get_state(db, "last_reclassification")}
    return {}


def _section_page(request: Request, db: Session, section: settings_store.Section, *, status_code: int = 200,
                  errors=(), submitted=None, test=None):
    s = get_settings()
    return render(
        request, "section.html", status_code=status_code, active=section.id, section=section,
        values=settings_store.form_values(s, submitted),
        choices={f.key: settings_store.choices_for(f, s) for f in section.fields
                 if f.kind in ("choice", "multiselect")},
        errors=list(errors), test=test, extra=_extras(section.id, db, s), settings=s)


@router.get("/settings", dependencies=[Depends(require_admin)])
def overview(request: Request, db: Annotated[Session, Depends(get_db)]):
    s = get_settings()
    warnings = []
    status = _panorama_status(db, s)
    if status["kind"] == "err":
        warnings.append(f"Panorama: {status['text']}. {status['detail']}")
    if s.panorama_mode == "mock" and s.classification_enabled:
        warnings.append("Panorama is in mock mode: categories are simulated.")
    if not s.host_api_auth_enabled:
        warnings.append("Host authentication is OFF: anyone who can reach the API can add URLs.")
    if not s.edl_publishing_enabled:
        warnings.append("EDL publishing is disabled: feeds return HTTP 503.")
    if not s.background_processing_enabled:
        warnings.append("Background processing is disabled: pending entries are not retried automatically.")
    pending = service.pending_count(db)
    snaps = _snapshots(db)
    for snap in snaps:
        if snap["truncated"]:
            warnings.append(f"List '{snap['list_name']}': {snap['truncated']} entries are not published "
                            f"because the maximum ({s.edl_max_entries}) is reached.")
        if snap["retained"]:
            warnings.append(f"List '{snap['list_name']}': {snap['note']}")
        elif snap["differs"]:
            warnings.append(f"List '{snap['list_name']}': the published feed differs from the eligible entries "
                            f"({snap['only_published']} only in the feed, {snap['only_eligible']} only eligible).")
        if snap["last_error"]:
            warnings.append(f"List '{snap['list_name']}': the last feed rebuild failed; the previous version is "
                            "still being served. See the application log.")
    rows = [(sec, [(f, settings_store.display_value(f, s)) for f in sec.fields]) for sec in settings_store.SECTIONS]
    return render(request, "overview.html", active="overview", rows=rows, status=status, warnings=warnings,
                  pending=pending, snapshots=snaps, engine=processing_engine.status)


@router.get("/settings/{section_id}", dependencies=[Depends(require_admin)])
def section_page(request: Request, section_id: str, db: Annotated[Session, Depends(get_db)]):
    return _section_page(request, db, _section(section_id))


def _stash(request: Request, updates, clear, section_id: str) -> str:
    now = time.monotonic()
    for token in [t for t, v in _PENDING.items() if v["expires"] < now]:
        _PENDING.pop(token, None)
    token = secrets.token_urlsafe(24)
    _PENDING[token] = {"updates": dict(updates), "clear": set(clear), "section": section_id,
                       "csrf": request.session.get("csrf"), "expires": now + _PENDING_TTL}
    return token


def _commit_plan(request: Request, db: Session, plan: settings_store.Plan, section_id: str):
    changed = settings_store.apply_plan(db, plan)
    runtime.on_settings_changed(db, changed)
    audit.record(db, actor=_actor(), action="settings.update", target=section_id,
                 detail=settings_store.redacted_changes(plan), ip=_ip(request))
    _flash(request, "ok", f"Settings saved: {len(changed)} change(s) applied.")
    return redirect(f"/settings/{section_id}")


# static POST routes must be declared before the /{section_id} route
@router.post("/settings/confirm", dependencies=Authed)
def settings_confirm(request: Request, db: Annotated[Session, Depends(get_db)], token: Annotated[str, Form()] = ""):
    held = _PENDING.pop(token, None)
    if not held or held["expires"] < time.monotonic() or held["csrf"] != request.session.get("csrf"):
        _flash(request, "err", "That confirmation expired. Make the change again.")
        return redirect("/settings")
    strict = held["section"] in settings_store.STRICT_SECTIONS
    plan = settings_store.plan_updates(held["updates"], held["clear"], strict=strict)  # re-validate now
    if plan.errors:
        return _section_page(request, db, _section(held["section"]), status_code=422, errors=plan.errors)
    return _commit_plan(request, db, plan, held["section"])


@router.post("/settings/reset-defaults", dependencies=Authed)
def settings_reset(request: Request, db: Annotated[Session, Depends(get_db)]):
    settings_store.reset_defaults(db)
    runtime.on_settings_changed(db, set(settings_store.EDITABLE))
    audit.record(db, actor=_actor(), action="settings.reset", detail="all settings reset to built-in defaults",
                 ip=_ip(request))
    _flash(request, "ok", "All settings were reset to built-in defaults (secrets cleared).")
    return redirect("/settings")


@router.post("/settings/panorama/test", dependencies=Authed)
async def panorama_test(request: Request, db: Annotated[Session, Depends(get_db)]):
    """Test Panorama with the values currently in the form (nothing is saved)."""
    section = _section("panorama")
    form = await request.form()
    updates, _ = settings_store.updates_from_form(section, form)
    try:
        result, saved = runtime.connection_test(db, updates)
    except (ValidationError, ValueError) as exc:
        return _section_page(request, db, section, status_code=422, errors=settings_store._format_exc(exc),
                             submitted=updates)
    audit.record(db, actor=_actor(), action="panorama.test", ip=_ip(request),
                 detail=f"{'ok' if result['ok'] else 'failed'} ({'saved' if saved else 'unsaved'} settings)")
    return _section_page(request, db, section, submitted=None if saved else updates,
                         test={**result, "saved": saved})


@router.post("/settings/{section_id}", dependencies=Authed)
async def section_save(request: Request, section_id: str, db: Annotated[Session, Depends(get_db)]):
    section = _section(section_id)
    form = await request.form()
    updates, clear = settings_store.updates_from_form(section, form)
    plan = settings_store.plan_updates(updates, clear, strict=section.id in settings_store.STRICT_SECTIONS)
    if plan.errors:
        return _section_page(request, db, section, status_code=422, errors=plan.errors, submitted=updates)
    if not plan.changes:
        _flash(request, "ok", "No changes to save.")
        return redirect(f"/settings/{section_id}")
    if plan.disruptive:
        token = _stash(request, updates, clear, section_id)
        return render(request, "confirm.html", active=section_id, section=section, plan=plan, token=token)
    return _commit_plan(request, db, plan, section_id)


# --------------------------------------------------------------------------- #
# processing controls
# --------------------------------------------------------------------------- #
@router.post("/processing/run", dependencies=Authed)
def processing_run(request: Request, db: Annotated[Session, Depends(get_db)]):
    result = processing_engine.tick(force=True)
    audit.record(db, actor=_actor(), action="processing.run", ip=_ip(request), detail=str(result)[:500])
    _flash(request, "ok" if "error" not in result else "err", f"Processing run finished: {result}")
    return redirect("/settings/processing")


@router.post("/processing/reclassify", dependencies=Authed)
def processing_reclassify(request: Request, db: Annotated[Session, Depends(get_db)]):
    result = processing_engine.tick(force=True, reclassify=True, refresh=True)
    audit.record(db, actor=_actor(), action="processing.reclassify", ip=_ip(request), detail=str(result)[:500])
    _flash(request, "ok" if "error" not in result else "err", f"Reclassification finished: {result}")
    return redirect("/settings/processing")


# --------------------------------------------------------------------------- #
# hosts
# --------------------------------------------------------------------------- #
def _hosts_page(request: Request, db: Session, status_code: int = 200, **ctx):
    rows = list(db.scalars(select(AllowedHost).order_by(AllowedHost.name)))
    return render(request, "hosts.html", status_code=status_code, active="hosts", hosts=rows,
                  settings=get_settings(), **ctx)


def _get_host(db: Session, host_id: int) -> AllowedHost:
    host = db.get(AllowedHost, host_id)
    if host is None:
        raise HTTPException(404, "no such host")
    return host


@router.get("/hosts", dependencies=[Depends(require_admin)])
def hosts_page(request: Request, db: Annotated[Session, Depends(get_db)]):
    return _hosts_page(request, db)


@router.post("/hosts", dependencies=Authed)
def host_create(request: Request, db: Annotated[Session, Depends(get_db)],
                name: Annotated[str, Form()] = "", addresses: Annotated[str, Form()] = "",
                lists: Annotated[str, Form()] = "*", expiry: Annotated[str, Form()] = ""):
    try:
        host, token = hosts_mod.create_host(db, name, addresses, lists, expiry)
    except ValueError as exc:
        return _hosts_page(request, db, status_code=422, error=str(exc),
                           form=dict(name=name, addresses=addresses, lists=lists, expiry=expiry))
    audit.record(db, actor=_actor(), action="host.create", target=host.name, ip=_ip(request),
                 detail=f"addresses={host.addresses}; lists={host.lists}")
    return _hosts_page(request, db, new_token=token, new_name=host.name)


@router.post("/hosts/{host_id}/update", dependencies=Authed)
def host_update(request: Request, host_id: int, db: Annotated[Session, Depends(get_db)],
                name: Annotated[str, Form()] = "", addresses: Annotated[str, Form()] = "",
                lists: Annotated[str, Form()] = "*", expiry: Annotated[str, Form()] = ""):
    host = _get_host(db, host_id)
    old_name = host.name
    try:
        hosts_mod.update_host(db, host, name, addresses, lists, expiry)
    except ValueError as exc:
        db.rollback()
        return _hosts_page(request, db, status_code=422, error=f"{old_name}: {exc}")
    audit.record(db, actor=_actor(), action="host.update", target=host.name, ip=_ip(request),
                 detail=f"addresses={host.addresses}; lists={host.lists}")
    _flash(request, "ok", f"Host {host.name} updated.")
    return redirect("/hosts")


@router.post("/hosts/{host_id}/toggle", dependencies=Authed)
def host_toggle(request: Request, host_id: int, db: Annotated[Session, Depends(get_db)]):
    host = _get_host(db, host_id)
    host.enabled = not host.enabled
    db.commit()
    audit.record(db, actor=_actor(), action="host.enable" if host.enabled else "host.disable",
                 target=host.name, ip=_ip(request))
    _flash(request, "ok", f"Host {host.name} {'enabled' if host.enabled else 'disabled'}.")
    return redirect("/hosts")


@router.post("/hosts/{host_id}/regenerate", dependencies=Authed)
def host_regenerate(request: Request, host_id: int, db: Annotated[Session, Depends(get_db)]):
    host = _get_host(db, host_id)
    token = hosts_mod.regenerate_token(db, host)
    audit.record(db, actor=_actor(), action="host.token", target=host.name, ip=_ip(request),
                 detail="token regenerated")
    return _hosts_page(request, db, new_token=token, new_name=host.name)


@router.post("/hosts/{host_id}/delete", dependencies=Authed)
def host_delete(request: Request, host_id: int, db: Annotated[Session, Depends(get_db)]):
    host = _get_host(db, host_id)
    db.delete(host)
    db.commit()
    audit.record(db, actor=_actor(), action="host.delete", target=host.name, ip=_ip(request))
    _flash(request, "ok", f"Host {host.name} deleted.")
    return redirect("/hosts")


# --------------------------------------------------------------------------- #
# audit log
# --------------------------------------------------------------------------- #
@router.get("/audit", dependencies=[Depends(require_admin)])
def audit_page(request: Request, db: Annotated[Session, Depends(get_db)],
               kind: Literal["", "admin", "api"] = "", page: int = 1):
    page = max(page, 1)
    size = 50
    total, rows = audit.recent(db, kind=kind or None, limit=size, offset=(page - 1) * size)
    return render(request, "audit.html", active="audit", rows=rows, total=total, kind=kind, page=page,
                  pages=max(1, -(-total // size)))
