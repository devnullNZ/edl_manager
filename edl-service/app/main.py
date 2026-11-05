import logging
import re
from contextlib import asynccontextmanager
from datetime import timezone
from email.utils import format_datetime
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasicCredentials
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Match

from . import __version__, audit, migrations, ratelimit, runtime, security_checks, service, settings_store
from . import db as dbmod
from . import hosts as hosts_mod
from .admin import router as admin_router
from .admin_api import router as admin_api_router
from .auth import basic, edl_auth, require_api_key
from .config import get_bootstrap, get_settings
from .db import AllowedHost, Entry, get_db
from .engine import processing_engine
from .panorama import PanoramaError
from .shadow import compute_shadows

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("edl")
LIST_NAME = r"^[a-zA-Z0-9_-]{1,64}$"
AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW = 20, 60  # failed host authentications per source address per minute


def init_app(engine_, session_factory) -> None:
    """Bring the database up to date and load settings. Existing stored settings are never
    overwritten; only settings that are missing (new install, or added by an upgrade) are seeded."""
    migrations.run_migrations(engine_)
    with session_factory() as db:
        for line in settings_store.upgrade_stored_settings(db):
            log.warning("upgrade: adjusted stored setting: %s", line)
        settings_store.seed_defaults(db)
        settings_store.reload(db)
        for key in settings_store.secret_problems():
            log.error("secret setting %s %s", key, settings_store.UNREADABLE_HELP)
        if settings_store.secrets_awaiting_rotation():
            log.warning("secrets still under the previous key: %s", ", ".join(settings_store.secrets_awaiting_rotation()))
        service.reconcile_wildcards(db)  # wildcard policy + public-suffix rule for entries stored by older versions
        service.rebuild_snapshots(db)  # also creates feeds for databases upgraded from older versions
    runtime.apply_runtime()


@asynccontextmanager
async def lifespan(app: FastAPI):
    b = get_bootstrap()
    missing = [n for n, v in (("API_KEY", b.api_key), ("SECRET_KEY", b.secret_key),
                              ("ADMIN_PASSWORD", b.admin_password)) if not v]
    if missing:
        raise RuntimeError(f"required environment variable(s) not set: {', '.join(missing)}")
    settings_store.check_encryption_config()  # clear, actionable error if ENCRYPTION_KEY is missing/weak
    init_app(dbmod.engine, dbmod.SessionLocal)
    for kind, msg in security_checks.system_warnings():
        (log.error if kind == "err" else log.warning)("%s", msg)
    if get_settings().classification_enabled:
        try:
            service.get_client()
        except PanoramaError as exc:  # fixable from the admin page, so don't refuse to start
            log.error("Panorama is not usable yet: %s", exc)
    processing_engine.start()
    yield
    await processing_engine.stop()


app = FastAPI(title="EDL Publisher", version=__version__, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=get_bootstrap().secret_key,
    session_cookie="edl_admin",
    max_age=8 * 3600,
    same_site="strict",
    https_only=get_bootstrap().admin_cookie_secure,
)
app.include_router(admin_router)
app.include_router(admin_api_router)


def _check_list(name: str) -> str:
    if not re.match(LIST_NAME, name):
        raise HTTPException(422, "list name must match [A-Za-z0-9_-]{1,64}")
    return name


def host_auth(name: str, request: Request, db: Annotated[Session, Depends(get_db)],
              authorization: Annotated[str | None, Header()] = None) -> AllowedHost | None:
    """Per-host authentication for populating a list: bearer token (+ source address), then the
    per-host rate limit. Returns None when host authentication is switched off in Settings."""
    s = get_settings()
    # The address used for IP restrictions and throttling is the TCP peer as resolved by uvicorn, which
    # honours X-Forwarded-For only from FORWARDED_ALLOW_IPS. This code never reads forwarding headers.
    ip = request.client.host if request.client else None
    list_name = _check_list(name)
    fail_key = f"authfail:{ratelimit.source_key(ip)}"
    wait = ratelimit.peek(fail_key, AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW)
    if wait:
        raise HTTPException(429, "too many failed authentication attempts", headers={"Retry-After": str(wait)})
    if not s.host_api_auth_enabled:
        host, key = None, f"ip:{ratelimit.source_key(ip)}"
    else:
        token = authorization[7:].strip() if authorization and authorization[:7].lower() == "bearer " else None
        try:
            host = hosts_mod.authenticate(db, token, ip, list_name, ip_restrictions=s.host_ip_restrictions_enabled)
        except hosts_mod.HostAuthError as exc:
            ratelimit.hit(fail_key, AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW)  # slows token guessing per source
            headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
            raise HTTPException(exc.status_code, exc.message, headers=headers) from None
        key = f"host:{host.name}"
    wait = ratelimit.hit(key, s.rate_limit_requests, s.rate_limit_interval_seconds)
    if wait:
        raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(wait)})
    return host


class UrlsIn(BaseModel):
    urls: list[Annotated[str, Field(max_length=65536)]] = Field(min_length=1, max_length=100000)
    source: str | None = Field(default=None, max_length=100,
                               description="Optional note appended to the host name as the entry's source.")


class UrlsDelete(BaseModel):
    urls: list[Annotated[str, Field(max_length=65536)]] = Field(min_length=1, max_length=100000)


@app.get("/healthz")
def healthz(db: Annotated[Session, Depends(get_db)]):
    db.execute(select(1))
    s = get_settings()
    return {"status": "ok", "version": __version__, "classification": s.classification_enabled,
            "panorama_mode": s.panorama_mode if s.classification_enabled else "disabled",
            "secrets": "unreadable" if settings_store.secret_problems() else "ok"}


# --------------------------------------------------------------------------- #
# The feed
# --------------------------------------------------------------------------- #
def _serve_feed(request: Request, db: Session, list_name: str) -> Response:
    """Serve the stored snapshot: plain text, one entry per line, no other formatting."""
    s = get_settings()
    if not s.edl_publishing_enabled:
        return PlainTextResponse("EDL publishing is disabled\n", status_code=503, headers={"Retry-After": "300"})
    snap = service.get_snapshot(db, list_name)
    if snap is None:
        return PlainTextResponse("feed unavailable\n", status_code=503, headers={"Retry-After": "60"})
    if snap.entry_count == 0 and s.edl_empty_behaviour == "return-error":
        return PlainTextResponse("no valid entries\n", status_code=503, headers={"Retry-After": "300"})
    generated = snap.generated_at if snap.generated_at.tzinfo else snap.generated_at.replace(tzinfo=timezone.utc)
    etag = f'"{snap.etag}"'
    headers = {"ETag": etag, "Last-Modified": format_datetime(generated.astimezone(timezone.utc), usegmt=True),
               "Cache-Control": "no-cache"}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content=snap.body, media_type="text/plain; charset=utf-8", headers=headers)


@app.get("/edl/{name}", response_class=Response, dependencies=[Depends(edl_auth)])
def get_edl(name: str, request: Request, db: Annotated[Session, Depends(get_db)]):
    """The feed Palo Alto fetches (External Dynamic List, type URL)."""
    return _serve_feed(request, db, _check_list(name))


# --------------------------------------------------------------------------- #
# Lists API
# --------------------------------------------------------------------------- #
@app.post("/v1/lists/{name}/entries")
def add_entries(name: str, body: UrlsIn, request: Request, db: Annotated[Session, Depends(get_db)],
                host: Annotated[AllowedHost | None, Depends(host_auth)]):
    """Populate a list. Requires an allowed host's bearer token (unless host auth is disabled)."""
    s = get_settings()
    if len(body.urls) > s.max_submission_size:
        raise HTTPException(413, f"too many URLs in one request (maximum {s.max_submission_size})")
    actor = host.name if host else "anonymous"
    source = f"{actor}:{body.source}" if body.source else actor
    try:
        results = service.add_urls(db, _check_list(name), body.urls, source)
    except service.SubmissionError as exc:
        raise HTTPException(422, detail={"errors": exc.errors}) from None
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    audit.record(db, actor=f"host:{actor}", action="submit", target=name, kind="api",
                 ip=request.client.host if request.client else None,
                 detail=f"{len(body.urls)} URL(s): " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return {"summary": counts, "results": results}


@app.delete("/v1/lists/{name}/entries", dependencies=[Depends(require_api_key)])
def delete_entries(name: str, body: UrlsDelete, db: Annotated[Session, Depends(get_db)]):
    try:
        return {"deleted": service.remove_urls(db, _check_list(name), body.urls)}
    except service.SubmissionError as exc:
        raise HTTPException(422, detail={"errors": exc.errors}) from None


@app.get("/v1/lists/{name}/entries", dependencies=[Depends(require_api_key)])
def list_entries(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    entry_status: Annotated[Literal["active", "blocked", "pending", "unverified"] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    name = _check_list(name)
    q = select(Entry).where(Entry.list_name == name)
    if entry_status:
        q = q.where(Entry.status == entry_status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(Entry.value).limit(limit).offset(offset))
    shadows = compute_shadows(service.published_values(db, name)) if entry_status in (None, "active", "unverified") else {}
    return {
        "total": total,
        "entries": [
            {"value": e.value, "status": e.status, "detail": e.detail, "source": e.source,
             "created_at": e.created_at, "checked_at": e.checked_at,
             "published": e.status in service.PUBLISHED and e.value not in shadows,
             "shadowed_by": shadows.get(e.value)}
            for e in rows
        ],
    }


@app.post("/v1/lists/{name}/recheck", dependencies=[Depends(require_api_key)])
def recheck_list(name: str, db: Annotated[Session, Depends(get_db)]):
    """Re-query Panorama (bypassing the cache) for every entry in the list."""
    return service.recheck(db, _check_list(name))


# --------------------------------------------------------------------------- #
# Optional extra feed path (Settings > EDL > Additional endpoint). A catch-all so it can change
# without a restart; everything else it sees is a plain 404.
# --------------------------------------------------------------------------- #
@app.get("/{full_path:path}", include_in_schema=False)
def alias_feed(full_path: str, request: Request, db: Annotated[Session, Depends(get_db)],
               creds: Annotated[HTTPBasicCredentials | None, Depends(basic)]):
    s = get_settings()
    if s.edl_endpoint and "/" + full_path.rstrip("/") == s.edl_endpoint:
        edl_auth(creds)
        return _serve_feed(request, db, s.edl_name)
    raise HTTPException(404, "Not Found")


RESERVED_PREFIXES = ("/admin", "/docs", "/redoc", "/openapi.json", "/v1", "/edl", "/healthz")


def route_conflict(path: str) -> str | None:
    """Why `path` cannot be used as the additional EDL endpoint, or None if it is free."""
    for prefix in RESERVED_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return f"'{path}' is reserved by the application ({prefix})."
    for route in app.routes:
        pattern = getattr(route, "path", None)
        if pattern is None or pattern == "/{full_path:path}":
            continue
        for method in ("GET", "POST", "PUT", "DELETE"):
            match, _ = route.matches({"type": "http", "path": path, "method": method, "root_path": ""})
            if match != Match.NONE:
                return f"'{path}' conflicts with the existing route {pattern}."
    return None


settings_store.ROUTE_CHECK = route_conflict
