"""Read-only views for the admin pages and the admin API: wildcard classification, sync history and
entry details. Nothing here writes, and nothing returns host tokens, token hashes or secrets."""
import json
from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import service
from .db import Entry, EntrySource, SyncRun, SyncSource


def _json(text: str | None):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def classification(e: Entry) -> dict:
    return {"method": e.class_method, "target": e.class_target, "result": e.class_result,
            "categories": e.class_categories.split(",") if e.class_categories else [],
            "status": e.class_status, "reason": e.detail, "at": e.checked_at}


def owners_for(db: Session, entry_ids: list[int]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = defaultdict(list)
    for chunk in service._chunks(entry_ids, 500):
        for o in db.scalars(select(EntrySource).where(EntrySource.entry_id.in_(chunk)).order_by(EntrySource.id)):
            out[o.entry_id].append({"kind": o.kind, "host": o.host, "source": o.source_id, "yaml_list": o.yaml_list,
                                    "added": o.created_at, "last_seen": o.last_seen_at,
                                    "last_sync_id": o.last_sync_id})
    return out


def wildcard_rows(db: Session, list_name: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    q = select(Entry).where(Entry.value.like("*.%"))
    if list_name:
        q = q.where(Entry.list_name == list_name)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    by_status = dict(db.execute(select(func.coalesce(Entry.class_status, Entry.status), func.count())
                                .where(Entry.value.like("*.%"))
                                .where(Entry.list_name == list_name if list_name else True)
                                .group_by(func.coalesce(Entry.class_status, Entry.status))).all())
    rows = list(db.scalars(q.order_by(Entry.list_name, Entry.value).limit(limit).offset(offset)))
    sup = defaultdict(int)
    if rows:
        for lst, by, n in db.execute(select(Entry.list_name, Entry.suppressed_by, func.count())
                                     .where(Entry.suppressed_by.in_([r.value for r in rows]))
                                     .group_by(Entry.list_name, Entry.suppressed_by)):
            sup[(lst, by)] = n
    return {"total": total, "summary": by_status, "wildcards": [
        {"list": e.list_name, "wildcard": e.value, "status": e.status, "classification": classification(e),
         "suppresses": sup.get((e.list_name, e.value), 0), "suppressed_by": e.suppressed_by,
         "published": e.status in service.PUBLISHED and e.enabled is not False and not e.suppressed_by}
        for e in rows]}


def sync_sources(db: Session, list_name: str | None = None) -> list[dict]:
    q = select(SyncSource)
    if list_name:
        q = q.where(SyncSource.list_name == list_name)
    out = []
    for r in db.scalars(q.order_by(SyncSource.list_name, SyncSource.host, SyncSource.source_id)):
        out.append({"list": r.list_name, "host": r.host, "source": r.source_id, "last_sync_id": r.last_sync_id,
                    "last_sync_at": r.last_sync_at, "status": r.last_status, "run_id": r.last_run_id,
                    "counts": _json(r.last_summary) or {}})
    return out


def sync_runs(db: Session, list_name: str | None = None, source: str | None = None, limit: int = 50,
              offset: int = 0) -> dict:
    q = select(SyncRun)
    if list_name:
        q = q.where(SyncRun.list_name == list_name)
    if source:
        q = q.where(SyncRun.source_id == source)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.scalars(q.order_by(SyncRun.id.desc()).limit(limit).offset(offset))
    return {"total": total, "runs": [
        {"id": r.id, "list": r.list_name, "host": r.host, "source": r.source_id, "sync_id": r.sync_id,
         "started_at": r.started_at, "finished_at": r.finished_at, "status": r.status,
         "counts": _json(r.summary) or {}, "error": r.error} for r in rows]}


def sync_run(db: Session, run_id: int) -> dict | None:
    r = db.get(SyncRun, run_id)
    if r is None:
        return None
    return {"id": r.id, "list": r.list_name, "host": r.host, "source": r.source_id, "sync_id": r.sync_id,
            "started_at": r.started_at, "finished_at": r.finished_at, "status": r.status,
            "counts": _json(r.summary) or {}, "error": r.error, "report": _json(r.report)}


def entry_rows(db: Session, list_name: str | None = None, status: str | None = None, q: str = "",
               suppressed: bool | None = None, wildcard: bool | None = None, limit: int = 100,
               offset: int = 0) -> dict:
    stmt = select(Entry)
    if list_name:
        stmt = stmt.where(Entry.list_name == list_name)
    if status:
        stmt = stmt.where(Entry.status == status)
    if q:
        stmt = stmt.where(Entry.value.contains(q.lower(), autoescape=True))
    if suppressed is True:
        stmt = stmt.where(Entry.suppressed_by.is_not(None))
    elif suppressed is False:
        stmt = stmt.where(Entry.suppressed_by.is_(None))
    if wildcard is True:
        stmt = stmt.where(Entry.value.like("*.%"))
    elif wildcard is False:
        stmt = stmt.where(~Entry.value.like("*.%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.scalars(stmt.order_by(Entry.list_name, Entry.value).limit(limit).offset(offset)))
    owners = owners_for(db, [e.id for e in rows])
    sources = {(s["list"], s["host"], s["source"]): s for s in sync_sources(db, list_name)}
    out = []
    for e in rows:
        own = owners.get(e.id, [])
        for o in own:
            s = sources.get((e.list_name, o["host"], o["source"])) if o["kind"] == "sync" else None
            o["source_last_sync_at"] = s["last_sync_at"] if s else None
        out.append({"list": e.list_name, "value": e.value, "status": e.status, "enabled": e.enabled is not False,
                    "published": e.status in service.PUBLISHED and e.enabled is not False and not e.suppressed_by,
                    "suppressed_by": e.suppressed_by, "classification": classification(e),
                    "created_at": e.created_at, "checked_at": e.checked_at, "owners": own})
    return {"total": total, "entries": out}
