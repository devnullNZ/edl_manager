"""Chunked, resumable synchronisation.

A large desired state is sent as a session:

  POST   /v1/lists/{list}/sync/sessions                      start (or resume) a session
  PUT    /v1/lists/{list}/sync/sessions/{id}/chunks/{index}  stage one chunk (idempotent)
  GET    /v1/lists/{list}/sync/sessions/{id}                 progress: which chunks arrived, what is missing
  POST   /v1/lists/{list}/sync/sessions/{id}/commit          verify completeness, then reconcile
  DELETE /v1/lists/{list}/sync/sessions/{id}                 abandon the session

Chunks are only STAGED (table sync_staged). The list, its ownership rows and the published feed are not
touched until `commit`, and commit refuses to run unless the importer states how many chunks and entries
make up the whole desired state and every one of them has arrived. So an interrupted upload, a lost
chunk or a crashed importer can never remove anything: a partial submission is not a desired state.
The commit stage is the ordinary sync pipeline (app/sync.py): validated, planned, classified and applied
in ONE transaction, with the same safety rules, report, audit trail and sync_id idempotency.

Sessions live in the database, so they survive a restart; an idle one expires after
`sync_session_ttl_minutes` and its staged data is discarded.
"""
import hashlib
import json
import logging
from datetime import timedelta
from typing import Annotated, Union

from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, sync
from .config import get_settings
from .db import SyncChunk, SyncRun, SyncSession, SyncStaged, utcnow
from .normalize import EntryTooLong, normalize
from .sync import SyncEntryIn, SyncIn, SyncRejected

log = logging.getLogger("edl")

MAX_CHUNK_INDEX = 1_000_000
INSERT_BATCH = 5000
KEEP_FINISHED_DAYS = 30


class SessionStart(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    sync_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@/+=-]+$")
    delete_missing: bool = False
    confirm_empty: bool = False
    reclassify: bool = False


class ChunkIn(BaseModel):
    entries: list[Union[Annotated[str, Field(max_length=65536)], SyncEntryIn]]


class CommitIn(BaseModel):
    total_chunks: int = Field(ge=0, le=MAX_CHUNK_INDEX + 1,
                              description="How many chunks make up the whole desired state (indexes 0..n-1).")
    total_entries: int = Field(ge=0, description="How many entries the importer sent in all chunks together.")
    dry_run: bool = Field(False, description="Report the proposed result; change nothing. The session stays open.")
    verbose: bool = False
    max_removals: int | None = Field(None, ge=0, description="Server-enforced removal limit, see the sync API. A "
                                     "refusal keeps the session open so the commit can be retried.")


# --------------------------------------------------------------------------- #
def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


def _key(sess: SyncSession) -> str:
    return f"{sess.list_name}|{sess.host}|{sess.source_id}|{sess.sync_id}"[:400]


def _discard_staging(db: Session, session_id: int) -> None:
    db.execute(delete(SyncStaged).where(SyncStaged.session_id == session_id))


def expire_stale(db: Session) -> int:
    """Expire idle sessions (discarding their staged data) and drop long-finished session records.
    Never touches entries. Returns the number expired."""
    ttl = timedelta(minutes=get_settings().sync_session_ttl_minutes)
    now = utcnow()
    stale = list(db.scalars(select(SyncSession).where(SyncSession.status == "receiving",
                                                      SyncSession.updated_at < now - ttl)))
    for sess in stale:
        _discard_staging(db, sess.id)
        sess.status, sess.finished_at = "expired", now
        sess.last_error = f"no activity for {get_settings().sync_session_ttl_minutes} minutes; staged data discarded"
    old = list(db.scalars(select(SyncSession.id).where(SyncSession.status != "receiving",
                                                       SyncSession.updated_at < now - timedelta(days=KEEP_FINISHED_DAYS))))
    for sid in old:
        _discard_staging(db, sid)
        db.execute(delete(SyncChunk).where(SyncChunk.session_id == sid))
        db.execute(delete(SyncSession).where(SyncSession.id == sid))
    if stale or old:
        db.commit()
    return len(stale)


def _get(db: Session, list_name: str, host: str, session_id: int) -> SyncSession:
    sess = db.get(SyncSession, session_id)
    if sess is None or sess.list_name != list_name or sess.host != host:  # another host's session: not found
        raise SyncRejected(404, "no such sync session")
    return sess


def _require_open(db: Session, sess: SyncSession) -> None:
    if sess.status == "receiving":
        ttl = timedelta(minutes=get_settings().sync_session_ttl_minutes)
        if utcnow() - _aware(sess.updated_at) > ttl:
            expire_stale(db)
            raise SyncRejected(410, "this sync session expired; start a new one")
        return
    detail = {"committed": "this sync session was already committed", "aborted": "this sync session was aborted",
              "expired": "this sync session expired; start a new one"}.get(sess.status, f"session is {sess.status}")
    raise SyncRejected(410 if sess.status in ("aborted", "expired") else 409, detail)


def _ranges(indexes: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for i in sorted(indexes):
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def _progress(db: Session, sess: SyncSession) -> dict:
    s = get_settings()
    idx = list(db.scalars(select(SyncChunk.idx).where(SyncChunk.session_id == sess.id)))
    top = max(idx) if idx else -1
    have = set(idx)
    gaps = [i for i in range(top + 1) if i not in have]
    return {
        "session_id": sess.id, "list": sess.list_name, "source": sess.source_id, "sync_id": sess.sync_id,
        "status": sess.status, "delete_missing": sess.delete_missing, "reclassify": bool(sess.reclassify),
        "received_chunks": len(idx), "received_entries": sess.received_entries,
        "received_invalid": sess.received_invalid or 0,
        "received_ranges": _ranges(idx), "missing_below_highest": gaps[:1000], "highest_chunk": top,
        "recommended_chunk_size": s.sync_chunk_size, "max_chunk_size": s.sync_max_chunk_size,
        "max_entries": s.max_sync_size, "run_id": sess.run_id,
        "created_at": sess.created_at, "updated_at": sess.updated_at, "last_error": sess.last_error,
        "note": ("Nothing has been applied. Send the missing chunks (any order, safe to repeat), then POST "
                 ".../commit with total_chunks and total_entries.") if sess.status == "receiving" else None,
    }


# --------------------------------------------------------------------------- #
def start(db: Session, *, list_name: str, host: str | None, body: SessionStart, ip: str | None) -> dict:
    host = host or "anonymous"
    sync._check_source_length(host, body.source)
    expire_stale(db)
    key = f"{list_name}|{host}|{body.source}|{body.sync_id}"[:400]

    done = db.scalar(select(SyncRun).where(SyncRun.dedup_key == key))
    if done is not None:  # this sync_id was applied before: nothing to upload
        return {"status": "already_applied", "run_id": done.id, "sync_id": body.sync_id, "source": body.source,
                "result": done.status, "summary": json.loads(done.summary or "{}"),
                "note": "this sync_id was already applied; use a new sync_id for new content"}

    sess = db.scalar(select(SyncSession).where(
        SyncSession.list_name == list_name, SyncSession.host == host,
        SyncSession.source_id == body.source, SyncSession.sync_id == body.sync_id))
    if sess is not None:
        if sess.status == "receiving":
            if (sess.delete_missing, sess.confirm_empty, bool(sess.reclassify)) != (
                    body.delete_missing, body.confirm_empty, body.reclassify):
                raise SyncRejected(409, "this sync_id has an open session with different options; abort it or "
                                        "use a new sync_id")
            out = _progress(db, sess)
            out["resumed"] = True
            return out
        # an aborted/expired session of the same id: begin again from scratch
        _discard_staging(db, sess.id)
        db.execute(delete(SyncChunk).where(SyncChunk.session_id == sess.id))
        db.delete(sess)
        db.flush()

    other = db.scalar(select(SyncSession).where(
        SyncSession.list_name == list_name, SyncSession.host == host, SyncSession.source_id == body.source,
        SyncSession.status == "receiving"))
    if other is not None:
        raise SyncRejected(409, {"errors": [f"another sync of this source is still receiving (sync_id "
                                            f"'{other.sync_id}', session {other.id}); finish it, or DELETE it to "
                                            "abandon it"], "session_id": other.id})
    sess = SyncSession(list_name=list_name, host=host, source_id=body.source, sync_id=body.sync_id,
                       delete_missing=body.delete_missing, confirm_empty=body.confirm_empty,
                       reclassify=body.reclassify, chunk_size=get_settings().sync_chunk_size)
    db.add(sess)
    try:
        audit.record(db, actor=f"host:{host}", action="sync-session-start", target=list_name, kind="api", ip=ip,
                     detail=f"source={body.source} sync_id={body.sync_id}", commit=False)
        db.commit()
    except IntegrityError:  # a concurrent start of the same session
        db.rollback()
        sess = db.scalar(select(SyncSession).where(
            SyncSession.list_name == list_name, SyncSession.host == host,
            SyncSession.source_id == body.source, SyncSession.sync_id == body.sync_id))
        if sess is None:
            raise SyncRejected(409, "another sync of this source is starting; retry") from None
        out = _progress(db, sess)
        out["resumed"] = True
        return out
    out = _progress(db, sess)
    out["resumed"] = False
    return out


def status(db: Session, *, list_name: str, host: str | None, session_id: int) -> dict:
    return _progress(db, _get(db, list_name, host or "anonymous", session_id))


def put_chunk(db: Session, *, list_name: str, host: str | None, session_id: int, index: int,
              body: ChunkIn) -> dict:
    s = get_settings()
    host = host or "anonymous"
    if not 0 <= index <= MAX_CHUNK_INDEX:
        raise SyncRejected(422, f"chunk index must be between 0 and {MAX_CHUNK_INDEX}")
    n = len(body.entries)
    if n > s.sync_max_chunk_size:
        raise SyncRejected(413, f"chunk has {n} entries; the maximum is {s.sync_max_chunk_size} "
                                f"(recommended {s.sync_chunk_size})")
    sess = _get(db, list_name, host, session_id)
    _require_open(db, sess)

    raw_items = [(e, None) if isinstance(e, str) else (e.url, e.yaml_list) for e in body.entries]
    digest = hashlib.sha256(json.dumps(raw_items, separators=(",", ":")).encode()).hexdigest()
    prior = db.get(SyncChunk, (sess.id, index))
    if prior is not None:
        if prior.digest != digest:
            raise SyncRejected(409, f"chunk {index} was already received with different content; abort the "
                                    "session and start again to change it")
        out = _progress(db, sess)
        out.update(chunk=index, already_received=True)
        return out
    if sess.received_entries + n > s.max_sync_size:
        raise SyncRejected(413, f"this would make the sync larger than the maximum of {s.max_sync_size} entries")

    rows = []
    bad = 0
    for pos, (raw, yl) in enumerate(raw_items):
        try:
            rows.append({"session_id": sess.id, "chunk_idx": index, "pos": pos, "value": normalize(raw),
                         "yaml_list": yl, "invalid_reason": None})
        except (EntryTooLong, ValueError) as exc:
            bad += 1
            rows.append({"session_id": sess.id, "chunk_idx": index, "pos": pos, "value": raw[:200],
                         "yaml_list": None, "invalid_reason": str(exc)[:300]})
    try:
        for k in range(0, len(rows), INSERT_BATCH):
            db.execute(SyncStaged.__table__.insert(), rows[k:k + INSERT_BATCH])
        db.add(SyncChunk(session_id=sess.id, idx=index, entries=n, invalid=bad, digest=digest))
        db.flush()
        sess.received_chunks = db.scalar(select(func.count()).select_from(SyncChunk).where(SyncChunk.session_id == sess.id))
        sess.received_entries = db.scalar(select(func.coalesce(func.sum(SyncChunk.entries), 0))
                                          .where(SyncChunk.session_id == sess.id))
        sess.received_invalid = db.scalar(select(func.coalesce(func.sum(SyncChunk.invalid), 0))
                                          .where(SyncChunk.session_id == sess.id))
        sess.updated_at = utcnow()
        db.commit()
    except IntegrityError:  # the same chunk arrived twice at once: the first one won
        db.rollback()
        sess = db.get(SyncSession, session_id)
        prior = db.get(SyncChunk, (session_id, index))
        if prior is not None and prior.digest == digest:
            out = _progress(db, sess)
            out.update(chunk=index, already_received=True)
            return out
        raise SyncRejected(409, f"chunk {index} was received concurrently with different content") from None
    out = _progress(db, sess)
    out.update(chunk=index, already_received=False, accepted=n, invalid_in_chunk=bad)
    return out


def invalid_entries(db: Session, *, list_name: str, host: str | None, session_id: int, offset: int,
                    limit: int) -> dict:
    """The entries of a session that failed validation, in upload order, with their chunk and position
    inside it (so the importer can point at the YAML line). Paged; the commit/422 reply lists only the first
    few."""
    sess = _get(db, list_name, host or "anonymous", session_id)
    limit = max(1, min(limit, 1000))
    q = (select(SyncStaged.chunk_idx, SyncStaged.pos, SyncStaged.value, SyncStaged.invalid_reason)
         .where(SyncStaged.session_id == sess.id, SyncStaged.invalid_reason.is_not(None))
         .order_by(SyncStaged.chunk_idx, SyncStaged.pos).offset(max(0, offset)).limit(limit))
    items = [{"chunk": c, "position": p, "entry": v, "reason": r} for c, p, v, r in db.execute(q)]
    return {"session_id": sess.id, "status": sess.status, "total_invalid": sess.received_invalid or 0,
            "offset": max(0, offset), "items": items}


def abort(db: Session, *, list_name: str, host: str | None, session_id: int, ip: str | None) -> dict:
    host = host or "anonymous"
    sess = _get(db, list_name, host, session_id)
    if sess.status == "committed":
        raise SyncRejected(409, "this sync session was already committed")
    _discard_staging(db, sess.id)
    sess.status, sess.finished_at, sess.updated_at = "aborted", utcnow(), utcnow()
    audit.record(db, actor=f"host:{host}", action="sync-session-abort", target=list_name, kind="api", ip=ip,
                 detail=f"source={sess.source_id} sync_id={sess.sync_id}", commit=False)
    db.commit()
    return _progress(db, sess)


def commit(db: Session, *, list_name: str, host: str | None, session_id: int, body: CommitIn,
           ip: str | None) -> dict:
    host = host or "anonymous"
    s = get_settings()
    sess = _get(db, list_name, host, session_id)
    if sess.status == "committed":  # idempotent: the stored result of the commit that succeeded
        run = db.get(SyncRun, sess.run_id) if sess.run_id else None
        report = json.loads(run.report or "{}") if run else {}
        report.update(duplicate=True, run_id=sess.run_id, status=run.status if run else "applied")
        return report
    _require_open(db, sess)

    # --- completeness: a partial submission is never a desired state
    rows = list(db.execute(select(SyncChunk.idx, SyncChunk.entries).where(SyncChunk.session_id == sess.id)))
    have = {i for i, _ in rows}
    want = set(range(body.total_chunks))
    problems = []
    if want - have:
        missing = sorted(want - have)
        problems.append(f"{len(missing)} chunk(s) missing: {missing[:50]}{' ...' if len(missing) > 50 else ''}")
    if have - want:
        problems.append(f"chunks outside 0..{body.total_chunks - 1} were received: {sorted(have - want)[:50]}")
    got = sum(n for _, n in rows)
    if got != body.total_entries and not (want - have):
        problems.append(f"{got} entries were received but total_entries is {body.total_entries}")
    if problems:
        sess.last_error = "; ".join(problems)[:1000]
        db.commit()
        raise SyncRejected(409, {"errors": ["the sync is incomplete; nothing was applied"] + problems,
                                 "received_ranges": _ranges(list(have)), "nothing_applied": True})
    if got > s.max_sync_size:
        raise SyncRejected(413, f"too many entries in one sync (maximum {s.max_sync_size})")

    # --- load the staged desired state (streamed; only the canonical values are kept in memory)
    desired: dict[str, str | None] = {}
    invalid: list[dict] = []
    dups = 0
    q = (select(SyncStaged.value, SyncStaged.yaml_list, SyncStaged.invalid_reason)
         .where(SyncStaged.session_id == sess.id).order_by(SyncStaged.chunk_idx, SyncStaged.id))
    for value, yl, bad in db.execute(q.execution_options(yield_per=10000)):
        if bad:
            invalid.append({"entry": value, "reason": bad})
        elif value in desired:
            dups += 1
            if desired[value] is None and yl:
                desired[value] = yl
        else:
            desired[value] = yl

    req = SyncIn(source=sess.source_id, sync_id=sess.sync_id, entries=[], delete_missing=sess.delete_missing,
                 confirm_empty=sess.confirm_empty, dry_run=body.dry_run, verbose=body.verbose,
                 reclassify=bool(sess.reclassify), max_removals=body.max_removals)
    try:
        report = sync.run_parsed(db, list_name=list_name, host=host, req=req, desired=desired, invalid=invalid,
                                 dups=dups, received=got, ip=ip)
    except SyncRejected as exc:
        db.rollback()
        sess = db.get(SyncSession, session_id)
        if sess is not None and sess.status == "receiving" and not body.dry_run:
            sess.last_error = str(exc.detail)[:1000]
            db.commit()
        raise
    report["session"] = {"session_id": sess.id, "chunks": body.total_chunks, "entries_received": got}
    if not body.dry_run:
        sess = db.get(SyncSession, session_id)
        sess.status, sess.finished_at, sess.updated_at = "committed", utcnow(), utcnow()
        sess.run_id, sess.last_error = report.get("run_id"), None
        _discard_staging(db, sess.id)
        db.commit()
    return report
