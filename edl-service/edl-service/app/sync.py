"""Source-based reconciliation: POST /v1/lists/{name}/sync.

The importer sends the DESIRED state of one source (host + source id); the server computes the
changes. Each run is staged and applied all-or-nothing:

  1. validate and normalise the request (nothing is written)
  2. plan against the database: new / unchanged / shared / removed / needing (re)classification
  3. classify what needs it, OUTSIDE the apply transaction (cached answers first, then a bounded
     number of live Panorama lookups; the rest is stored pending and left to the background engine)
  4. one transaction: re-plan, write entries and ownership, recompute wildcard suppression, replace
     the feed snapshot, record the run and the audit trail, commit
  5. return the report

Nothing outside the requesting (host, source) is ever removed: other sources' entries, entries from the
legacy submission endpoint and manually managed entries are only ever touched by adding an owner.
A failure at any stage leaves the database and the published feed exactly as they were.
"""
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Annotated, Union

from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit, service
from .config import get_settings
from .db import Entry, EntrySource, SyncRun, SyncSource, utcnow
from .normalize import MAX_SOURCE_LENGTH, EntryTooLong, normalize
from .service import PUBLISHED, Outcome, classification_target, status_for
from .shadow import suppressed_by

log = logging.getLogger("edl")

REPORT_DETAIL_CAP = 2000   # per-entry lines kept in a report (counts are always complete)
INVALID_SHOWN = 100
LOCK_TIMEOUT = 300         # seconds to wait for another sync of the same list


class SyncEntryIn(BaseModel):
    url: Annotated[str, Field(max_length=65536)]
    yaml_list: str | None = Field(default=None, max_length=256,
                                  description="Name of the list this entry came from in the importer's YAML.")


class SyncIn(BaseModel):
    source: str = Field(min_length=1, max_length=100,
                        description="Identifies the importer's data set, e.g. 'yaml-import'. Ownership is per host and source.")
    sync_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@/+=-]+$",
                         description="Unique per sync run. Repeating a successful sync_id returns the stored result.")
    entries: list[Union[Annotated[str, Field(max_length=65536)], SyncEntryIn]] = Field(max_length=500000)
    delete_missing: bool = Field(False, description="Remove entries this source owns that are no longer listed.")
    confirm_empty: bool = Field(False, description="Required, together with delete_missing, when entries is empty.")
    dry_run: bool = Field(False, description="Validate and report the proposed result; change nothing.")
    verbose: bool = Field(False, description="Include unchanged entries in the per-entry detail.")


class SyncRejected(Exception):
    """The request was refused before anything was written (validation, size, conflict, busy)."""

    def __init__(self, status_code: int, detail):
        super().__init__(str(detail))
        self.status_code, self.detail = status_code, detail


@dataclass
class Row:
    id: int
    status: str
    class_method: str | None
    enabled: bool | None


@dataclass
class Plan:
    desired: dict[str, str | None]
    existing: dict[str, Row]
    owned: dict[str, tuple[int, int, str | None]]    # value -> (ownership id, entry id, yaml_list)
    new: list[str] = field(default_factory=list)
    shared_add: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    yaml_changed: list[str] = field(default_factory=list)
    removals: list[str] = field(default_factory=list)       # owned, no longer desired, delete_missing set
    kept_missing: list[str] = field(default_factory=list)   # owned, no longer desired, delete_missing not set
    reclass: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Request validation
# --------------------------------------------------------------------------- #
def parse_entries(req: SyncIn) -> tuple[dict[str, str | None], list[dict], int]:
    """(desired {canonical value: yaml list}, invalid [{entry, reason}], duplicates in the request)."""
    desired: dict[str, str | None] = {}
    invalid: list[dict] = []
    dups = 0
    for item in req.entries:
        raw, yl = (item, None) if isinstance(item, str) else (item.url, item.yaml_list)
        try:
            value = normalize(raw)
        except EntryTooLong as exc:
            invalid.append({"entry": raw[:200], "reason": str(exc)})
            continue
        except ValueError as exc:
            invalid.append({"entry": raw[:200], "reason": str(exc)})
            continue
        if value in desired:
            dups += 1
            if desired[value] is None and yl:
                desired[value] = yl
            continue
        desired[value] = yl
    return desired, invalid, dups


def fingerprint(req: SyncIn, desired: dict[str, str | None], invalid: list[dict]) -> str:
    h = hashlib.sha256()
    h.update(json.dumps([req.delete_missing, req.confirm_empty, sorted(desired.items()),
                         sorted(i["entry"] for i in invalid)], separators=(",", ":")).encode())
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Planning (read only)
# --------------------------------------------------------------------------- #
def _load_existing(db: Session, list_name: str, values: list[str]) -> dict[str, Row]:
    cols = (Entry.id, Entry.value, Entry.status, Entry.class_method, Entry.enabled)
    out: dict[str, Row] = {}
    if len(values) > 2000:  # one pass over the list beats hundreds of IN queries
        for i, v, st, cm, en in db.execute(select(*cols).where(Entry.list_name == list_name)):
            out[v] = Row(i, st, cm, en)
        return out
    for chunk in service._chunks(values, 500):
        for i, v, st, cm, en in db.execute(select(*cols).where(Entry.list_name == list_name, Entry.value.in_(chunk))):
            out[v] = Row(i, st, cm, en)
    return out


def _load_owned(db: Session, list_name: str, host: str, source: str) -> dict[str, tuple[int, int, str | None]]:
    q = (select(EntrySource.id, EntrySource.entry_id, Entry.value, EntrySource.yaml_list)
         .join(Entry, Entry.id == EntrySource.entry_id)
         .where(EntrySource.list_name == list_name, EntrySource.host == host,
                EntrySource.source_id == source, EntrySource.kind == "sync"))
    return {v: (oid, eid, yl) for oid, eid, v, yl in db.execute(q)}


def _needs_reclass(value: str, row: Row, policy: str) -> bool:
    if row.status in ("pending", "unverified"):
        return True
    # a wildcard stored by an older version, approved without apex classification metadata
    return value.startswith("*.") and policy == "apex-classification" and row.status != "blocked" \
        and row.class_method is None


def build_plan(db: Session, list_name: str, host: str, source: str, desired: dict[str, str | None],
               delete_missing: bool) -> Plan:
    policy = get_settings().wildcard_classification_policy
    existing = _load_existing(db, list_name, list(desired))
    owned = _load_owned(db, list_name, host, source)
    plan = Plan(desired=desired, existing=existing, owned=owned)
    for value in sorted(desired):
        row = existing.get(value)
        if row is None:
            plan.new.append(value)
            continue
        if value in owned:
            if owned[value][2] != desired[value]:
                plan.yaml_changed.append(value)
            else:
                plan.unchanged.append(value)
        else:
            plan.shared_add.append(value)
        if _needs_reclass(value, row, policy):
            plan.reclass.append(value)
    for value in sorted(set(owned) - set(desired)):
        (plan.removals if delete_missing else plan.kept_missing).append(value)
    return plan


# --------------------------------------------------------------------------- #
# Classification (outside the apply transaction)
# --------------------------------------------------------------------------- #
@dataclass
class Classified:
    outcomes: dict[str, Outcome] = field(default_factory=dict)
    how: dict[str, str] = field(default_factory=dict)    # cached | live | queued | not_required | requires_live | error
    errors: int = 0
    queued: int = 0
    live_requests: int = 0


def classify(db: Session, values: list[str], *, live_ok: set[str], dry_run: bool) -> Classified:
    """Cache first. A real run then asks Panorama for at most `sync_classification_budget` distinct
    targets (identical apex domains count once), and only for `live_ok` values (entries new to the
    list). Values beyond the budget, or whose lookup failed, are never approved: they come back
    pending and the background engine classifies them. Existing entries that merely need another
    look (still pending) use cached answers only, so repeating an identical sync sends nothing to
    Panorama; the background engine owns their retries."""
    s = get_settings()
    res = Classified()
    if not values:
        return res
    cached = service.lookup_outcomes(db, values, cache_only=True)
    need_live: list[str] = []
    for v, o in cached.items():
        if o.kind == "uncached" and v not in live_ok:
            res.how[v] = "engine"       # no cached answer: left to the background engine, no outcome
        elif o.kind == "uncached":
            need_live.append(v)
        else:
            res.outcomes[v] = o
            res.how[v] = "cached" if o.target else "not_required"
    if not need_live:
        return res

    def pending(v: str, why: str) -> Outcome:
        return Outcome("pending", why, target=classification_target(v),
                       method="wildcard_apex" if v.startswith("*.") else "url", wildcard=v.startswith("*."))

    if dry_run:
        for v in need_live:
            res.outcomes[v] = pending(v, "requires live classification (not performed in a dry run)")
            res.how[v] = "requires_live"
        return res

    by_target: dict[str, list[str]] = defaultdict(list)
    for v in sorted(need_live):
        by_target[classification_target(v)].append(v)
    allowed = list(by_target)[: s.sync_classification_budget]
    live_values = [v for t in allowed for v in by_target[t]]
    queued_values = [v for t in list(by_target)[s.sync_classification_budget:] for v in by_target[t]]
    if live_values:
        res.live_requests = len(allowed)
        live = service.lookup_outcomes(db, live_values)
        db.commit()  # the Panorama answers are cached on their own, whatever happens to the apply step
        for v, o in live.items():
            res.outcomes[v] = o
            if o.kind == "error":
                res.errors += 1
                res.how[v] = "error"
            else:
                res.how[v] = "live"
    for v in queued_values:
        res.outcomes[v] = pending(v, "queued for background classification (sync classification budget reached)")
        res.how[v] = "queued"
        res.queued += 1
    return res


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _status_of(outcome: Outcome | None) -> tuple[str, str | None]:
    if outcome is None:
        return "pending", "awaiting classification"
    return status_for(outcome)


def _class_view(e_status: str, outcome: Outcome | None, how: str | None) -> dict:
    d = {"status": {"active": "approved"}.get(e_status, e_status)}
    if outcome is not None:
        f = service.class_fields(outcome, e_status)
        d.update(method=f["class_method"], target=f["class_target"], result=f["class_result"],
                 categories=(f["class_categories"] or "").split(",") if f["class_categories"] else [])
    if how:
        d["source"] = how
    return d


def simulate(db: Session, list_name: str, plan: Plan, cl: Classified, removed_entry_values: set[str],
             delete_missing: bool) -> dict[str, dict]:
    """The state each DESIRED entry would end up in, without writing anything: {value: {status,
    suppressed_by, published}} plus list-wide feed numbers under the key ''."""
    rows = db.execute(select(Entry.id, Entry.value, Entry.status, Entry.enabled)
                      .where(Entry.list_name == list_name)).all()
    state: dict[str, list] = {v: [i, st, en is not False] for i, v, st, en in rows}
    for v in removed_entry_values:
        state.pop(v, None)
    next_id = max((r[0] for r in rows), default=0) + 1
    for v in plan.new:
        status, _ = _status_of(cl.outcomes.get(v))
        state[v] = [next_id, status, True]
        next_id += 1
    for v in plan.reclass:
        o = cl.outcomes.get(v)
        if o is not None and o.kind != "error":
            state[v][1] = _status_of(o)[0]
        elif o is not None and state[v][1] in ("pending", "unverified") and v.startswith("*."):
            state[v][1] = "pending"
    return state_view(state, plan.desired)


def state_view(state: dict[str, list], desired) -> dict[str, dict]:
    approved = [v for v, (_i, st, en) in state.items() if v.startswith("*.") and st in PUBLISHED and en]
    sup = suppressed_by(state, approved)
    eligible = [(i, v) for v, (i, st, en) in state.items() if st in PUBLISHED and en]
    effective, truncated = service.effective_from_rows(eligible)
    eff = set(effective)
    out = {v: {"status": state[v][1], "suppressed_by": sup.get(v), "published": v in eff}
           for v in desired if v in state}
    out[""] = {"effective": eff, "truncated": truncated}
    return out


def _entry_reason(action: str, status: str, detail: str | None, sup: str | None) -> str:
    if sup:
        return f"suppressed by approved wildcard {sup}"
    return detail or {"active": "approved", "blocked": "blocked", "pending": "pending classification",
                      "unverified": "published without verification (fail-open)"}.get(status, status)


def assemble_report(*, req: SyncIn, host: str, plan: Plan, cl: Classified, view: dict[str, dict],
                    invalid: list[dict], duplicates: int, received: int, before: set[str],
                    removed_values: list[str], entries_deleted: int, retained: int, deferred: bool,
                    dry_run: bool, details_extra: dict[str, str]) -> dict:
    desired = plan.desired
    feed = view.pop("")
    after: set[str] = feed["effective"]
    final = {v: view.get(v, {"status": "pending", "suppressed_by": None, "published": False}) for v in desired}
    blocked_policy = blocked_class = pending = apex_ok = sup = 0
    for v, f in final.items():
        o = cl.outcomes.get(v)
        if f["status"] == "blocked":
            if o is not None and o.kind == "wildcard" or (o is None and v.startswith("*.") and
                                                         get_settings().wildcard_classification_policy == "exclude"):
                blocked_policy += 1
            else:
                blocked_class += 1
        elif f["status"] == "pending":
            pending += 1
        if v.startswith("*.") and f["status"] == "active":
            apex_ok += 1
        if f["suppressed_by"]:
            sup += 1
    counts = {
        "received": received, "duplicates_in_request": duplicates, "total_desired": len(desired),
        "existing": len(desired) - len(plan.new), "new": len(plan.new), "unchanged": len(plan.unchanged),
        "ownership_added": len(plan.shared_add), "yaml_list_changed": len(plan.yaml_changed),
        "removed": len(removed_values), "entries_deleted": entries_deleted, "kept_other_owners": retained,
        "missing_not_removed": len(plan.kept_missing),
        "blocked_by_policy": blocked_policy, "blocked_by_classification": blocked_class,
        "pending_classification": pending, "queued_for_background": cl.queued,
        "approved_by_apex_classification": apex_ok, "suppressed_by_shadowing": sup,
        "requiring_reclassification": len(plan.reclass), "invalid": len(invalid),
        "processing_errors": cl.errors, "live_lookups": cl.live_requests,
        "published_of_desired": sum(1 for f in final.values() if f["published"]),
    }
    new_set, reclass_set = set(plan.new), set(plan.reclass)
    items: list[dict] = []

    def add(value: str, action: str):
        f = final.get(value, {"status": "removed", "suppressed_by": None, "published": False})
        o = cl.outcomes.get(value)
        st, detail = _status_of(o) if (value in new_set or value in reclass_set) else (f["status"], None)
        if value in details_extra and not detail:
            detail = details_extra[value]
        items.append({"entry": value, "action": action, "status": f["status"],
                      "published": f["published"], "suppressed_by": f["suppressed_by"],
                      "reason": _entry_reason(action, f["status"], detail, f["suppressed_by"]),
                      "classification": _class_view(f["status"], o, cl.how.get(value)) if o is not None else None})

    for v in plan.new:
        add(v, "added")
    for v in plan.shared_add:
        add(v, "ownership_added")
    for v in plan.yaml_changed:
        add(v, "yaml_list_changed")
    for v in plan.reclass:
        if v not in new_set:
            add(v, "reclassified")
    for v in removed_values:
        items.append({"entry": v, "action": "removed" if not dry_run else "would_remove", "status": "removed",
                      "published": False, "suppressed_by": None, "reason": "no longer listed by this source"})
    for v in plan.kept_missing:
        items.append({"entry": v, "action": "missing_kept", "status": "kept", "published": v in after,
                      "suppressed_by": None, "reason": "no longer listed, kept because delete_missing is false"})
    for i in invalid[:INVALID_SHOWN]:
        items.append({"entry": i["entry"], "action": "invalid", "status": "invalid", "published": False,
                      "suppressed_by": None, "reason": i["reason"]})
    shown = {i["entry"] for i in items}
    for v in plan.unchanged:
        if req.verbose or final[v]["suppressed_by"] or final[v]["status"] != "active":
            if v not in shown:
                add(v, "unchanged")
    truncated = len(items) > REPORT_DETAIL_CAP
    status_note = None
    if deferred:
        status_note = ("removals were NOT applied because classification failed during this run; "
                       "repeat the sync to apply them")
    report = {
        "list": None, "source": req.source, "host": host, "sync_id": req.sync_id, "dry_run": dry_run,
        "delete_missing": req.delete_missing, "removals_deferred": deferred, "counts": counts,
        "feed": {"entries_before": len(before), "entries_after": len(after),
                 "added": len(after - before), "removed": len(before - after), "changed": after != before,
                 "truncated_by_maximum": feed["truncated"]},
        "entries": items[:REPORT_DETAIL_CAP], "entries_truncated": truncated,
        "invalid": invalid[:INVALID_SHOWN],
    }
    if status_note:
        report["warning"] = status_note
    return report


# --------------------------------------------------------------------------- #
# The operation
# --------------------------------------------------------------------------- #
def _dedup_key(list_name: str, host: str, source: str, sync_id: str) -> str:
    return f"{list_name}|{host}|{source}|{sync_id}"[:400]


def _reject(db: Session, *, list_name, host, req, fp, actor, ip, status_code, detail, summary: str):
    """Refuse a request: nothing was applied; the refusal itself is recorded for the audit trail."""
    if not req.dry_run:
        try:
            now = utcnow()
            db.add(SyncRun(list_name=list_name, host=host, source_id=req.source, sync_id=req.sync_id,
                           fingerprint=fp, started_at=now, finished_at=now, status="failed",
                           summary=json.dumps({"rejected": status_code}), error=summary[:4000]))
            _touch_source(db, list_name, host, req.source, req.sync_id, "failed", None, now,
                          json.dumps({"error": summary[:300]}))
            audit.record(db, actor=actor, action="sync-rejected", target=list_name, kind="api", ip=ip,
                         detail=f"source={req.source} sync_id={req.sync_id}: {summary}", commit=False)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("could not record the rejected sync")
    raise SyncRejected(status_code, detail)


def _touch_source(db: Session, list_name: str, host: str, source: str, sync_id: str, status: str,
                  run_id: int | None, now, summary: str) -> None:
    row = db.scalar(select(SyncSource).where(SyncSource.list_name == list_name, SyncSource.host == host,
                                             SyncSource.source_id == source))
    if row is None:
        row = SyncSource(list_name=list_name, host=host, source_id=source)
        db.add(row)
    row.last_sync_id, row.last_sync_at, row.last_status = sync_id, now, status
    row.last_run_id, row.last_summary = run_id, summary


def run_sync(db: Session, *, list_name: str, host: str | None, req: SyncIn, ip: str | None = None) -> dict:
    s = get_settings()
    host = host or "anonymous"
    actor = f"host:{host}"
    composite = f"{host}:{req.source}"
    if len(composite) > MAX_SOURCE_LENGTH:
        raise SyncRejected(422, {"errors": [f"source is {len(composite)} characters (host name + ':' + source); "
                                            f"the maximum is {MAX_SOURCE_LENGTH}"]})
    if len(req.entries) > s.max_sync_size:
        raise SyncRejected(413, f"too many entries in one sync (maximum {s.max_sync_size})")
    received = len(req.entries)
    desired, invalid, dups = parse_entries(req)
    fp = fingerprint(req, desired, invalid)

    lock = service.list_lock(list_name)
    if not lock.acquire(timeout=LOCK_TIMEOUT):
        raise SyncRejected(503, "another sync of this list is still running; retry shortly")
    try:
        return _run_locked(db, s=s, list_name=list_name, host=host, actor=actor, req=req, desired=desired,
                           invalid=invalid, dups=dups, received=received, fp=fp, ip=ip)
    finally:
        lock.release()


def _run_locked(db: Session, *, s, list_name, host, actor, req, desired, invalid, dups, received, fp, ip) -> dict:
    reject = lambda code, detail, summary: _reject(  # noqa: E731
        db, list_name=list_name, host=host, req=req, fp=fp, actor=actor, ip=ip,
        status_code=code, detail=detail, summary=summary)

    if not req.dry_run:
        prior = db.scalar(select(SyncRun).where(SyncRun.dedup_key == _dedup_key(list_name, host, req.source, req.sync_id)))
        if prior is not None:
            if prior.fingerprint != fp:
                raise SyncRejected(409, f"sync_id '{req.sync_id}' was already used by this source with different "
                                        "content; use a new sync_id for new content")
            report = json.loads(prior.report or "{}")
            report.update(duplicate=True, run_id=prior.id, status=prior.status)
            return report

    if not desired and not invalid and req.delete_missing and not req.confirm_empty:
        reject(422, {"errors": ["the desired state is empty and delete_missing is set: this would remove "
                                "everything this source owns. Send confirm_empty=true to confirm."]},
               "empty desired state without confirm_empty")
    if invalid and req.delete_missing:
        reject(422, {"errors": [f"{len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: nothing is "
                                "removed from an incomplete or invalid import. Fix them or send delete_missing=false."],
                     "invalid": invalid[:INVALID_SHOWN]},
               f"{len(invalid)} invalid entries with delete_missing")

    started = utcnow()
    try:
        plan = build_plan(db, list_name, host, req.source, desired, req.delete_missing)
        need = sorted(set(plan.new) | set(plan.reclass))
        cl = classify(db, need, live_ok=set(plan.new), dry_run=req.dry_run)
    except Exception as exc:
        db.rollback()
        log.exception("sync %s/%s failed while planning", list_name, req.sync_id)
        if not req.dry_run:
            _record_failure(db, list_name, host, req, fp, actor, ip, exc)
        raise SyncRejected(500, "sync failed before anything was applied; no changes were made") from None

    deferred = bool(plan.removals) and cl.errors > 0
    removals = [] if deferred else plan.removals

    if req.dry_run:
        return _dry_run(db, list_name, host, req, plan, cl, removals, deferred, invalid, dups, received)

    # ---- apply: one transaction for entries, ownership, suppression, feed, run record and audit
    with service._snapshot_lock:
        try:
            before_snap = db.get(service.EdlSnapshot, list_name)
            before = set(before_snap.body.splitlines()) if before_snap else set()
            plan = build_plan(db, list_name, host, req.source, desired, req.delete_missing)  # fresh read
            if deferred:
                plan.removals, plan.kept_missing = [], plan.kept_missing + plan.removals
            now = utcnow()
            changed = _write(db, list_name, host, req, plan, cl, now)
            db.flush()
            service.rebuild_snapshot(db, list_name, commit=False)
            view = _view_from_db(db, list_name, plan.desired)
            report = assemble_report(
                req=req, host=host, plan=plan, cl=cl, view=view, invalid=invalid, duplicates=dups,
                received=received, before=before, removed_values=list(plan.removals),
                entries_deleted=changed["entries_deleted"], retained=changed["retained"], deferred=deferred,
                dry_run=False, details_extra={})
            report["list"] = list_name
            c = report["counts"]
            did_change = bool(plan.new or plan.shared_add or plan.yaml_changed or plan.removals
                              or changed["reclassified"] or report["feed"]["changed"])
            status = "applied" if did_change else "no_change"
            run = SyncRun(list_name=list_name, host=host, source_id=req.source, sync_id=req.sync_id,
                          fingerprint=fp, started_at=started, finished_at=now, status=status,
                          summary=json.dumps(c), report=json.dumps(report),
                          dedup_key=_dedup_key(list_name, host, req.source, req.sync_id))
            db.add(run)
            db.flush()
            _touch_source(db, list_name, host, req.source, req.sync_id,
                          status if not cl.errors else status + "_with_errors", run.id, now, json.dumps(c))
            audit.record(db, actor=actor, action="sync", target=list_name, kind="api", ip=ip, commit=False,
                         detail=(f"source={req.source} sync_id={req.sync_id} {status}: new={c['new']} "
                                 f"unchanged={c['unchanged']} removed={c['removed']} blocked="
                                 f"{c['blocked_by_policy'] + c['blocked_by_classification']} "
                                 f"pending={c['pending_classification']} suppressed={c['suppressed_by_shadowing']} "
                                 f"invalid={c['invalid']} errors={c['processing_errors']}"
                                 + (" removals_deferred" if deferred else "")))
            db.commit()
        except IntegrityError:
            db.rollback()
            # a concurrent request with the same sync_id won the unique key: report its result
            prior = db.scalar(select(SyncRun).where(
                SyncRun.dedup_key == _dedup_key(list_name, host, req.source, req.sync_id)))
            if prior is not None and prior.fingerprint == fp:
                report = json.loads(prior.report or "{}")
                report.update(duplicate=True, run_id=prior.id, status=prior.status)
                return report
            log.exception("sync %s/%s hit a database conflict", list_name, req.sync_id)
            _record_failure(db, list_name, host, req, fp, actor, ip, RuntimeError("database conflict"))
            raise SyncRejected(409, "the list changed while the sync was being applied; no changes were "
                                    "made, retry with the same sync_id") from None
        except Exception as exc:
            db.rollback()
            log.exception("sync %s/%s failed; nothing was applied", list_name, req.sync_id)
            _record_failure(db, list_name, host, req, fp, actor, ip, exc)
            raise SyncRejected(500, "sync failed and was rolled back; no changes were made") from None
    report.update(run_id=run.id, status=status, duplicate=False)
    return report


def _record_failure(db: Session, list_name, host, req, fp, actor, ip, exc: Exception) -> None:
    try:
        now = utcnow()
        db.add(SyncRun(list_name=list_name, host=host, source_id=req.source, sync_id=req.sync_id,
                       fingerprint=fp, started_at=now, finished_at=now, status="failed",
                       summary=json.dumps({"error": type(exc).__name__}), error=type(exc).__name__))
        _touch_source(db, list_name, host, req.source, req.sync_id, "failed", None, now,
                      json.dumps({"error": type(exc).__name__}))
        audit.record(db, actor=actor, action="sync-failed", target=list_name, kind="api", ip=ip, commit=False,
                     detail=f"source={req.source} sync_id={req.sync_id}: {type(exc).__name__}; nothing was applied")
        db.commit()
    except Exception:
        db.rollback()
        log.exception("could not record the failed sync")


def _write(db: Session, list_name: str, host: str, req: SyncIn, plan: Plan, cl: Classified, now) -> dict:
    """Apply the plan inside the caller's transaction (nothing is committed here)."""
    source_note = f"{host}:{req.source}"
    rows = []
    for v in plan.new:
        o = cl.outcomes.get(v) or Outcome("pending", "awaiting classification", target=classification_target(v),
                                          method="wildcard_apex" if v.startswith("*.") else "url",
                                          wildcard=v.startswith("*."))
        status, detail = status_for(o)
        rows.append({"list_name": list_name, "value": v, "source": source_note, "status": status, "detail": detail,
                     "created_at": now, "enabled": True,
                     # never-attempted entries get no timestamp, so the engine classifies them first
                     "checked_at": None if cl.how.get(v) == "queued" else now,
                     **service.class_fields(o, status)})
    new_ids: dict[str, int] = {}
    if rows:  # bulk insert (executemany), then one query for the generated ids: no per-entry round trips
        max_before = db.scalar(select(func.max(Entry.id))) or 0
        for chunk in service._chunks(rows, 5000):
            db.execute(Entry.__table__.insert(), chunk)
        wanted = set(plan.new)
        for i, v in db.execute(select(Entry.id, Entry.value).where(Entry.list_name == list_name, Entry.id > max_before)):
            if v in wanted:
                new_ids[v] = i
    owner_rows = [{"entry_id": new_ids[v], "list_name": list_name, "kind": "sync", "host": host,
                   "source_id": req.source, "yaml_list": plan.desired[v], "created_at": now, "last_seen_at": now,
                   "last_sync_id": req.sync_id} for v in plan.new]
    for v in plan.shared_add:
        owner_rows.append({"entry_id": plan.existing[v].id, "list_name": list_name, "kind": "sync", "host": host,
                           "source_id": req.source, "yaml_list": plan.desired[v], "created_at": now,
                           "last_seen_at": now, "last_sync_id": req.sync_id})
    for k in range(0, len(owner_rows), 5000):
        db.execute(EntrySource.__table__.insert(), owner_rows[k:k + 5000])
    for v in plan.yaml_changed:
        oid = plan.owned[v][0]
        db.execute(update(EntrySource).where(EntrySource.id == oid)
                   .values(yaml_list=plan.desired[v], last_seen_at=now, last_sync_id=req.sync_id))

    reclassified = 0
    ids = [plan.existing[v].id for v in plan.reclass]
    by_id = {}
    for chunk in service._chunks(ids, 500):
        by_id.update({e.id: e for e in db.scalars(select(Entry).where(Entry.id.in_(chunk)))})
    for v in plan.reclass:
        e, o = by_id.get(plan.existing[v].id), cl.outcomes.get(v)
        if e is None or o is None or o.kind in ("error", "uncached"):
            continue  # an outage or an exhausted budget never changes what was already decided
        status, detail = status_for(o)
        if (e.status, e.detail, e.class_method) != (status, detail, service.class_fields(o, status)["class_method"]):
            reclassified += 1
        service.set_classification(e, o, status, detail, now)

    entries_deleted = retained = 0
    if plan.removals:
        own_ids = [plan.owned[v][0] for v in plan.removals]
        entry_ids = [plan.owned[v][1] for v in plan.removals]
        for chunk in service._chunks(own_ids, 500):
            db.execute(delete(EntrySource).where(EntrySource.id.in_(chunk)))
        for chunk in service._chunks(entry_ids, 500):
            still = set(db.scalars(select(EntrySource.entry_id).where(EntrySource.entry_id.in_(chunk))))
            gone = [i for i in chunk if i not in still]
            retained += len(chunk) - len(gone)
            if gone:
                db.execute(delete(Entry).where(Entry.id.in_(gone)))
                entries_deleted += len(gone)
    return {"reclassified": reclassified, "entries_deleted": entries_deleted, "retained": retained}


def _view_from_db(db: Session, list_name: str, desired) -> dict[str, dict]:
    rows = db.execute(select(Entry.id, Entry.value, Entry.status, Entry.enabled, Entry.suppressed_by)
                      .where(Entry.list_name == list_name)).all()
    state = {v: [i, st, en is not False] for i, v, st, en, _ in rows}
    sup = {v: sb for _i, v, _st, _en, sb in rows}
    view = state_view(state, desired)
    for v in desired:
        if v in view:
            view[v]["suppressed_by"] = sup.get(v)  # what was actually stored
    return view


def _dry_run(db: Session, list_name, host, req, plan: Plan, cl: Classified, removals, deferred, invalid, dups,
             received) -> dict:
    """Nothing is written. Panorama is never contacted: entries without a cached answer are reported as
    'requires_live' and projected as pending."""
    removed_entry_values: set[str] = set()
    retained = 0
    if removals:
        entry_ids = {plan.owned[v][1]: v for v in removals}
        others: set[int] = set()
        for chunk in service._chunks(list(entry_ids), 500):
            others |= set(db.scalars(select(EntrySource.entry_id).where(
                EntrySource.entry_id.in_(chunk),
                ~((EntrySource.host == host) & (EntrySource.source_id == req.source) & (EntrySource.kind == "sync")))))
        for eid, v in entry_ids.items():
            if eid in others:
                retained += 1
            else:
                removed_entry_values.add(v)
    plan.removals = list(removals)
    if deferred:
        plan.kept_missing = plan.kept_missing + [v for v in plan.owned if v not in plan.desired and v not in removals]
    view = simulate(db, list_name, plan, cl, removed_entry_values, req.delete_missing)
    snap = db.get(service.EdlSnapshot, list_name)
    before = set(snap.body.splitlines()) if snap else set()
    report = assemble_report(
        req=req, host=host, plan=plan, cl=cl, view=view, invalid=invalid, duplicates=dups, received=received,
        before=before, removed_values=list(plan.removals), entries_deleted=len(removed_entry_values),
        retained=retained, deferred=deferred, dry_run=True, details_extra={})
    report.update(list=list_name, status="dry_run", duplicate=False, run_id=None)
    report["classification_needed"] = {
        "cached": sum(1 for h in cl.how.values() if h == "cached"),
        "requires_live": sum(1 for h in cl.how.values() if h == "requires_live"),
        "left_to_engine": sum(1 for h in cl.how.values() if h == "engine"),
        "not_required": sum(1 for h in cl.how.values() if h == "not_required"),
    }
    return report
