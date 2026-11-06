import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from . import settings_store
from .db import AppSetting, CategoryCache, EdlSnapshot, Entry, EntrySource, utcnow
from .normalize import MAX_SOURCE_LENGTH, EntryTooLong, normalize, split_value
from .config import MAX_PANORAMA_CONCURRENCY
from .panorama import (Classification, MockPanoramaClient, PanoramaClient, PanoramaError, parse_result_text)
from .psl import is_public_suffix
from .shadow import compute_shadows, suppressed_by

log = logging.getLogger("edl")

PUBLISHED = ("active", "unverified")
_client: PanoramaClient | MockPanoramaClient | None = None


# --------------------------------------------------------------------------- #
# Panorama client lifecycle
# --------------------------------------------------------------------------- #
def make_client(s: Settings) -> PanoramaClient | MockPanoramaClient:
    if s.panorama_mode == "mock":
        return MockPanoramaClient(s)
    return PanoramaClient(s)


def get_client() -> PanoramaClient | MockPanoramaClient:
    global _client
    if _client is None:
        s = get_settings()
        if s.panorama_mode == "mock":
            log.warning("Panorama mode is 'mock': category data is simulated, do not use in production")
        _client = make_client(s)
    return _client


def reset_client() -> None:
    """Drop the cached client so the next lookup uses the current settings."""
    global _client
    old, _client = _client, None
    if old is not None:
        old.close()


def test_connection(s: Settings) -> dict:
    """Check connectivity and authentication with the given settings. Never raises, and the
    result never contains the API key."""
    try:
        client = make_client(s)
    except PanoramaError as exc:
        return {"ok": False, "message": str(exc)}
    try:
        return client.test_connection()
    except PanoramaError as exc:
        return {"ok": False, "message": str(exc)}
    except Exception as exc:  # type name only: arbitrary exception text could echo credentials
        return {"ok": False, "message": f"unexpected error: {type(exc).__name__}"}
    finally:
        client.close()


def clear_classification_cache(db: Session) -> int:
    res = db.execute(delete(CategoryCache))
    db.commit()
    return res.rowcount or 0


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Outcome:
    kind: str  # clean | blocked | unknown | error | invalid | wildcard | pending | uncached
    detail: str | None = None
    categories: tuple[str, ...] = ()
    target: str | None = None      # what was submitted to Panorama (the apex domain, for wildcards)
    method: str = "url"            # url | wildcard_apex
    wildcard: bool = False


WILDCARD_EXCLUDED = ("wildcard excluded by policy: Panorama classifies individual URLs and cannot vouch for "
                     "every subdomain this wildcard covers")
WILDCARD_NEEDS_CLASSIFICATION = ("classification is disabled, but the wildcard policy requires the base domain to be "
                                 "classified before a wildcard is published")
WILDCARD_INCONCLUSIVE = ("inconclusive: Panorama gave no usable category for the base domain, so the wildcard "
                         "stays pending (an inconclusive result is never treated as approval)")
WILDCARD_APEX_NOTE = ("wildcard: only the base domain was classified; the category of subdomains is NOT verified")


def _is_wildcard(value: str) -> bool:
    return value.startswith("*.")


def classification_target(value: str) -> str:
    """What is submitted to Panorama for an entry.

    A wildcard is NEVER submitted literally: `*.example.com/` is classified as its apex `example.com`
    and `*.sub.example.com/` as `sub.example.com`. That answer describes the apex only (see the
    README: it does not prove every subdomain is safe). Other entries are submitted as host or
    host/path."""
    host, path = split_value(value)
    if host.startswith("*."):
        return host[2:]
    return f"{host}/{path}" if path else host


def _suffix_wildcard(value: str) -> bool:
    """Legacy rows only: new submissions are rejected by normalize(). A stored wildcard over a
    public suffix (*.com) would shadow and publish a huge slice of the internet, so it is never
    eligible regardless of classification settings."""
    host = value.partition("/")[0]
    return _is_wildcard(host) and is_public_suffix(host[2:])


def _chunks(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def lookup_outcomes(db: Session, values: list[str], force: bool = False, *,
                    cache_only: bool = False) -> dict[str, Outcome]:
    """Ask Panorama (via the cache) about each entry. No status policy is applied here.

    Identical targets are asked once (so a thousand `*.example.com` entries cost one request) and a
    fresh cached answer is never re-requested. cache_only=True never contacts Panorama and never
    writes: targets without a fresh cached answer come back as kind "uncached" (used by dry runs)."""
    s = get_settings()
    values = list(values)
    out: dict[str, Outcome] = {}
    for v in values:
        if _suffix_wildcard(v):
            out[v] = Outcome("invalid", "wildcard targets a public suffix (not allowed)", wildcard=True,
                             method="wildcard_apex")
    # Wildcard exclusion is a publishing policy, not a Panorama feature: it is enforced here, before
    # (and independently of) the classification switch, for new submissions and for every recheck.
    if s.wildcard_classification_policy == "exclude":
        for v in values:
            if v not in out and _is_wildcard(v):
                out[v] = Outcome("wildcard", WILDCARD_EXCLUDED, wildcard=True, method="wildcard_apex")
    values = [v for v in values if v not in out]
    if not s.classification_enabled:
        for v in values:
            if _is_wildcard(v):  # this policy requires the apex to be classified, so it cannot be approved
                out[v] = Outcome("pending", WILDCARD_NEEDS_CLASSIFICATION, wildcard=True, method="wildcard_apex")
            else:
                out[v] = Outcome("clean")
        return out

    now = utcnow()
    ttl = timedelta(hours=s.classification_cache_ttl_hours)
    targets = {v: classification_target(v) for v in values}
    unique = sorted(set(targets.values()))

    parsed: dict[str, Classification] = {}
    raw_by_target: dict[str, str] = {}
    if not force and ttl.total_seconds() > 0:
        for chunk in _chunks(unique, 500):
            for row in db.scalars(select(CategoryCache).where(CategoryCache.target.in_(chunk))):
                checked = row.checked_at if row.checked_at.tzinfo else row.checked_at.replace(tzinfo=now.tzinfo)
                if now - checked < ttl:
                    try:  # a cached answer that cannot be parsed (older format) is simply re-fetched
                        parsed[row.target] = parse_result_text(row.raw, row.target)
                        raw_by_target[row.target] = row.raw
                    except PanoramaError:
                        continue

    todo = [t for t in unique if t not in raw_by_target]
    errors: dict[str, str] = {}
    uncached: set[str] = set()
    if todo and cache_only:
        uncached, todo = set(todo), []
    if todo:
        client, client_error = None, ""
        try:
            client = get_client()
        except PanoramaError as exc:  # e.g. host/key not configured yet
            client_error = str(exc)

        def work(t: str):
            if client is None:
                return t, None, client_error
            try:
                raw = client.lookup(t)
                parse_result_text(raw, t)  # an answer that cannot be understood is a failed lookup
                return t, raw, None
            except PanoramaError as exc:
                return t, None, str(exc)

        # Never more than MAX_PANORAMA_CONCURRENCY workers; the limiter inside the client also
        # caps in-flight requests process-wide across all callers.
        workers = max(1, min(s.max_concurrent_requests, MAX_PANORAMA_CONCURRENCY))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for t, raw, err in pool.map(work, todo):
                if err:
                    errors[t] = err
                    continue
                raw_by_target[t] = raw
                parsed[t] = parse_result_text(raw, t)
                row = db.get(CategoryCache, t)
                if row:
                    row.raw, row.checked_at = raw, now
                else:
                    db.add(CategoryCache(target=t, raw=raw, checked_at=now))
        db.flush()

    high_risk = s.high_risk_set
    for value, target in targets.items():
        wc = _is_wildcard(value)
        method = "wildcard_apex" if wc else "url"
        if target in uncached:
            out[value] = Outcome("uncached", "no fresh cached classification", target=target, method=method, wildcard=wc)
            continue
        if target in errors:
            out[value] = Outcome("error", errors[target], target=target, method=method, wildcard=wc)
            continue
        c = parsed[target]
        note = WILDCARD_APEX_NOTE if wc else None
        cats = tuple(sorted(c.categories))
        hits = sorted(set(c.categories) & high_risk)
        if hits:
            out[value] = Outcome("blocked", ", ".join(hits) + (" (base domain)" if note else ""), cats, target, method, wc)
        elif c.unknown:
            out[value] = Outcome("unknown", note, cats, target, method, wc)
        else:
            out[value] = Outcome("clean", note, cats, target, method, wc)
    return out


def lookup_with_retries(db: Session, values: list[str], force: bool = False) -> dict[str, Outcome]:
    """lookup_outcomes plus the engine's retry rounds for entries whose lookup failed."""
    s = get_settings()
    out = lookup_outcomes(db, values, force)
    for _ in range(s.retry_attempts):
        failed = [v for v, o in out.items() if o.kind == "error"]
        if not failed:
            break
        if s.retry_delay_seconds:
            time.sleep(s.retry_delay_seconds)
        out.update(lookup_outcomes(db, failed, force))
    return out


def status_for(outcome: Outcome) -> tuple[str, str | None]:
    """Apply the unknown-category and failure policies to a lookup outcome."""
    s = get_settings()
    if outcome.kind == "clean":
        return "active", outcome.detail
    if outcome.kind in ("blocked", "invalid", "wildcard"):
        return "blocked", outcome.detail
    if outcome.kind == "pending":
        return "pending", outcome.detail
    if outcome.wildcard and outcome.kind in ("error", "unknown"):
        # Wildcards that need classification fail CLOSED whatever the failure and unknown-category
        # settings say: an unavailable or inconclusive Panorama is never approval.
        if outcome.kind == "error":
            return "pending", f"awaiting classification of the base domain: {outcome.detail}"
        return "pending", WILDCARD_INCONCLUSIVE
    if outcome.kind == "unknown":
        note = f"; {outcome.detail}" if outcome.detail else ""
        if s.unknown_category_behaviour == "publish":
            return "active", "unknown category (published by policy)" + note
        return "blocked", "unknown category (excluded by policy)" + note
    if s.classification_failure_behaviour == "fail-open":
        return "unverified", f"not verified: {outcome.detail}"
    return "pending", outcome.detail


def classify(db: Session, values: list[str], force: bool = False) -> dict[str, tuple[str, str | None]]:
    """Return {entry value: (status, detail)}."""
    return {v: status_for(o) for v, o in lookup_outcomes(db, values, force).items()}


_RESULT_FOR_KIND = {"clean": "clean", "blocked": "blocked", "unknown": "unknown", "error": "error",
                    "wildcard": "excluded", "invalid": "invalid", "pending": "disabled", "uncached": "error"}


def class_fields(outcome: Outcome, status: str) -> dict:
    """The classification metadata stored on an entry (method, what was submitted, result, categories,
    status). `detail` carries the human-readable reason; the timestamp is Entry.checked_at."""
    if outcome.kind == "wildcard":
        cstatus = "excluded"
    else:
        cstatus = {"active": "approved", "unverified": "unverified", "blocked": "blocked",
                   "pending": "pending"}.get(status, status)
    result = _RESULT_FOR_KIND.get(outcome.kind, outcome.kind)
    if outcome.kind == "clean" and outcome.target is None:
        result = "not_classified"
    return {"class_method": outcome.method if outcome.target else None,
            "class_target": outcome.target, "class_result": result,
            "class_categories": ",".join(outcome.categories) or None, "class_status": cstatus}


def set_classification(e: Entry, outcome: Outcome, status: str, detail: str | None, now) -> None:
    e.status, e.detail, e.checked_at = status, detail, now
    for k, v in class_fields(outcome, status).items():
        setattr(e, k, v)


# --------------------------------------------------------------------------- #
# Adding / removing
# --------------------------------------------------------------------------- #
class SubmissionError(ValueError):
    """The request itself is invalid (HTTP 422). Raised before anything is written, so a rejected
    request never leaves partial data behind."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def check_lengths(urls: list[str], source: str | None = None) -> None:
    """Reject over-long entries and source strings outright (never truncate, never half-store)."""
    errors: list[str] = []
    if source is not None and len(source) > MAX_SOURCE_LENGTH:
        errors.append(f"source is {len(source)} characters (host name + ':' + source); "
                      f"the maximum is {MAX_SOURCE_LENGTH}")
    for i, raw in enumerate(urls):
        try:
            normalize(raw)
        except EntryTooLong as exc:
            errors.append(f"urls[{i}]: {exc}")
        except ValueError:
            pass  # other problems are reported per URL as 'invalid' (existing behaviour)
    if errors:
        raise SubmissionError(errors)


def split_owner(source: str | None) -> tuple[str, str]:
    """(host, source note) from the composite source string `host[:note]`."""
    host, _, note = (source or "anonymous").partition(":")
    return (host or "anonymous")[:64], note[:100]


def ensure_owners(db: Session, list_name: str, entry_ids: list[int], host: str, source_id: str,
                  kind: str = "api", sync_id: str | None = None, now=None) -> int:
    """Give each entry an owner row for (host, source_id) if it does not have one. Bulk, no per-row queries."""
    have: set[int] = set()
    for chunk in _chunks(entry_ids, 500):
        have |= set(db.scalars(select(EntrySource.entry_id).where(
            EntrySource.entry_id.in_(chunk), EntrySource.host == host, EntrySource.source_id == source_id)))
    missing = [i for i in entry_ids if i not in have]
    now = now or utcnow()
    if missing:
        db.execute(EntrySource.__table__.insert(), [
            {"entry_id": i, "list_name": list_name, "kind": kind, "host": host, "source_id": source_id,
             "created_at": now, "last_seen_at": now, "last_sync_id": sync_id} for i in missing])
    return len(missing)


def add_urls(db: Session, list_name: str, urls: list[str], source: str | None,
             owner: tuple[str, str] | None = None) -> list[dict]:
    check_lengths(urls, source)  # before any database work
    with list_lock(list_name):
        return _add_urls(db, list_name, urls, source, owner)


def _add_urls(db: Session, list_name: str, urls: list[str], source: str | None,
              owner: tuple[str, str] | None) -> list[dict]:
    owner_host, owner_note = owner or split_owner(source)
    results: list[dict] = []
    fresh: list[tuple[str, str]] = []  # (raw, value)
    seen: set[str] = set()

    for raw in urls:
        try:
            value = normalize(raw)
        except ValueError as exc:
            results.append({"url": raw, "status": "invalid", "detail": str(exc)})
            continue
        if value in seen:
            results.append({"url": raw, "value": value, "status": "duplicate", "detail": "repeated in request"})
            continue
        seen.add(value)
        fresh.append((raw, value))

    existing: dict[str, Entry] = {}
    for chunk in _chunks(sorted(seen), 500):
        for e in db.scalars(select(Entry).where(Entry.list_name == list_name, Entry.value.in_(chunk))):
            existing[e.value] = e

    to_classify = []
    for raw, value in fresh:
        if value in existing:
            results.append({"url": raw, "value": value, "status": "duplicate",
                            "detail": f"already present (status: {existing[value].status})"})
        else:
            to_classify.append((raw, value))

    raw_outcomes = lookup_outcomes(db, [v for _, v in to_classify])
    now = utcnow()
    for raw, value in to_classify:
        o = raw_outcomes[value]
        status, detail = status_for(o)
        try:
            with db.begin_nested():
                e = Entry(list_name=list_name, value=value, source=source, status=status)
                set_classification(e, o, status, detail, now)
                db.add(e)
                db.flush()
                db.add(EntrySource(entry_id=e.id, list_name=list_name, kind="api", host=owner_host,
                                   source_id=owner_note, created_at=now, last_seen_at=now))
        except IntegrityError:
            results.append({"url": raw, "value": value, "status": "duplicate", "detail": "concurrent insert"})
            continue
        results.append({"url": raw, "value": value,
                        "status": "added" if status in PUBLISHED else status, "detail": detail})
    # an entry that was already stored gains this submitter as an additional owner
    dup_values = [r["value"] for r in results if r["status"] == "duplicate" and r.get("value") in existing]
    if dup_values:
        ensure_owners(db, list_name, [existing[v].id for v in set(dup_values)], owner_host, owner_note, now=now)
    db.commit()

    snapshot_inputs = published_values(db, list_name)
    shadows = compute_shadows(snapshot_inputs)
    for r in results:
        v = r.get("value")
        if r["status"] == "added":
            by = shadows.get(v)
            r["published"] = by is None
            if by:
                r["shadowed_by"] = by
        elif r["status"] in ("blocked", "pending"):
            r["published"] = False
    rebuild_snapshot(db, list_name)
    return results


def remove_urls(db: Session, list_name: str, urls: list[str]) -> int:
    check_lengths(urls)
    with list_lock(list_name):
        return _remove_urls(db, list_name, urls)


def _remove_urls(db: Session, list_name: str, urls: list[str]) -> int:
    values = set()
    for u in urls:
        try:
            values.add(normalize(u))
        except ValueError:
            continue
    if not values:
        return 0
    deleted = 0
    for chunk in _chunks(sorted(values), 500):
        ids = list(db.scalars(select(Entry.id).where(Entry.list_name == list_name, Entry.value.in_(chunk))))
        if ids:
            db.execute(delete(EntrySource).where(EntrySource.entry_id.in_(ids)))
        res = db.execute(delete(Entry).where(Entry.list_name == list_name, Entry.value.in_(chunk)))
        deleted += res.rowcount or 0
    db.commit()
    rebuild_snapshot(db, list_name)
    return deleted


# --------------------------------------------------------------------------- #
# Publishing: snapshots
# --------------------------------------------------------------------------- #
def published_rows(db: Session, list_name: str) -> list[tuple[int, str]]:
    """Entries that are individually eligible: validated and classified acceptable (active, or
    unverified under fail-open), and enabled. Suppression by wildcards is applied separately."""
    return [tuple(r) for r in db.execute(
        select(Entry.id, Entry.value).where(Entry.list_name == list_name, Entry.status.in_(PUBLISHED),
                                            Entry.enabled.is_not(False)))]


def refresh_suppression(db: Session, list_name: str) -> int:
    """Record, on each entry, which APPROVED wildcard (if any) suppresses it. Nothing is deleted:
    when the wildcard is removed, blocked, disabled or goes back to pending the rows are released
    again here. Only changed rows are written. Returns how many rows changed."""
    rows = db.execute(select(Entry.id, Entry.value, Entry.status, Entry.enabled, Entry.suppressed_by)
                      .where(Entry.list_name == list_name)).all()
    approved = [v for _, v, st, en, _ in rows if v.startswith("*.") and st in PUBLISHED and en is not False]
    new = suppressed_by((v for _, v, *_ in rows), approved)
    changes = [{"id": i, "suppressed_by": new.get(v)} for i, v, _st, _en, cur in rows if new.get(v) != cur]
    for chunk in _chunks(changes, 2000):
        db.execute(update(Entry), chunk)
    return len(changes)


def published_values(db: Session, list_name: str) -> list[str]:
    return [v for _, v in published_rows(db, list_name)]


def effective_from_rows(rows: list[tuple[int, str]]) -> tuple[list[str], int]:
    """The effective feed for eligible (id, value) rows: wildcard-suppressed entries removed, then the
    configured maximum applied (oldest kept), sorted, no duplicates. Returns (values, cut by maximum)."""
    shadows = compute_shadows(v for _, v in rows)
    kept = sorted(((i, v) for i, v in rows if v not in shadows), key=lambda r: r[0])
    limit = get_settings().edl_max_entries
    truncated = 0
    if limit and len(kept) > limit:
        truncated = len(kept) - limit
        kept = kept[:limit]
    return sorted({v for _, v in kept}), truncated


def build_body(db: Session, list_name: str) -> tuple[str, int, int]:
    """Return (feed text, entries published, eligible entries cut by the maximum).

    The effective list contains only entries that are validated, approved (active, or unverified
    under fail-open), enabled and not suppressed by an approved wildcard. Output is one entry per
    line, sorted, plain text, so identical data always produces identical bytes."""
    values, truncated = effective_from_rows(published_rows(db, list_name))
    return ("\n".join(values) + "\n" if values else ""), len(values), truncated


_list_locks: dict[str, threading.RLock] = {}
_list_locks_guard = threading.Lock()


def list_lock(list_name: str) -> threading.RLock:
    """One lock per list: serialises sync, submissions and removals for that list."""
    with _list_locks_guard:
        return _list_locks.setdefault(list_name, threading.RLock())


_snapshot_lock = threading.RLock()  # serialises rebuilds so a slow, stale one cannot overwrite a newer one


def _snapshot_error_key(list_name: str) -> str:
    return f"snapshot_error:{list_name}"


def _apply_snapshot(db: Session, list_name: str) -> tuple[EdlSnapshot | None, bool]:
    """Bring suppression and the stored feed up to date inside the CURRENT transaction (no commit).
    Returns (snapshot, whether the stored feed changed). The feed is not touched when the effective
    output is identical."""
    s = get_settings()
    refresh_suppression(db, list_name)
    body, count, truncated = build_body(db, list_name)
    snap = db.get(EdlSnapshot, list_name)
    if count == 0 and snap is not None and snap.entry_count > 0 and s.edl_empty_behaviour == "keep-previous":
        note = (f"Retained: no eligible entries remain, so the previous list ({snap.entry_count} "
                "entries) is still being served (empty-list behaviour: keep-previous).")
        if not snap.retained or snap.note != note:
            snap.retained, snap.note = True, note
            log.warning("list %s: %s", list_name, note)
            return snap, True
        return snap, False
    etag = hashlib.sha256(body.encode()).hexdigest()[:32]
    now = utcnow()
    if snap is None:
        snap = EdlSnapshot(list_name=list_name, body=body, entry_count=count, truncated=truncated,
                           etag=etag, generated_at=now, retained=False, note=None)
        db.add(snap)
        return snap, True
    if snap.etag != etag or snap.truncated != truncated or snap.retained:
        snap.body, snap.entry_count, snap.truncated = body, count, truncated
        snap.etag, snap.generated_at, snap.retained, snap.note = etag, now, False, None
        return snap, True
    return snap, False


def rebuild_snapshot(db: Session, list_name: str, *, commit: bool = True) -> EdlSnapshot | None:
    """Regenerate the stored feed.

    The new body is built completely in memory first, then the snapshot row is replaced in ONE
    database transaction (body, count, etag and flags together). If anything fails, the
    transaction is rolled back, the previous snapshot is untouched and keeps being served, and
    the failure is recorded so administrators can see it.

    commit=False is for callers that own a larger transaction (sync): the snapshot is written with
    it, errors propagate so the caller rolls everything back, and nothing is committed here."""
    s = get_settings()
    with _snapshot_lock:
        if not commit:
            return _apply_snapshot(db, list_name)[0]
        try:
            snap, changed = _apply_snapshot(db, list_name)
            db.commit()
            _clear_snapshot_error(db, list_name)
            if changed and snap is not None and snap.truncated:
                log.warning("list %s: %d eligible entries are not published (maximum %d reached)",
                            list_name, snap.truncated, s.edl_max_entries)
            return snap
        except Exception as exc:
            db.rollback()
            log.exception("could not rebuild the feed for list %s; the previous version is still served", list_name)
            try:
                settings_store.set_state(db, _snapshot_error_key(list_name),
                                         {"at": utcnow().isoformat(), "error": type(exc).__name__})
            except Exception:
                db.rollback()
            return db.get(EdlSnapshot, list_name)


def _clear_snapshot_error(db: Session, list_name: str) -> None:
    row = db.get(AppSetting, f"state:{_snapshot_error_key(list_name)}")
    if row is not None:
        db.delete(row)
        db.commit()


def snapshot_status(db: Session, list_name: str) -> dict:
    """What firewalls are being served versus what the database currently makes eligible."""
    s = get_settings()
    snap = db.get(EdlSnapshot, list_name)
    published = set(snap.body.splitlines()) if snap else set()
    try:
        body, _, _ = build_body(db, list_name)
        eligible = set(body.splitlines())
    except Exception:  # the status page must still work when the database cannot be evaluated
        log.exception("could not compute eligible entries for list %s", list_name)
        db.rollback()
        eligible = published
    only_pub, only_elig = sorted(published - eligible), sorted(eligible - published)
    error = settings_store.get_state(db, _snapshot_error_key(list_name))
    if not s.edl_publishing_enabled:
        serving = "disabled: firewalls receive HTTP 503 and keep their current list"
    elif snap is None:
        serving = "no feed generated yet (HTTP 503)"
    elif snap.entry_count == 0 and s.edl_empty_behaviour == "return-error":
        serving = "HTTP 503: no valid entries (empty-list behaviour: return-error)"
    elif snap.retained:
        serving = "previous list retained (keep-previous)"
    else:
        serving = "current"
    return {
        "list_name": list_name, "entry_count": snap.entry_count if snap else 0,
        "truncated": snap.truncated if snap else 0, "generated_at": snap.generated_at if snap else None,
        "eligible_count": len(eligible), "published_count": len(published),
        "only_published": len(only_pub), "only_eligible": len(only_elig),
        "sample_only_published": only_pub[:10], "sample_only_eligible": only_elig[:10],
        "differs": bool(only_pub or only_elig), "retained": bool(snap and snap.retained),
        "note": snap.note if snap else None, "serving": serving,
        "last_error": error,
    }


def snapshot_statuses(db: Session) -> list[dict]:
    return [snapshot_status(db, n) for n in sorted(set(db.scalars(select(EdlSnapshot.list_name))))]


def reconcile_wildcards(db: Session) -> dict[str, int]:
    """Make stored wildcard entries consistent with the wildcard policy and the public-suffix rule,
    without calling Panorama and without deleting anything (rows are only re-statused).

    - wildcards over a public suffix (legacy data) -> blocked
    - policy 'exclude': published and pending wildcards -> blocked/excluded (reason recorded)
    - policy 'apex-classification':
        wildcards previously excluded by policy -> pending, so the base domain is classified
        (nothing is published until that succeeds)
        published wildcards while classification is disabled, or published without verification
        (legacy fail-open) -> pending, because this policy requires the base domain to be classified
    Blocked-by-classification wildcards keep their verdict until a recheck. Snapshots (and the
    suppression recorded on subdomain rows) of affected lists are rebuilt."""
    sset = get_settings()
    policy = sset.wildcard_classification_policy
    counts = {"public_suffix": 0, "excluded": 0, "released": 0, "demoted": 0}
    touched: set[str] = set()
    for e in db.scalars(select(Entry).where(Entry.value.like("*.%"))):
        if _suffix_wildcard(e.value):
            if e.status != "blocked" or not (e.detail or "").startswith("wildcard targets a public suffix"):
                e.status, e.detail = "blocked", "wildcard targets a public suffix (not allowed)"
                e.class_status, e.class_result = "blocked", "invalid"
                counts["public_suffix"] += 1
                touched.add(e.list_name)
        elif policy == "exclude":
            if e.status in PUBLISHED or e.status == "pending":
                e.status, e.detail = "blocked", WILDCARD_EXCLUDED
                e.class_status, e.class_result = "excluded", "excluded"
                e.class_method = e.class_target = e.class_categories = None
                counts["excluded"] += 1
                touched.add(e.list_name)
        elif e.status == "blocked" and e.detail == WILDCARD_EXCLUDED:
            e.status, e.detail = "pending", "awaiting classification of the base domain"
            e.class_status, e.class_result = "pending", None
            counts["released"] += 1
            touched.add(e.list_name)
        elif e.status == "unverified" or (e.status == "active" and not sset.classification_enabled):
            e.status = "pending"
            e.detail = WILDCARD_NEEDS_CLASSIFICATION if not sset.classification_enabled else \
                "awaiting classification of the base domain"
            e.class_status = "pending"
            counts["demoted"] += 1
            touched.add(e.list_name)
    db.commit()
    if touched:
        log.info("wildcard reconciliation (policy %s): %s", policy, counts)
        rebuild_snapshots(db, touched)
    return counts


def all_list_names(db: Session) -> set[str]:
    names = set(db.scalars(select(Entry.list_name).distinct()))
    names |= set(db.scalars(select(EdlSnapshot.list_name)))
    names.add(get_settings().edl_name)
    return names


def rebuild_snapshots(db: Session, lists: set[str] | None = None) -> None:
    for name in sorted(lists if lists is not None else all_list_names(db)):
        rebuild_snapshot(db, name)


def get_snapshot(db: Session, list_name: str) -> EdlSnapshot | None:
    return db.get(EdlSnapshot, list_name) or rebuild_snapshot(db, list_name)


# --------------------------------------------------------------------------- #
# Re-checking (categories change over time) and background processing
# --------------------------------------------------------------------------- #
def recheck_entries(db: Session, entries: list[Entry], *, force: bool = True, retries: bool = False) -> dict[str, int]:
    values = sorted({e.value for e in entries})
    outcomes = lookup_with_retries(db, values, force) if retries else lookup_outcomes(db, values, force)
    now = utcnow()
    changed = 0
    kept = 0
    for e in entries:
        o = outcomes[e.value]
        if o.kind == "error" and e.status in ("active", "blocked", "unverified"):
            # Panorama could not be asked this time. An entry that was classified earlier keeps its
            # status (and stays in / out of the feed) instead of being demoted by a transient outage.
            kept += 1
            continue
        status, detail = status_for(o)
        if status != e.status:
            changed += 1
            log.info("entry %s/%s: %s -> %s (%s)", e.list_name, e.value, e.status, status, detail)
        set_classification(e, o, status, detail, now)
    db.commit()
    if kept:
        log.warning("%d entries could not be re-checked (Panorama unavailable); their status is unchanged", kept)
    return {"checked": len(entries), "changed": changed, "unchanged_after_error": kept}


def recheck_wildcards(db: Session, list_name: str | None = None, *, force: bool = True) -> dict[str, int]:
    """Re-classify only the stored wildcard entries (the admin 'recheck wildcards' action). Their
    apex domains are de-duplicated, answered from the cache unless force=True, and fetched at most
    max_concurrent_requests at a time. Nothing is deleted. An unreachable Panorama leaves entries
    that were already classified exactly as they are."""
    out = recheck(db, list_name, force=force, retries=True, wildcards_only=True)
    out["policy"] = get_settings().wildcard_classification_policy
    return out


def recheck(db: Session, list_name: str | None = None, *, force: bool = True, retries: bool = False,
            wildcards_only: bool = False) -> dict[str, int]:
    """Re-classify stored entries in batches (one list, or all). Snapshots are rebuilt afterwards,
    even if a batch fails part-way, so published data always reflects what was committed."""
    q = select(Entry.id)
    if list_name:
        q = q.where(Entry.list_name == list_name)
    if wildcards_only:
        q = q.where(Entry.value.like("*.%"))
    ids = list(db.scalars(q.order_by(Entry.id)))
    batch = get_settings().max_batch_size
    checked = changed = 0
    touched: set[str] = {list_name} if list_name else set()
    try:
        for chunk in _chunks(ids, batch):
            entries = list(db.scalars(select(Entry).where(Entry.id.in_(chunk))))
            r = recheck_entries(db, entries, force=force, retries=retries)
            checked += r["checked"]
            changed += r["changed"]
            touched |= {e.list_name for e in entries}
    finally:
        db.rollback()
        if touched:
            rebuild_snapshots(db, touched)
    return {"checked": checked, "changed": changed}


def process_pending(db: Session) -> dict[str, int]:
    """One batch of entries that could not be classified earlier (pending or unverified),
    least recently attempted first."""
    s = get_settings()
    entries = list(db.scalars(
        select(Entry).where(Entry.status.in_(("pending", "unverified")))
        .order_by(Entry.checked_at.is_(None).desc(), Entry.checked_at, Entry.id).limit(s.max_batch_size)))
    if not entries:
        return {"checked": 0, "changed": 0}
    try:
        return recheck_entries(db, entries, force=False, retries=True)
    finally:
        db.rollback()
        rebuild_snapshots(db, {e.list_name for e in entries})


def pending_count(db: Session) -> int:
    from sqlalchemy import func
    return db.scalar(select(func.count()).select_from(Entry).where(Entry.status.in_(("pending", "unverified")))) or 0
