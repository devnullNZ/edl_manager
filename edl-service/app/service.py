import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from . import settings_store
from .db import AppSetting, CategoryCache, EdlSnapshot, Entry, utcnow
from .normalize import MAX_SOURCE_LENGTH, EntryTooLong, normalize
from .config import MAX_PANORAMA_CONCURRENCY
from .panorama import (Classification, MockPanoramaClient, PanoramaClient, PanoramaError, lookup_target,
                       parse_result_text)
from .psl import is_public_suffix
from .shadow import compute_shadows

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
    kind: str  # clean | blocked | unknown | error | invalid | wildcard
    detail: str | None = None


WILDCARD_EXCLUDED = ("wildcard excluded by policy: Panorama classifies individual URLs and cannot vouch for "
                     "every subdomain this wildcard covers")
WILDCARD_APEX_NOTE = ("wildcard: only the base domain was classified; the category of subdomains is NOT verified")


def _is_wildcard(value: str) -> bool:
    return value.startswith("*.")


def _suffix_wildcard(value: str) -> bool:
    """Legacy rows only: new submissions are rejected by normalize(). A stored wildcard over a
    public suffix (*.com) would shadow and publish a huge slice of the internet, so it is never
    eligible regardless of classification settings."""
    host = value.partition("/")[0]
    return _is_wildcard(host) and is_public_suffix(host[2:])


def _chunks(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def lookup_outcomes(db: Session, values: list[str], force: bool = False) -> dict[str, Outcome]:
    """Ask Panorama (via the cache) about each entry. No policy is applied here."""
    s = get_settings()
    values = list(values)
    out: dict[str, Outcome] = {}
    for v in values:
        if _suffix_wildcard(v):
            out[v] = Outcome("invalid", "wildcard targets a public suffix (not allowed)")
    # Wildcard exclusion is a publishing policy, not a Panorama feature: it is enforced here, before
    # (and independently of) the classification switch, for new submissions and for every recheck.
    if s.wildcard_classification_policy == "exclude":
        for v in values:
            if v not in out and _is_wildcard(v):
                out[v] = Outcome("wildcard", WILDCARD_EXCLUDED)
    values = [v for v in values if v not in out]
    if not s.classification_enabled:
        out.update({v: Outcome("clean") for v in values})
        return out

    now = utcnow()
    ttl = timedelta(hours=s.classification_cache_ttl_hours)
    targets = {v: lookup_target(v) for v in values}
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
        if target in errors:
            out[value] = Outcome("error", errors[target])
            continue
        c = parsed[target]
        note = WILDCARD_APEX_NOTE if _is_wildcard(value) else None
        hits = sorted(set(c.categories) & high_risk)
        if hits:
            out[value] = Outcome("blocked", ", ".join(hits) + (" (base domain)" if note else ""))
        elif c.unknown:
            out[value] = Outcome("unknown", note)
        else:
            out[value] = Outcome("clean", note)
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


def add_urls(db: Session, list_name: str, urls: list[str], source: str | None) -> list[dict]:
    check_lengths(urls, source)  # before any database work
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

    outcomes = classify(db, [v for _, v in to_classify])
    now = utcnow()
    for raw, value in to_classify:
        status, detail = outcomes[value]
        try:
            with db.begin_nested():
                db.add(Entry(list_name=list_name, value=value, status=status, detail=detail,
                             source=source, checked_at=now))
        except IntegrityError:
            results.append({"url": raw, "value": value, "status": "duplicate", "detail": "concurrent insert"})
            continue
        results.append({"url": raw, "value": value,
                        "status": "added" if status in PUBLISHED else status, "detail": detail})
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
        res = db.execute(delete(Entry).where(Entry.list_name == list_name, Entry.value.in_(chunk)))
        deleted += res.rowcount or 0
    db.commit()
    rebuild_snapshot(db, list_name)
    return deleted


# --------------------------------------------------------------------------- #
# Publishing: snapshots
# --------------------------------------------------------------------------- #
def published_rows(db: Session, list_name: str) -> list[tuple[int, str]]:
    return [tuple(r) for r in db.execute(
        select(Entry.id, Entry.value).where(Entry.list_name == list_name, Entry.status.in_(PUBLISHED)))]


def published_values(db: Session, list_name: str) -> list[str]:
    return [v for _, v in published_rows(db, list_name)]


def build_body(db: Session, list_name: str) -> tuple[str, int, int]:
    """Return (feed text, entries published, eligible entries cut by the maximum).

    Shadowed entries are removed first; if the maximum still applies, the oldest entries are
    kept. Output is one entry per line, sorted, plain text."""
    rows = published_rows(db, list_name)
    shadows = compute_shadows(v for _, v in rows)
    kept = sorted(((i, v) for i, v in rows if v not in shadows), key=lambda r: r[0])
    limit = get_settings().edl_max_entries
    truncated = 0
    if limit and len(kept) > limit:
        truncated = len(kept) - limit
        kept = kept[:limit]
    values = sorted(v for _, v in kept)
    return ("\n".join(values) + "\n" if values else ""), len(values), truncated


_snapshot_lock = threading.RLock()  # serialises rebuilds so a slow, stale one cannot overwrite a newer one


def _snapshot_error_key(list_name: str) -> str:
    return f"snapshot_error:{list_name}"


def rebuild_snapshot(db: Session, list_name: str) -> EdlSnapshot | None:
    """Regenerate the stored feed.

    The new body is built completely in memory first, then the snapshot row is replaced in ONE
    database transaction (body, count, etag and flags together). If anything fails, the
    transaction is rolled back, the previous snapshot is untouched and keeps being served, and
    the failure is recorded so administrators can see it."""
    s = get_settings()
    with _snapshot_lock:
        try:
            body, count, truncated = build_body(db, list_name)
            snap = db.get(EdlSnapshot, list_name)
            if count == 0 and snap is not None and snap.entry_count > 0 and s.edl_empty_behaviour == "keep-previous":
                note = (f"Retained: no eligible entries remain, so the previous list ({snap.entry_count} "
                        "entries) is still being served (empty-list behaviour: keep-previous).")
                if not snap.retained or snap.note != note:
                    snap.retained, snap.note = True, note
                    db.commit()
                    log.warning("list %s: %s", list_name, note)
                _clear_snapshot_error(db, list_name)
                return snap
            etag = hashlib.sha256(body.encode()).hexdigest()[:32]
            now = utcnow()
            if snap is None:
                snap = EdlSnapshot(list_name=list_name, body=body, entry_count=count, truncated=truncated,
                                   etag=etag, generated_at=now, retained=False, note=None)
                db.add(snap)
            elif snap.etag != etag or snap.truncated != truncated or snap.retained:
                snap.body, snap.entry_count, snap.truncated = body, count, truncated
                snap.etag, snap.generated_at, snap.retained, snap.note = etag, now, False, None
            else:
                _clear_snapshot_error(db, list_name)
                return snap
            db.commit()
            _clear_snapshot_error(db, list_name)
            if truncated:
                log.warning("list %s: %d eligible entries are not published (maximum %d reached)",
                            list_name, truncated, s.edl_max_entries)
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
    - policy 'exclude': published wildcards -> blocked (reason recorded)
    - policy 'apex-classification': wildcards previously excluded by policy -> pending, so the
      engine classifies their base domain
    Snapshots of affected lists are rebuilt."""
    policy = get_settings().wildcard_classification_policy
    counts = {"public_suffix": 0, "excluded": 0, "released": 0}
    touched: set[str] = set()
    for e in db.scalars(select(Entry).where(Entry.value.like("*.%"))):
        if _suffix_wildcard(e.value):
            if e.status != "blocked" or not (e.detail or "").startswith("wildcard targets a public suffix"):
                e.status, e.detail = "blocked", "wildcard targets a public suffix (not allowed)"
                counts["public_suffix"] += 1
                touched.add(e.list_name)
        elif policy == "exclude":
            if e.status in PUBLISHED or e.status == "pending":
                e.status, e.detail = "blocked", WILDCARD_EXCLUDED
                counts["excluded"] += 1
                touched.add(e.list_name)
        elif e.status == "blocked" and e.detail == WILDCARD_EXCLUDED:
            e.status, e.detail = "pending", "awaiting classification of the base domain"
            counts["released"] += 1
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
        e.status, e.detail, e.checked_at = status, detail, now
    db.commit()
    if kept:
        log.warning("%d entries could not be re-checked (Panorama unavailable); their status is unchanged", kept)
    return {"checked": len(entries), "changed": changed, "unchanged_after_error": kept}


def recheck(db: Session, list_name: str | None = None, *, force: bool = True, retries: bool = False) -> dict[str, int]:
    """Re-classify stored entries in batches (one list, or all). Snapshots are rebuilt afterwards,
    even if a batch fails part-way, so published data always reflects what was committed."""
    q = select(Entry.id)
    if list_name:
        q = q.where(Entry.list_name == list_name)
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
