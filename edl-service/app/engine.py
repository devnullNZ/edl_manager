"""Background processing engine.

Every `processing_interval_seconds` it (1) retries entries that could not be classified
(pending / unverified) and works off reclassification jobs requested through the sync API,
and (2) runs scheduled reclassification of all entries every `reclassification_interval_hours`.

A cycle does not stop after one batch: while eligible work remains it takes the next batch of
`max_batch_size` entries after `processing_batch_delay_seconds`, and only then waits for the next
interval. "Eligible" means not yet attempted in this cycle, so every entry is tried once per cycle and
an outage cannot make the loop spin; if every lookup of a batch fails, Panorama is treated as
unavailable and the cycle ends. Panorama concurrency is capped inside the classifier (at most 5
requests in flight process-wide), whatever the batch size. Settings are read fresh before every batch, a
lock prevents overlapping runs, and stop() lets the batch in progress finish and then returns.
"""
import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from . import audit, service, settings_store
from . import db as dbmod
from .config import get_settings

log = logging.getLogger("edl")


class ProcessingEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._task: asyncio.Task | None = None
        self._reclassify_requested = False
        self._last_purge = float("-inf")
        self._stop = threading.Event()
        self._inflight: asyncio.Future | None = None
        self.status: dict = {"last_run": None, "last_result": None, "last_error": None, "progress": None}

    # ---- lifecycle
    def start(self) -> None:
        self._stop.clear()
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self._task = self._loop.create_task(self._run())

    async def stop(self) -> None:
        """Clean shutdown: no new batch is started, the one in progress finishes and is committed."""
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        inflight = self._inflight
        if inflight is not None and not inflight.done():
            try:
                await asyncio.wait_for(asyncio.shield(inflight), timeout=120)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                log.warning("the processing batch in progress did not finish within 120 s of shutdown")
        self._task = self._loop = self._wake = self._inflight = None

    def wake(self, reclassify: bool = False) -> None:
        """Run a cycle soon (thread-safe). reclassify=True also re-evaluates every entry."""
        if reclassify:
            self._reclassify_requested = True
        if self._loop and self._wake:
            self._loop.call_soon_threadsafe(self._wake.set)

    async def _run(self) -> None:
        while True:
            interval = get_settings().processing_interval_seconds
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            if self._stop.is_set():
                return
            self._inflight = asyncio.ensure_future(asyncio.to_thread(self.tick, drain=True))
            await asyncio.shield(self._inflight)

    # ---- one cycle
    def tick(self, *, force: bool = False, reclassify: bool = False, refresh: bool = False,
             drain: bool = False) -> dict:
        """Run one processing cycle. force=True ignores the background-processing switch (manual
        'run now' actions); reclassify=True re-evaluates every entry; refresh=True makes that
        re-evaluation ask Panorama again instead of using cached answers. drain=True (the background
        loop) keeps taking batches while eligible work remains; without it a cycle is one batch."""
        if not self._lock.acquire(blocking=False):
            return {"skipped": "a processing run is already in progress"}
        try:
            s = get_settings()
            if not s.background_processing_enabled and not force:
                return {"skipped": "background processing is disabled"}
            result: dict = {}
            with dbmod.SessionLocal() as db:
                cycle_start = dbmod.utcnow()
                result["pending"] = service.process_pending(db, before=cycle_start if drain else None)
                result["reclass_jobs"] = service.process_reclass(db)

                requested, self._reclassify_requested = self._reclassify_requested or reclassify, False
                scheduled = self._reclassification_due(db)
                if requested or scheduled:
                    # scheduled runs refresh from Panorama; settings-change runs can use the cache
                    result["reclassification"] = service.recheck(db, None, force=scheduled or refresh,
                                                                 retries=True)
                    settings_store.set_state(db, "last_reclassification",
                                             {"at": datetime.now(timezone.utc).isoformat()})
                if drain:
                    result["drain"] = self._drain(db, cycle_start, result)
                self._purge_audit(db)
                from . import sync_sessions
                sync_sessions.expire_stale(db)
            self.status.update(last_run=datetime.now(timezone.utc), last_result=result, last_error=None,
                               progress=self._progress(None, state="idle"))
            return result
        except Exception as exc:
            log.exception("processing run failed")
            self.status.update(last_run=datetime.now(timezone.utc), last_error=type(exc).__name__)
            return {"error": type(exc).__name__}
        finally:
            self._lock.release()

    def _drain(self, db, cycle_start, first: dict) -> dict:
        """Keep going while eligible work remains. Returns what the loop did and why it ended."""
        batches, processed, changed = 1, 0, 0
        for part in ("pending", "reclass_jobs"):
            processed += first[part]["checked"]
            changed += first[part]["changed"]
        cursor = first["reclass_jobs"].get("last_id", 0)
        reason = "no eligible work left"
        # a batch in which every lookup failed means Panorama is unavailable: stop, try next interval
        down = lambda r: r["checked"] > 0 and r.get("errors", 0) >= r["checked"]  # noqa: E731
        if down(first["pending"]) and not first["reclass_jobs"]["checked"]:
            reason = "Panorama appears unavailable (every lookup failed); will retry at the next interval"
            return {"batches": batches, "processed": processed, "changed": changed, "ended": reason}
        while True:
            self._progress(db, state="draining", cycle_start=cycle_start, cursor=cursor, batches=batches,
                           processed=processed)
            s = get_settings()
            if self._stop.is_set():
                reason = "stopped (shutdown)"
                break
            if not s.background_processing_enabled:
                reason = "background processing was switched off"
                break
            if s.processing_batch_delay_seconds and self._stop.wait(s.processing_batch_delay_seconds):
                reason = "stopped (shutdown)"
                break
            p = service.process_pending(db, before=cycle_start)
            j = service.process_reclass(db, after_id=cursor)
            if not p["checked"] and not j["checked"]:
                break
            batches += 1
            processed += p["checked"] + j["checked"]
            changed += p["changed"] + j["changed"]
            cursor = j.get("last_id", cursor)
            if (p["checked"] or j["checked"]) and down(p) and (down(j) or not j["checked"]):
                reason = "Panorama appears unavailable (every lookup failed); will retry at the next interval"
                break
        return {"batches": batches, "processed": processed, "changed": changed, "ended": reason}

    def _progress(self, db, *, state: str, cycle_start=None, cursor=0, batches=0, processed=0) -> dict:
        prog = {"state": state, "batches": batches, "processed": processed, "at": datetime.now(timezone.utc)}
        if db is not None and cycle_start is not None:
            prog["pending_remaining"] = service.pending_count(db)
            prog["not_yet_attempted_this_cycle"] = service.pending_count(db, before=cycle_start)
            prog["reclass_remaining"] = service.reclass_remaining(db)
        self.status["progress"] = prog
        return prog

    def _reclassification_due(self, db) -> bool:
        s = get_settings()
        if s.reclassification_interval_hours <= 0 or not s.classification_enabled:
            return False
        state = settings_store.get_state(db, "last_reclassification")
        if not state:  # first run: start the clock, don't hammer Panorama at boot
            settings_store.set_state(db, "last_reclassification", {"at": datetime.now(timezone.utc).isoformat()})
            return False
        last = datetime.fromisoformat(state["at"])
        return datetime.now(timezone.utc) - last >= timedelta(hours=s.reclassification_interval_hours)

    def _purge_audit(self, db) -> None:
        if time.monotonic() - self._last_purge < 86400:
            return
        self._last_purge = time.monotonic()
        removed = audit.purge(db)
        if removed:
            log.info("purged %d old audit record(s)", removed)


processing_engine = ProcessingEngine()
