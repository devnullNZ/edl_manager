"""Background processing engine.

Every `processing_interval_seconds` it (1) retries entries that could not be classified
(pending / unverified) in batches and (2) runs scheduled reclassification of all entries
every `reclassification_interval_hours`. Settings are read fresh on each cycle, and a lock
prevents overlapping runs, so changing them from the admin page is always safe: the new
values apply from the next cycle, and wake() makes that cycle start immediately.
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
        self.status: dict = {"last_run": None, "last_result": None, "last_error": None}

    # ---- lifecycle
    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self._task = self._loop.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = self._loop = self._wake = None

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
            await asyncio.to_thread(self.tick)

    # ---- one cycle
    def tick(self, *, force: bool = False, reclassify: bool = False, refresh: bool = False) -> dict:
        """Run one processing cycle. force=True ignores the background-processing switch (manual
        'run now' actions); reclassify=True re-evaluates every entry; refresh=True makes that
        re-evaluation ask Panorama again instead of using cached answers."""
        if not self._lock.acquire(blocking=False):
            return {"skipped": "a processing run is already in progress"}
        try:
            s = get_settings()
            if not s.background_processing_enabled and not force:
                return {"skipped": "background processing is disabled"}
            result: dict = {}
            with dbmod.SessionLocal() as db:
                result["pending"] = service.process_pending(db)

                requested, self._reclassify_requested = self._reclassify_requested or reclassify, False
                scheduled = self._reclassification_due(db)
                if requested or scheduled:
                    # scheduled runs refresh from Panorama; settings-change runs can use the cache
                    result["reclassification"] = service.recheck(db, None, force=scheduled or refresh,
                                                                 retries=True)
                    settings_store.set_state(db, "last_reclassification",
                                             {"at": datetime.now(timezone.utc).isoformat()})
                self._purge_audit(db)
            self.status.update(last_run=datetime.now(timezone.utc), last_result=result, last_error=None)
            return result
        except Exception as exc:
            log.exception("processing run failed")
            self.status.update(last_run=datetime.now(timezone.utc), last_error=type(exc).__name__)
            return {"error": type(exc).__name__}
        finally:
            self._lock.release()

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
