"""Applies the side effects of a settings change so it takes effect without a restart."""
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from . import service, settings_store
from .config import Settings, get_settings
from .engine import processing_engine
from .panorama import panorama_limiter

log = logging.getLogger("edl")
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# Changing any of these changes *where answers come from*, so cached answers are discarded.
SOURCE_KEYS = {"panorama_mode", "panorama_host", "panorama_port", "panorama_url_cmd", "panorama_target",
               "mock_categories_file"}
CONNECTION_KEYS = SOURCE_KEYS | {"panorama_api_key", "panorama_verify_tls", "panorama_connect_timeout",
                                 "panorama_retry_count", "http_request_timeout"}
CLASSIFY_KEYS = {"classification_enabled", "high_risk_categories", "unknown_category_behaviour",
                 "classification_failure_behaviour", "wildcard_classification_policy"}
EDL_KEYS = {"edl_max_entries", "edl_empty_behaviour", "edl_name"}
PROCESSING_KEYS = {"background_processing_enabled", "processing_interval_seconds", "max_batch_size",
                   "retry_attempts", "retry_delay_seconds", "reclassification_interval_hours"}


class _TZFormatter(logging.Formatter):
    def __init__(self, fmt: str, tz: ZoneInfo):
        super().__init__(fmt)
        self._tz = tz

    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created, tz=self._tz).isoformat(timespec="seconds")


def apply_runtime(s: Settings | None = None) -> None:
    """Log level, log timezone, and keeping HTTP client logs from ever being verbose."""
    s = s or get_settings()
    logging.getLogger("edl").setLevel(getattr(logging, s.log_level))
    panorama_limiter.set_limit(s.max_concurrent_requests)
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    formatter = _TZFormatter(_LOG_FORMAT, ZoneInfo(s.app_timezone))
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)


def connection_test(db: Session, updates: Mapping[str, str] | None = None) -> tuple[dict, bool]:
    """Test Panorama connectivity and authentication using the saved settings overlaid with
    `updates` (which are NOT saved; a blank secret keeps the saved one). Returns
    (result, tested_saved_config). The result of testing the saved configuration is remembered
    for the status indicator. Raises ValidationError/ValueError if the combination is invalid."""
    current = settings_store.current_values()
    merged = dict(current)
    for key, value in (updates or {}).items():
        if key in settings_store.EDITABLE and (key not in settings_store.SECRET_KEYS or value):
            merged[key] = value
    candidate = settings_store.build_effective(merged)
    saved = merged == current
    result = service.test_connection(candidate)
    result["tested_at"] = datetime.now(timezone.utc).isoformat()
    if saved:
        settings_store.set_state(db, "panorama_test", result)
    return result, saved


def on_settings_changed(db: Session, changed: set[str]) -> None:
    """Invalidate caches and notify the engine after `changed` settings were saved."""
    if not changed:
        return
    s = get_settings()
    apply_runtime(s)
    if changed & CONNECTION_KEYS:
        service.reset_client()
    if changed & SOURCE_KEYS:
        n = service.clear_classification_cache(db)
        log.info("classification cache cleared (%d entries): Panorama source settings changed", n)
    if "wildcard_classification_policy" in changed:
        service.reconcile_wildcards(db)  # immediate, needs no Panorama call
    if changed & (CLASSIFY_KEYS | SOURCE_KEYS):
        # entries may now classify differently: re-evaluate them in the background
        processing_engine.wake(reclassify=True)
    elif changed & PROCESSING_KEYS:
        processing_engine.wake()
    if changed & (EDL_KEYS | CLASSIFY_KEYS):
        service.rebuild_snapshots(db)
