"""Deployment and configuration problems that administrators must be told about."""
import os

from . import settings_store
from .config import get_bootstrap, get_settings


def forwarded_trusts_everyone() -> bool:
    """uvicorn honours X-Forwarded-For only from peers listed in FORWARDED_ALLOW_IPS. '*' means any
    client could claim any source address, which defeats the per-host IP restrictions."""
    return "*" in [p.strip() for p in os.environ.get("FORWARDED_ALLOW_IPS", "").split(",")]


def worker_count() -> int:
    raw = os.environ.get("WEB_CONCURRENCY", "1")
    return int(raw) if raw.strip().isdigit() else 1


def system_warnings() -> list[tuple[str, str]]:
    """(kind, message) pairs: kind is 'err' or 'warn'."""
    out: list[tuple[str, str]] = []
    s = get_settings()
    if not s.host_api_auth_enabled:
        out.append(("err", "Host authentication is DISABLED: anyone who can reach the API can add URLs to the "
                           "published list. Re-enable it under Security and API unless this is a closed test setup."))
    elif not s.host_ip_restrictions_enabled:
        out.append(("warn", "IP restrictions are off: a valid host token works from any address."))
    if forwarded_trusts_everyone():
        out.append(("err", "FORWARDED_ALLOW_IPS=* lets any client forge its source address with X-Forwarded-For, "
                           "so host IP restrictions and rate limits can be bypassed. List only your reverse "
                           "proxy's address."))
    if worker_count() > 1:
        out.append(("err", f"WEB_CONCURRENCY={worker_count()}: rate limits, confirmations and the processing "
                           "engine are per process and are not correct with more than one worker. Run one."))
    for key in settings_store.secret_problems():
        out.append(("err", f"Secret '{key}' cannot be decrypted with ENCRYPTION_KEY. Restore the original key, or "
                           "re-enter the secret. The stored value has not been changed."))
    if s.wildcard_classification_policy == "apex-classification" and not s.classification_enabled:
        out.append(("warn", "The wildcard policy is 'Classify Apex Domain' but classification is disabled: wildcard "
                            "entries cannot be approved and stay pending (unpublished) until classification is "
                            "enabled."))
    if get_bootstrap().encryption_key_previous:
        out.append(("warn", "ENCRYPTION_KEY_PREVIOUS is set (key rotation window). Once all secrets show as "
                            "current, remove it and restart."))
    return out
