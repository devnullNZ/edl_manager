"""Application configuration.

Two layers:

* Bootstrap values (database URL, API key, admin login, SECRET_KEY, ENCRYPTION_KEY, cookie
  flag) come only from the environment / Docker secrets and are never editable at runtime.
* Everything else is an *editable setting*. The database is authoritative; the first time
  the application starts, missing settings are seeded from the environment (if provided)
  or the defaults below. Afterwards only the admin page / admin API change them.
"""
import logging
import os
import re
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_URL_CMD = "<test><url>{url}</url></test>"
DEFAULT_HIGH_RISK = "malware,phishing,command-and-control,grayware,ransomware,hacking"
DEFAULT_KNOWN = (
    "malware,phishing,command-and-control,grayware,ransomware,hacking,"
    "proxy-avoidance-and-anonymizers,newly-registered-domain,parked,dynamic-dns,"
    "questionable,extremism,high-risk,medium-risk,low-risk"
)
MAX_PANORAMA_CONCURRENCY = 5
_CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_LIST_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ENDPOINT_RE = re.compile(r"^/[A-Za-z0-9._~/-]*$")


def _normalize_categories(value: str) -> str:
    parts = [p.strip().lower() for p in re.split(r"[,\s]+", value or "") if p.strip()]
    for p in parts:
        if not _CATEGORY_RE.match(p):
            raise ValueError(f"invalid category name: {p!r} (use lowercase letters, digits and hyphens)")
    return ",".join(dict.fromkeys(parts))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    # ------------------------------------------------------------------ bootstrap
    database_url: str = "sqlite:///./edl.db"
    # Management/admin API key (X-API-Key). Separate from host credentials.
    api_key: str = ""
    admin_user: str = "admin"
    admin_password: str = ""
    # Signs admin session cookies.
    secret_key: str = ""
    # Encrypts secret settings at rest (Fernet key derived from this value).
    encryption_key: str = ""
    # During a controlled key rotation: the key the stored secrets were encrypted with before.
    # Used only for decrypting; anything it decrypts is re-encrypted with ENCRYPTION_KEY at startup.
    encryption_key_previous: str = ""
    # Set false only when serving the admin page over plain http (local development).
    admin_cookie_secure: bool = True

    # ------------------------------------------------------------------ general
    app_name: str = Field("EDL Publisher", min_length=1, max_length=80)
    app_description: str = Field("External Dynamic List publisher for Palo Alto firewalls", max_length=300)
    app_timezone: str = "UTC"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    audit_logging_enabled: bool = True
    audit_retention_days: int = Field(365, ge=0, le=36500)

    # ------------------------------------------------------------------ panorama
    # "mock" needs no Panorama: categories are simulated (development only).
    panorama_mode: Literal["live", "mock"] = "live"
    panorama_host: str = Field("", max_length=253)
    panorama_port: int = Field(443, ge=1, le=65535)
    panorama_api_key: str = ""
    panorama_verify_tls: bool = True
    panorama_connect_timeout: float = Field(
        10.0, ge=1, le=120, validation_alias=AliasChoices("panorama_connect_timeout", "panorama_timeout"))
    panorama_retry_count: int = Field(2, ge=0, le=10)
    # Optional: serial of a managed firewall to proxy lookups through (Panorama "target").
    panorama_target: str = Field("", max_length=64)
    # XML op command; {url} is replaced with the (escaped) URL being looked up.
    panorama_url_cmd: str = Field(DEFAULT_URL_CMD, max_length=500)
    mock_categories_file: str = Field("", max_length=500)

    # ------------------------------------------------------------------ classification
    classification_enabled: bool = Field(
        True, validation_alias=AliasChoices("classification_enabled", "category_check_enabled"))
    classification_cache_ttl_hours: int = Field(24, ge=0, le=8760)
    classification_failure_behaviour: Literal["fail-closed", "fail-open"] = "fail-closed"
    high_risk_categories: str = Field(
        DEFAULT_HIGH_RISK, validation_alias=AliasChoices("high_risk_categories", "blocked_categories"))
    known_categories: str = DEFAULT_KNOWN
    reclassification_interval_hours: int = Field(
        24, ge=0, le=8760, validation_alias=AliasChoices("reclassification_interval_hours", "recheck_interval_hours"))
    unknown_category_behaviour: Literal["publish", "exclude"] = "publish"
    # Panorama categorises specific URLs; it cannot vouch for every subdomain a wildcard covers.
    #   exclude         - wildcard entries are never published (conservative; default)
    #   apex-classification - classify the base domain only and publish if it is clean. This is NOT
    #                     evidence about subdomains and is flagged as such wherever it is shown.
    wildcard_classification_policy: Literal["exclude", "apex-classification"] = "exclude"

    # ------------------------------------------------------------------ edl
    edl_name: str = "default"
    edl_description: str = Field("", max_length=300)
    # Optional extra path serving the primary list (the built-in /edl/<name> always works).
    edl_endpoint: str = Field("", max_length=200)
    edl_max_entries: int = Field(100000, ge=0, le=10_000_000)  # 0 = unlimited
    edl_publishing_enabled: bool = True
    edl_empty_behaviour: Literal["publish-empty", "keep-previous", "return-error"] = "publish-empty"
    # Optional HTTP basic auth on the feed (PAN-OS can send these).
    edl_user: str = Field("", max_length=128)
    edl_password: str = ""

    # ------------------------------------------------------------------ processing
    background_processing_enabled: bool = True
    processing_interval_seconds: int = Field(60, ge=5, le=86400)
    max_batch_size: int = Field(500, ge=1, le=10000)
    # Palo Alto Networks recommends no more than 5 concurrent XML API requests to limit management-plane load.
    max_concurrent_requests: int = Field(
        MAX_PANORAMA_CONCURRENCY, ge=1, le=MAX_PANORAMA_CONCURRENCY,
        validation_alias=AliasChoices("max_concurrent_requests", "lookup_workers"))
    http_request_timeout: float = Field(30.0, ge=1, le=300)
    retry_attempts: int = Field(2, ge=0, le=10)
    retry_delay_seconds: int = Field(10, ge=0, le=3600)

    # ------------------------------------------------------------------ security / api
    host_api_auth_enabled: bool = True
    host_ip_restrictions_enabled: bool = True
    host_token_expiry_days: int = Field(365, ge=0, le=3650)  # 0 = tokens never expire by default
    max_submission_size: int = Field(1000, ge=1, le=100000)
    rate_limit_requests: int = Field(120, ge=0, le=1_000_000)  # 0 = unlimited
    rate_limit_interval_seconds: int = Field(60, ge=1, le=86400)
    audit_api_submissions: bool = True

    # ------------------------------------------------------------------ validators
    @field_validator("app_timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise ValueError(f"unknown timezone {v!r} (use an IANA name such as Australia/Brisbane)") from None
        return v

    @field_validator("edl_name")
    @classmethod
    def _edl_name(cls, v: str) -> str:
        if not _LIST_RE.match(v):
            raise ValueError("must be 1-64 characters: letters, digits, '_' or '-'")
        return v

    @field_validator("edl_endpoint")
    @classmethod
    def _endpoint(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return ""
        if not _ENDPOINT_RE.match(v) or "//" in v or ".." in v:
            raise ValueError("must be a path such as /feeds/blocklist.txt (letters, digits, . _ ~ - /)")
        v = v.rstrip("/")
        if not v:
            raise ValueError("the root path cannot be used")
        return v

    @field_validator("high_risk_categories", "known_categories")
    @classmethod
    def _categories(cls, v: str) -> str:
        return _normalize_categories(v)

    @field_validator("panorama_host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if v and not re.match(r"^[A-Za-z0-9.:_\-\[\]]+$", v):
            raise ValueError("enter a hostname or IP address only (no scheme, port or path)")
        return v

    @model_validator(mode="after")
    def _risk_subset(self):
        unknown = self.high_risk_set - self.known_set
        if unknown:
            raise ValueError(
                f"high-risk categories not in the available category list: {', '.join(sorted(unknown))}. "
                "Add them to the available categories first.")
        return self

    @property
    def high_risk_set(self) -> set[str]:
        return {c for c in self.high_risk_categories.split(",") if c}

    @property
    def known_set(self) -> set[str]:
        return {c for c in self.known_categories.split(",") if c}


# Settings that may be supplied as Docker secrets / files: NAME_FILE=/run/secrets/...
_FILE_SECRETS = ("api_key", "secret_key", "encryption_key", "encryption_key_previous", "admin_password", "database_url",
                 "panorama_api_key", "edl_password")


def _file_kwargs() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _FILE_SECRETS:
        path = os.environ.get(f"{name.upper()}_FILE")
        if path:
            out[name] = Path(path).read_text().strip()
    return out


def _clamped_env() -> dict[str, object]:
    """An old MAX_CONCURRENT_REQUESTS / LOOKUP_WORKERS above the supported maximum (it used to allow
    64) is clamped to 5 with a warning instead of stopping the app from starting."""
    out: dict[str, object] = {}
    for name in ("MAX_CONCURRENT_REQUESTS", "LOOKUP_WORKERS"):
        raw = os.environ.get(name)
        if raw and raw.strip().isdigit() and int(raw) > MAX_PANORAMA_CONCURRENCY:
            logging.getLogger("edl").warning("%s=%s exceeds the maximum of %d Panorama requests; using %d",
                                             name, raw, MAX_PANORAMA_CONCURRENCY, MAX_PANORAMA_CONCURRENCY)
            out["max_concurrent_requests"] = MAX_PANORAMA_CONCURRENCY
    return out


def settings_from(values: Mapping[str, object] | None = None) -> Settings:
    """Build Settings from env + file secrets, with explicit values taking precedence."""
    return Settings(**{**_file_kwargs(), **_clamped_env(), **(values or {})})


@lru_cache
def get_bootstrap() -> Settings:
    """Environment-only settings, available before the database is."""
    return settings_from()


_effective: Settings | None = None


def get_settings() -> Settings:
    """Bootstrap values plus the database-backed settings (once loaded)."""
    return _effective or get_bootstrap()


def set_effective(settings: Settings | None) -> None:
    global _effective
    _effective = settings
