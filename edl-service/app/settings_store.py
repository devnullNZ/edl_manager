"""Database-backed settings: schema (sections/fields), seeding, validation, encryption.

* The database is authoritative. On first start missing settings are *seeded* (from the
  environment if provided, else defaults); existing values are never overwritten.
* Secret settings are encrypted at rest (Fernet; key derived from ENCRYPTION_KEY) and are
  never returned by any API or rendered in any page.
* Changes go through plan_updates() (validate + diff + detect disruptive changes) and
  apply_plan() (persist + reload). Side effects of a change live in runtime.py.
"""
import base64
import hashlib
import json
import logging
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import MAX_PANORAMA_CONCURRENCY, Settings, get_bootstrap, get_settings, set_effective, settings_from
from .db import AppSetting

log = logging.getLogger("edl")
MASK = "********"

# Set by main: returns an error message if an EDL endpoint path clashes with an existing route.
ROUTE_CHECK: Callable[[str], str | None] | None = None


@dataclass(frozen=True)
class Field:
    key: str
    label: str
    kind: str  # bool | int | float | str | text | choice | secret | multiselect | list
    help: str = ""
    choices: tuple[str, ...] = ()
    unit: str = ""


@dataclass(frozen=True)
class Section:
    id: str
    label: str
    description: str
    fields: tuple[Field, ...] = field(default_factory=tuple)


SECTIONS: tuple[Section, ...] = (
    Section("general", "General", "Application identity, logging and audit.", (
        Field("app_name", "Application name", "str", "Shown in the page header and titles."),
        Field("app_description", "Application description", "str", "Short description shown on the sign-in page."),
        Field("app_timezone", "Timezone", "str",
              "IANA timezone (e.g. Australia/Brisbane) used for timestamps in the admin pages and in logs."),
        Field("log_level", "Log level", "choice", "Verbosity of application logs.",
              choices=("DEBUG", "INFO", "WARNING", "ERROR")),
        Field("audit_logging_enabled", "Audit administrative actions", "bool",
              "Record settings changes, host changes and sign-ins in the audit log."),
        Field("audit_retention_days", "Audit log retention", "int",
              "Older audit records are deleted automatically. 0 keeps them forever.", unit="days"),
    )),
    Section("panorama", "Panorama Integration", "How the application reaches Panorama.", (
        Field("panorama_mode", "Mode", "choice",
              "live queries Panorama. mock simulates categories for development: a host label like "
              "cat-malware.example.com is classified as malware.", choices=("live", "mock")),
        Field("panorama_host", "Hostname / IP", "str", "Panorama management address (no scheme or port)."),
        Field("panorama_port", "Port", "int", "HTTPS port of the Panorama XML API (default 443)."),
        Field("panorama_api_key", "API key", "secret",
              "Panorama XML API key. Stored encrypted and never shown again; enter a new value to replace it."),
        Field("panorama_verify_tls", "Verify HTTPS certificate", "bool",
              "Turn off only for lab systems with self-signed certificates."),
        Field("panorama_connect_timeout", "Connection timeout", "float",
              "Seconds to wait when connecting to Panorama.", unit="seconds"),
        Field("panorama_retry_count", "API retry count", "int",
              "Extra attempts for a request that fails on a network error or HTTP 5xx.", unit="retries"),
        Field("panorama_target", "Target firewall serial", "str",
              "Optional. Proxy lookups through this managed firewall instead of Panorama itself."),
        Field("panorama_url_cmd", "URL lookup command", "text",
              "XML op command; {url} is replaced with the URL. The default works on many PAN-OS versions; "
              "use Test connection and a classification test to confirm it on yours."),
        Field("mock_categories_file", "Mock rules file", "str",
              "Mock mode only. Path to a JSON file of {domain: category} rules, re-read when it changes."),
    )),
    Section("classification", "URL Classification", "Which URLs are kept out of the published list.", (
        Field("classification_enabled", "Enable Panorama classification", "bool",
              "When off, no Panorama queries are made and every valid URL is published."),
        Field("classification_cache_ttl_hours", "Classification cache TTL", "int",
              "How long a Panorama answer is reused when the same URL is submitted again.", unit="hours"),
        Field("classification_failure_behaviour", "Failure behaviour", "choice",
              "If Panorama cannot be queried: fail-closed holds the entry back (pending) until it can be "
              "checked; fail-open publishes it (unverified) and re-checks later.",
              choices=("fail-closed", "fail-open")),
        Field("known_categories", "Available categories", "list",
              "Categories offered in the selector below, one per line or comma separated. Not every "
              "Panorama deployment has every category, so edit this to match yours."),
        Field("high_risk_categories", "High-risk categories", "multiselect",
              "URLs in any selected category are never published."),
        Field("reclassification_interval_hours", "Reclassification interval", "int",
              "How often stored entries are re-checked against Panorama (needs background processing). "
              "0 disables scheduled reclassification.", unit="hours"),
        Field("unknown_category_behaviour", "Unknown category behaviour", "choice",
              "What to do with URLs Panorama reports as unknown (not yet categorised).",
              choices=("publish", "exclude")),
        Field("wildcard_classification_policy", "Wildcard entries (*.example.com)", "choice",
              "Panorama classifies individual URLs, not whole domains: the category of example.com says "
              "nothing reliable about a.example.com or any other subdomain. exclude (recommended) never "
              "publishes wildcard entries. apex-classification checks only the base domain and publishes the "
              "wildcard if that is clean, which does NOT prove the subdomains are safe.",
              choices=("exclude", "apex-classification")),
    )),
    Section("edl", "EDL Configuration", "What is published to the firewalls.", (
        Field("edl_publishing_enabled", "Enable EDL publishing", "bool",
              "When off, the feed returns HTTP 503 so firewalls keep the list they already have."),
        Field("edl_name", "EDL name", "str",
              "Name of the primary list. Its feed is always available at /edl/<name>."),
        Field("edl_description", "EDL description", "str", "Free-text description of the list."),
        Field("edl_endpoint", "Additional endpoint", "str",
              "Optional extra path that serves the primary list, e.g. /feeds/blocklist.txt. It may not clash "
              "with an existing route (/admin, /v1, /edl, /docs, /healthz ...). Leave empty for none."),
        Field("edl_max_entries", "Maximum entries", "int",
              "Upper bound on published entries; the oldest entries are kept. 0 means no limit.",
              unit="entries"),
        Field("edl_empty_behaviour", "Empty list behaviour", "choice",
              "When no valid entries remain: publish-empty serves an empty list; keep-previous keeps serving "
              "the last non-empty list; return-error answers HTTP 503.",
              choices=("publish-empty", "keep-previous", "return-error")),
        Field("edl_user", "Feed username", "str",
              "Optional HTTP basic auth for fetching the feed. Leave empty for none."),
        Field("edl_password", "Feed password", "secret",
              "Stored encrypted. Enter a new value to replace it."),
    )),
    Section("processing", "Processing and Performance", "The background engine and request limits.", (
        Field("background_processing_enabled", "Enable background processing", "bool",
              "Retries pending/unverified entries and runs scheduled reclassification."),
        Field("processing_interval_seconds", "Processing interval", "int",
              "How often the engine looks for pending entries.", unit="seconds"),
        Field("max_batch_size", "Maximum batch size", "int",
              "Most URLs handled in one processing batch.", unit="URLs"),
        Field("max_concurrent_requests", "Maximum concurrent requests", "int",
              "Parallel Panorama XML API requests, process-wide (API submissions, background processing and rechecks share this limit). Palo Alto Networks recommends at most 5, which is the enforced maximum.", unit="requests"),
        Field("http_request_timeout", "HTTP request timeout", "float",
              "Seconds to wait for a response from Panorama.", unit="seconds"),
        Field("retry_attempts", "Retry attempts", "int",
              "Extra rounds the engine makes for entries whose classification failed, within one run.",
              unit="retries"),
        Field("retry_delay_seconds", "Retry delay", "int", "Pause between retry rounds.", unit="seconds"),
    )),
    Section("security", "Security and API", "How hosts submit URLs. Individual hosts are on the Hosts page.", (
        Field("host_api_auth_enabled", "Require host authentication", "bool",
              "When off, anyone who can reach the API can submit URLs. Not recommended."),
        Field("host_ip_restrictions_enabled", "Enable IP restrictions", "bool",
              "Also require submissions to come from the host's configured addresses."),
        Field("host_token_expiry_days", "Default API key expiry", "int",
              "Validity of newly issued host tokens. 0 means they never expire.", unit="days"),
        Field("max_submission_size", "Maximum submission size", "int",
              "Most URLs accepted in one POST request.", unit="URLs"),
        Field("rate_limit_requests", "Rate limit", "int",
              "Most requests per host within the interval below. 0 disables the limit.", unit="requests"),
        Field("rate_limit_interval_seconds", "Rate limit interval", "int",
              "Length of the rate-limit window.", unit="seconds"),
        Field("audit_api_submissions", "Audit API submissions", "bool",
              "Record each host submission (host, address, list and result counts) in the audit log."),
    )),
)
SECTION_BY_ID = {s.id: s for s in SECTIONS}
EDITABLE: dict[str, Field] = {f.key: f for s in SECTIONS for f in s.fields}
SECTION_OF: dict[str, str] = {f.key: s.id for s in SECTIONS for f in s.fields}
SECRET_KEYS = {k for k, f in EDITABLE.items() if f.kind == "secret"}
# Cross-field validation (e.g. live mode needs a host and key) runs only when these are saved.
STRICT_SECTIONS = {"panorama", "classification"}


# --------------------------------------------------------------------------- #
# Encryption
# --------------------------------------------------------------------------- #
def _fernet(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


MIN_KEY_LENGTH = 16
KEY_HELP = ('Generate one with:  python -c "import secrets; print(secrets.token_urlsafe(48))"  '
            "and set it as ENCRYPTION_KEY (or ENCRYPTION_KEY_FILE). Keep a copy in your password manager: "
            "it must stay the same across restarts, or saved secrets become unreadable.")


class EncryptionConfigError(RuntimeError):
    """ENCRYPTION_KEY is missing or unusable. The message says how to fix it."""


def check_encryption_config() -> None:
    """Fail early, with an actionable message, if the encryption key is absent or weak."""
    key = get_bootstrap().encryption_key
    if not key:
        raise EncryptionConfigError("ENCRYPTION_KEY is not set. " + KEY_HELP)
    if len(key) < MIN_KEY_LENGTH:
        raise EncryptionConfigError(
            f"ENCRYPTION_KEY is too short ({len(key)} characters; at least {MIN_KEY_LENGTH} required). "
            "Do not simply change it: secrets already stored with the old key would become unreadable. "
            "To replace it, follow 'Encryption key rotation' in the README (ENCRYPTION_KEY_PREVIOUS). " + KEY_HELP)


def _key_ring() -> list[str]:
    """Keys tried, in order, when decrypting: current, previous (rotation window), then the
    SECRET_KEY-derived key used by v1 deployments. Only the first is ever used to encrypt."""
    b = get_bootstrap()
    return list(dict.fromkeys(k for k in (b.encryption_key, b.encryption_key_previous, b.secret_key) if k))


def _fernet(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def encrypt(value: str) -> str:
    check_encryption_config()
    return "enc:" + _fernet(get_bootstrap().encryption_key).encrypt(value.encode()).decode()


def decrypt(stored: str) -> tuple[str | None, int]:
    """Return (plaintext, index into the key ring that worked). 0 = ENCRYPTION_KEY (current);
    anything higher means the value is still under an older key and should be re-encrypted.
    (None, -1) if no key works. Never raises and never logs the value."""
    for i, secret in enumerate(_key_ring()):
        try:
            return _fernet(secret).decrypt(stored[4:].encode()).decode(), i
        except InvalidToken:
            continue
    return None, -1


# key -> "ok" | "previous-key" | "unreadable" for every stored, non-empty secret (refreshed by reload())
SECRET_STATUS: dict[str, str] = {}


def secret_problems() -> list[str]:
    return sorted(k for k, v in SECRET_STATUS.items() if v == "unreadable")


def secrets_awaiting_rotation() -> list[str]:
    return sorted(k for k, v in SECRET_STATUS.items() if v == "previous-key")


UNREADABLE_HELP = ("cannot be decrypted with ENCRYPTION_KEY (or ENCRYPTION_KEY_PREVIOUS). Restore the original "
                   "key, or - if it is lost - re-enter the secret on the Settings page. The stored value has "
                   "NOT been changed or removed.")


def _encode(key: str, value: str) -> str:
    return encrypt(value) if key in SECRET_KEYS and value else value


# --------------------------------------------------------------------------- #
# Conversion helpers
# --------------------------------------------------------------------------- #
def to_str(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(v) for v in value)
    return str(value)


def _defaults() -> Settings:
    return Settings.model_construct()


def current_values() -> dict[str, str]:
    s = get_settings()
    return {k: to_str(getattr(s, k)) for k in EDITABLE}


def choices_for(f: Field, s: Settings) -> list[str]:
    if f.kind == "multiselect":
        known = [c for c in s.known_categories.split(",") if c]
        return known + sorted(s.high_risk_set - set(known))
    return list(f.choices)


def form_values(s: Settings, submitted: Mapping[str, str] | None = None) -> dict[str, object]:
    """Values for rendering forms: bool -> bool, multiselect -> list, others -> str."""
    out: dict[str, object] = {}
    for k, f in EDITABLE.items():
        raw = (submitted or {}).get(k)
        raw = to_str(getattr(s, k)) if raw is None else raw
        if f.kind == "secret":
            out[k] = bool(getattr(s, k))  # only whether it is set
        elif f.kind == "bool":
            out[k] = raw == "true"
        elif f.kind == "multiselect":
            out[k] = [c for c in raw.split(",") if c]
        else:
            out[k] = raw
    return out


def display_value(f: Field, s: Settings) -> str:
    v = getattr(s, f.key)
    if f.kind == "secret":
        return "•••••••• (configured)" if v else "not set"
    if f.kind == "bool":
        return "Enabled" if v else "Disabled"
    if f.kind in ("multiselect", "list"):
        return ", ".join(c for c in str(v).split(",") if c) or "none"
    text = str(v)
    if not text:
        return "not set"
    return f"{text} {f.unit}".strip() if f.unit else text


def _api_value(f: Field, value):
    if f.kind in ("multiselect", "list"):
        return [c for c in str(value).split(",") if c]
    return value


_API_TYPES = {"bool": "boolean", "int": "integer", "float": "number", "str": "string", "text": "string",
              "choice": "string", "secret": "secret", "multiselect": "list", "list": "list"}


def describe(s: Settings | None = None, section: str | None = None) -> list[dict]:
    """API/overview description of settings. Secrets are never included, only whether set."""
    s = s or get_settings()
    d = _defaults()
    out = []
    for sec in SECTIONS:
        if section and sec.id != section:
            continue
        items = []
        for f in sec.fields:
            item = {"key": f.key, "label": f.label, "description": f.help, "type": _API_TYPES[f.kind],
                    "unit": f.unit or None}
            if f.kind == "secret":
                unreadable = SECRET_STATUS.get(f.key) == "unreadable"
                item.update(value=None, configured=bool(getattr(s, f.key)) or unreadable,
                            masked=MASK if (getattr(s, f.key) or unreadable) else None, default=None,
                            status="unreadable" if unreadable else "ok")
            else:
                item.update(value=_api_value(f, getattr(s, f.key)), default=_api_value(f, getattr(d, f.key)))
            if f.kind in ("choice", "multiselect"):
                item["choices"] = choices_for(f, s)
            items.append(item)
        out.append({"id": sec.id, "label": sec.label, "description": sec.description, "settings": items})
    return out


# --------------------------------------------------------------------------- #
# Load / reload / seed
# --------------------------------------------------------------------------- #
def load_overrides(db: Session) -> dict[str, str]:
    """All stored settings, decrypted. Unreadable secrets are skipped (logged by key only)."""
    out: dict[str, str] = {}
    status: dict[str, str] = {}
    for row in db.scalars(select(AppSetting)):
        if row.key not in EDITABLE:
            continue
        if row.value.startswith("enc:"):
            plain, idx = decrypt(row.value)
            if plain is None:
                log.error("secret setting %s %s", row.key, UNREADABLE_HELP)
                status[row.key] = "unreadable"
                out[row.key] = ""  # unusable, and the environment must not silently stand in for it
                continue
            status[row.key] = "ok" if idx == 0 else "previous-key"
            out[row.key] = plain
        else:
            out[row.key] = row.value
    SECRET_STATUS.clear()
    SECRET_STATUS.update(status)
    return out


def build_effective(values: Mapping[str, str], *, strict: bool = False, check_routes: bool = False) -> Settings:
    s = settings_from(values)  # explicit values beat the environment; raises ValidationError
    if strict and s.classification_enabled and s.panorama_mode == "live" \
            and not (s.panorama_host and s.panorama_api_key):
        raise ValueError("Classification in live mode needs a Panorama host and API key. Configure them, "
                         "switch to mock mode, or disable classification.")
    if check_routes and s.edl_endpoint and ROUTE_CHECK:
        problem = ROUTE_CHECK(s.edl_endpoint)
        if problem:
            raise ValueError(problem)
    return s


def reload(db: Session) -> Settings:
    """Rebuild and activate the effective settings. If stored values are invalid, fall back to the
    environment/defaults so the admin page stays reachable."""
    try:
        s = build_effective(load_overrides(db))
    except (ValidationError, ValueError) as exc:
        log.error("stored settings are invalid (%s); using defaults", _format_exc(exc))
        s = get_bootstrap()
    set_effective(s)
    return s


def seed_defaults(db: Session, use_env: bool = True) -> list[str]:
    """Insert settings that are missing. Never changes an existing value. Also re-encrypts any
    secret still encrypted with the legacy key. Returns the keys created."""
    base = settings_from() if use_env else _defaults()
    existing = {r.key: r for r in db.scalars(select(AppSetting))}
    created = []
    for key in EDITABLE:
        if key in existing:
            continue
        db.add(AppSetting(key=key, value=_encode(key, to_str(getattr(base, key)))))
        created.append(key)
    for key, row in existing.items():
        if key in SECRET_KEYS and row.value.startswith("enc:"):
            plain, idx = decrypt(row.value)
            if plain is not None and idx > 0:
                row.value = encrypt(plain)
                log.info("setting %s re-encrypted with the current ENCRYPTION_KEY", key)
    db.commit()
    if created:
        log.info("seeded %d setting(s)", len(created))
    return created


def reset_defaults(db: Session) -> None:
    """Remove every stored setting and re-seed built-in defaults (not the environment)."""
    db.execute(delete(AppSetting).where(AppSetting.key.in_(list(EDITABLE))))
    db.commit()
    seed_defaults(db, use_env=False)
    reload(db)


# --------------------------------------------------------------------------- #
# Small internal state (not user-editable), e.g. last connection test
# --------------------------------------------------------------------------- #
def get_state(db: Session, name: str) -> dict | None:
    row = db.get(AppSetting, f"state:{name}")
    try:
        return json.loads(row.value) if row else None
    except ValueError:
        return None


def set_state(db: Session, name: str, value: dict) -> None:
    row = db.get(AppSetting, f"state:{name}")
    text = json.dumps(value)
    if row:
        row.value = text
    else:
        db.add(AppSetting(key=f"state:{name}", value=text))
    db.commit()


# --------------------------------------------------------------------------- #
# Planning and applying changes
# --------------------------------------------------------------------------- #
@dataclass
class Change:
    key: str
    label: str
    old: str
    new: str
    secret: bool = False


@dataclass
class Plan:
    new_values: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    disruptive: list[str] = field(default_factory=list)


def _format_exc(exc: Exception) -> list[str]:
    if isinstance(exc, ValidationError):
        out = []
        for e in exc.errors():
            loc = e["loc"]
            key = loc[0] if loc else None
            msg = e["msg"].removeprefix("Value error, ")
            out.append(f"{EDITABLE[key].label}: {msg}" if key in EDITABLE else msg)
        return out
    return [str(exc)]


def updates_from_form(section: Section, form) -> tuple[dict[str, str], set[str]]:
    """Translate a submitted section form (a Starlette FormData) into updates for plan_updates."""
    updates: dict[str, str] = {}
    clear: set[str] = set()
    for f in section.fields:
        if f.kind == "bool":
            updates[f.key] = "true" if form.get(f.key) == "on" else "false"
        elif f.kind == "secret":
            if form.get(f.key):
                updates[f.key] = str(form.get(f.key))
            if form.get(f"{f.key}__clear") == "on":
                clear.add(f.key)
        elif f.kind == "multiselect":
            updates[f.key] = ",".join(str(v) for v in form.getlist(f.key))
        elif f.key in form:
            updates[f.key] = str(form.get(f.key)).strip()
    return updates, clear


def disruptive_reasons(old: Settings, new: Settings) -> list[str]:
    r = []
    if old.edl_publishing_enabled and not new.edl_publishing_enabled:
        r.append("EDL publishing will be switched off: firewalls will get HTTP 503 and keep their current list.")
    if old.edl_name != new.edl_name:
        r.append(f"The primary EDL name changes from '{old.edl_name}' to '{new.edl_name}'. Any additional "
                 "endpoint will serve the new list, so firewalls using it will receive different content.")
    if old.edl_endpoint != new.edl_endpoint:
        r.append("The additional EDL endpoint changes: firewalls fetching the old path will stop receiving the list.")
    if new.edl_max_entries and (not old.edl_max_entries or new.edl_max_entries < old.edl_max_entries):
        r.append(f"The maximum entry count drops to {new.edl_max_entries}: newer entries beyond it will be "
                 "removed from the published list.")
    if old.edl_empty_behaviour != new.edl_empty_behaviour and new.edl_empty_behaviour == "publish-empty":
        r.append("An empty result will now be published as an empty list, which removes all blocked entries "
                 "from firewalls.")
    if old.classification_enabled and not new.classification_enabled:
        r.append("Classification will be switched off: high-risk URLs will no longer be filtered out, and "
                 "currently excluded entries will be published.")
    if old.high_risk_set != new.high_risk_set:
        r.append("The high-risk category set changes: stored entries will be re-evaluated and some may be "
                 "added to or removed from the published list.")
    if old.classification_failure_behaviour != new.classification_failure_behaviour \
            and new.classification_failure_behaviour == "fail-open":
        r.append("Fail-open: URLs will be published even when Panorama cannot classify them.")
    if old.wildcard_classification_policy != new.wildcard_classification_policy:
        if new.wildcard_classification_policy == "exclude":
            r.append("Wildcard entries (*.example.com) will be removed from the published list: their "
                     "subdomains cannot be classified.")
        else:
            r.append("Wildcard entries will be published after only their base domain is classified. That "
                     "does NOT establish that the subdomains are safe.")
    if old.unknown_category_behaviour != new.unknown_category_behaviour:
        r.append("The handling of unknown-category URLs changes: stored entries may be added or removed.")
    if old.background_processing_enabled and not new.background_processing_enabled:
        r.append("Background processing will stop: pending entries stay unpublished until you run processing "
                 "manually, and scheduled reclassification stops.")
    if old.host_api_auth_enabled and not new.host_api_auth_enabled:
        r.append("Host authentication will be switched off: anyone who can reach the API can add URLs.")
    if old.host_ip_restrictions_enabled and not new.host_ip_restrictions_enabled:
        r.append("IP restrictions will be switched off: a host token will work from any address.")
    return r


def plan_updates(updates: Mapping[str, str], clear: Collection[str] = (), *, strict: bool = False) -> Plan:
    """Validate a set of updates against the current settings without saving anything."""
    plan = Plan()
    old = get_settings()
    cur = current_values()
    new = dict(cur)

    for key in clear:
        if key not in SECRET_KEYS:
            plan.errors.append(f"{key}: only secret settings can be cleared")
        else:
            new[key] = ""
    for key, value in updates.items():
        f = EDITABLE.get(key)
        if f is None:
            plan.errors.append(f"unknown setting: {key}")
        elif f.kind == "secret":
            if value:  # blank keeps the current secret
                new[key] = value
        else:
            new[key] = to_str(value)
    if plan.errors:
        return plan

    endpoint_changed = "edl_endpoint" in updates and new["edl_endpoint"].strip().rstrip("/") != cur["edl_endpoint"]
    try:
        candidate = build_effective(new, strict=strict, check_routes=endpoint_changed)
    except (ValidationError, ValueError) as exc:
        plan.errors = _format_exc(exc)
        return plan

    plan.new_values = {k: to_str(getattr(candidate, k)) for k in EDITABLE}  # normalised
    for key, f in EDITABLE.items():
        if plan.new_values[key] != cur[key]:
            secret = key in SECRET_KEYS
            plan.changes.append(Change(
                key, f.label,
                ("(configured)" if cur[key] else "(not set)") if secret else cur[key],
                ("(replaced)" if plan.new_values[key] else "(cleared)") if secret else plan.new_values[key],
                secret))
    plan.disruptive = disruptive_reasons(old, candidate)
    return plan


def apply_plan(db: Session, plan: Plan) -> set[str]:
    """Persist the changed settings and activate them. Returns the changed keys."""
    changed = {c.key for c in plan.changes}
    for key in changed:
        stored = _encode(key, plan.new_values[key])
        row = db.get(AppSetting, key)
        if row:
            row.value = stored
        else:
            db.add(AppSetting(key=key, value=stored))
    db.commit()
    reload(db)
    return changed


def redacted_changes(plan: Plan) -> str:
    """Human-readable change list for the audit log. Secret values are never included."""
    return "; ".join(f"{c.key}: {c.old} -> {c.new}" for c in plan.changes)


# --------------------------------------------------------------------------- #
# One-off, idempotent upgrade steps (run at startup, before settings are loaded)
# --------------------------------------------------------------------------- #
def upgrade_stored_settings(db: Session) -> list[str]:
    """Bring values saved by an earlier release in line with current limits. Never deletes a setting.
    Returns descriptions of what was adjusted."""
    done: list[str] = []
    row = db.get(AppSetting, "max_concurrent_requests")
    if row and row.value.strip().isdigit() and int(row.value) > MAX_PANORAMA_CONCURRENCY:
        done.append(f"max_concurrent_requests {row.value} -> {MAX_PANORAMA_CONCURRENCY} "
                    "(Palo Alto Networks recommends at most 5 concurrent XML API requests)")
        row.value = str(MAX_PANORAMA_CONCURRENCY)
    db.commit()
    return done
