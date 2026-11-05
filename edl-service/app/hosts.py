"""Per-host authentication for the POST (populate) endpoint.

A request is accepted only when:
  * it carries a bearer token belonging to an enabled, unexpired host, and
  * (while IP restrictions are enabled) its source IP is inside that host's addresses, and
  * the host is allowed to write to the requested list.
Tokens are stored only as SHA-256 hashes (they are random, so no salt/stretching is needed)
and are shown once, when created or regenerated.
"""
import hashlib
import ipaddress
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .db import AllowedHost, utcnow

log = logging.getLogger("edl")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
LIST_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class HostAuthError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return "edl_" + secrets.token_urlsafe(32)


def parse_addresses(text: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma/space/newline separated list of IPs and CIDRs. Raises ValueError."""
    parts = [p for p in re.split(r"[,\s]+", text.strip()) if p]
    if not parts:
        raise ValueError("at least one IP address or CIDR is required")
    nets = []
    for p in parts:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            raise ValueError(f"not an IP address or CIDR: {p!r}") from None
        if net.prefixlen == 0:
            raise ValueError(f"{p!r} would allow every address; list specific hosts or networks")
        nets.append(net)
    return nets


def normalize_addresses(text: str) -> str:
    return ", ".join(str(n) for n in parse_addresses(text))


def normalize_lists(text: str) -> str:
    parts = [p for p in re.split(r"[,\s]+", text.strip()) if p]
    if not parts or "*" in parts:
        return "*"
    for p in parts:
        if not LIST_RE.match(p):
            raise ValueError(f"invalid list name: {p!r}")
    return ", ".join(dict.fromkeys(parts))


def validate_name(name: str) -> str:
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("name must be 1-64 characters of letters, digits, '.', '_' or '-'")
    return name


def parse_expiry(text: str) -> datetime | None:
    """'' -> the configured default validity; 'never' -> no expiry; YYYY-MM-DD -> end of that day (UTC)."""
    text = (text or "").strip().lower()
    if not text:
        days = get_settings().host_token_expiry_days
        return utcnow() + timedelta(days=days) if days else None
    if text == "never":
        return None
    try:
        day = datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise ValueError("expiry must be a date (YYYY-MM-DD) or 'never'") from None
    return day.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_expired(host: AllowedHost) -> bool:
    exp = _aware(host.expires_at)
    return exp is not None and exp <= utcnow()


def create_host(db: Session, name: str, addresses: str, lists: str, expiry: str = "") -> tuple[AllowedHost, str]:
    """Create a host and return it with its plaintext token (shown once). Raises ValueError."""
    token = new_token()
    host = AllowedHost(name=validate_name(name), addresses=normalize_addresses(addresses),
                       lists=normalize_lists(lists), enabled=True, expires_at=parse_expiry(expiry),
                       token_hash=hash_token(token), token_prefix=token[:8])
    db.add(host)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ValueError(f"a host named {host.name!r} already exists") from None
    return host, token


def regenerate_token(db: Session, host: AllowedHost) -> str:
    """Issue a new token; the validity period restarts from the configured default."""
    token = new_token()
    host.token_hash, host.token_prefix = hash_token(token), token[:8]
    host.expires_at = parse_expiry("")
    db.commit()
    return token


def update_host(db: Session, host: AllowedHost, name: str, addresses: str, lists: str, expiry: str = "") -> None:
    host.name = validate_name(name)
    host.addresses = normalize_addresses(addresses)
    host.lists = normalize_lists(lists)
    if expiry.strip():  # blank leaves the current expiry unchanged
        host.expires_at = parse_expiry(expiry)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ValueError(f"a host named {name!r} already exists") from None


def _client_ip(ip_str: str | None):
    try:
        ip = ipaddress.ip_address(ip_str or "")
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def authenticate(db: Session, token: str | None, ip_str: str | None, list_name: str, *,
                 ip_restrictions: bool = True) -> AllowedHost:
    if not token:
        raise HostAuthError(401, "missing bearer token")
    host = db.scalar(select(AllowedHost).where(AllowedHost.token_hash == hash_token(token)))
    if host is None or not host.enabled:
        log.warning("rejected POST from %s: unknown or disabled token", ip_str)
        raise HostAuthError(401, "invalid token")
    if is_expired(host):
        log.warning("rejected POST for host %s: token expired", host.name)
        raise HostAuthError(401, "token expired")

    ip = _client_ip(ip_str)
    if ip_restrictions and (ip is None or not any(ip in net for net in parse_addresses(host.addresses))):
        log.warning("rejected POST for host %s: source %s not allowed", host.name, ip_str)
        raise HostAuthError(403, "source address not permitted for this host")

    allowed = {p.strip() for p in host.lists.split(",")}
    if "*" not in allowed and list_name not in allowed:
        log.warning("rejected POST for host %s: list %s not permitted", host.name, list_name)
        raise HostAuthError(403, f"host is not permitted to write to list {list_name!r}")

    host.last_used_at, host.last_ip = utcnow(), str(ip) if ip else ip_str
    db.commit()
    return host
