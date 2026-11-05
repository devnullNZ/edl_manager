from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import get_bootstrap

_settings = get_bootstrap()
_connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
engine = create_engine(_settings.database_url, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Entry(Base):
    """One URL/domain entry. `value` is the normalised form, so the unique
    constraint is what de-duplicates."""

    __tablename__ = "entries"
    __table_args__ = (UniqueConstraint("list_name", "value", name="uq_list_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    list_name: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    # active     -> classified acceptable; published (subject to shadow filtering)
    # blocked    -> high-risk (or excluded unknown) category; never published
    # pending    -> classification failed under fail-closed; not published until it succeeds
    # unverified -> classification failed under fail-open; published, re-checked in background
    status: Mapped[str] = mapped_column(String(16), index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # time of the last classification attempt (successful or not)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CategoryCache(Base):
    """Raw Panorama lookup output, cached per lookup target. Evaluated against the
    *current* high-risk set on read, so category changes apply immediately."""

    __tablename__ = "category_cache"

    target: Mapped[str] = mapped_column(String(2048), primary_key=True)
    raw: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    """Settings (and a little internal state under "state:" keys). Secret values are
    stored Fernet-encrypted with an "enc:" prefix."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AllowedHost(Base):
    """A client allowed to POST entries: it presents this host's token and (when IP
    restrictions are enabled) connects from one of its addresses."""

    __tablename__ = "allowed_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    addresses: Mapped[str] = mapped_column(Text)  # comma separated IPs / CIDRs
    lists: Mapped[str] = mapped_column(Text, default="*")  # "*" or comma separated list names
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 hex
    token_prefix: Mapped[str] = mapped_column(String(12))  # for identification only
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EdlSnapshot(Base):
    """The last successfully generated feed for a list. The feed is served from this, so
    a failed processing run never removes or corrupts what firewalls already fetch."""

    __tablename__ = "edl_snapshots"

    list_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    body: Mapped[str] = mapped_column(Text)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[int] = mapped_column(Integer, default=0)  # eligible entries cut by the max
    etag: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # keep-previous: the list being served is the previous one, not what the database now justifies
    retained: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # admin | api
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
