"""Administrative and API audit log. Entries never contain secret values: callers pass
redacted change descriptions (see settings_store.redacted_changes)."""
import logging
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import AuditLog, utcnow

log = logging.getLogger("edl")


def record(db: Session, *, actor: str, action: str, target: str = "", detail: str = "",
           ip: str | None = None, kind: str = "admin") -> bool:
    """Write an audit record if auditing is enabled for this kind. Never raises."""
    s = get_settings()
    if kind == "admin" and not s.audit_logging_enabled:
        return False
    if kind == "api" and not s.audit_api_submissions:
        return False
    try:
        db.add(AuditLog(kind=kind, actor=actor[:128], action=action[:64], target=target[:256],
                        detail=detail[:4000], ip=ip))
        db.commit()
        return True
    except Exception:
        db.rollback()
        log.exception("could not write audit record")
        return False


def recent(db: Session, *, kind: str | None = None, limit: int = 50, offset: int = 0):
    q = select(AuditLog)
    if kind:
        q = q.where(AuditLog.kind == kind)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = list(db.scalars(q.order_by(AuditLog.id.desc()).limit(limit).offset(offset)))
    return total, rows


def purge(db: Session) -> int:
    days = get_settings().audit_retention_days
    if days <= 0:
        return 0
    res = db.execute(delete(AuditLog).where(AuditLog.ts < utcnow() - timedelta(days=days)))
    db.commit()
    return res.rowcount or 0
