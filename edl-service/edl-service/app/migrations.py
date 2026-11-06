"""Database schema management.

The project does not use Alembic. Instead, startup runs this additive, idempotent step:
create any missing tables, then add any missing columns listed below. It never drops or
rewrites existing data, so it is safe to run on every start and on upgrade.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import Boolean, bindparam, DateTime, String, Text, inspect, text
from sqlalchemy.engine import Engine

from .db import Base

log = logging.getLogger("edl")

# (table, column, SQLAlchemy type) added after the first release of each table
ADDITIVE_COLUMNS = [
    ("allowed_hosts", "expires_at", DateTime(timezone=True)),           # v2.0.0
    ("edl_snapshots", "retained", Boolean()),                           # v2.1.0
    ("edl_snapshots", "note", Text()),                                  # v2.1.0
    ("entries", "enabled", Boolean()),                                  # v2.2.0
    ("entries", "suppressed_by", String(2048)),                         # v2.2.0
    ("entries", "class_method", String(24)),                            # v2.2.0
    ("entries", "class_target", String(2048)),                          # v2.2.0
    ("entries", "class_result", String(16)),                            # v2.2.0
    ("entries", "class_categories", Text()),                            # v2.2.0
    ("entries", "class_status", String(16)),                            # v2.2.0
]

STATUS_RANK = {"blocked": 0, "pending": 1, "unverified": 2, "active": 3}  # lower = more restrictive


def run_migrations(engine: Engine) -> list[str]:
    """Bring the schema up to date. Returns a description of what changed."""
    applied: list[str] = []
    before = set(inspect(engine).get_table_names())
    Base.metadata.create_all(engine)
    applied += [f"created table {t}" for t in sorted(set(inspect(engine).get_table_names()) - before)]

    insp = inspect(engine)
    for table, column, coltype in ADDITIVE_COLUMNS:
        if table not in insp.get_table_names():
            continue
        if column in {c["name"] for c in insp.get_columns(table)}:
            continue
        ddl = coltype.compile(dialect=engine.dialect)
        with engine.begin() as conn:
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'))
        applied.append(f"added column {table}.{column}")
    applied += migrate_data(engine)
    for line in applied:
        log.info("schema: %s", line)
    return applied


def migrate_data(engine: Engine) -> list[str]:
    """One-off data upgrades, each idempotent (it finds only rows that still need the change), run in a
    single transaction: either the whole upgrade is applied or none of it.

    1. entries.enabled backfilled to true.
    2. Domain roots get the canonical trailing slash (`example.com` -> `example.com/`). Path-specific
       entries are never rewritten. If a root and its slashed twin both exist in one list (not expected
       from v2.1.1 data) they are merged: the more restrictive status wins, ownership is combined.
    3. Entries stored before ownership existed get an `api` owner derived from their source string.
    Audit history and cached classifications are not touched; suppression and the feed are recomputed
    by the caller (init_app) afterwards."""
    done: list[str] = []
    with engine.begin() as conn:
        if "entries" not in inspect(conn).get_table_names():
            return done
        n = conn.execute(text("UPDATE entries SET enabled = :t WHERE enabled IS NULL"), {"t": True}).rowcount or 0
        if n:
            done.append(f"entries.enabled backfilled for {n} row(s)")

        pairs = conn.execute(text(
            "SELECT a.id, b.id FROM entries a JOIN entries b ON b.list_name = a.list_name "
            "AND b.value = a.value || '/' WHERE a.value NOT LIKE '%/%'")).fetchall()
        for loser_id, keeper_id in pairs:
            loser = conn.execute(text("SELECT status, detail FROM entries WHERE id = :i"), {"i": loser_id}).one()
            keeper = conn.execute(text("SELECT status, detail FROM entries WHERE id = :i"), {"i": keeper_id}).one()
            if STATUS_RANK.get(loser[0], 0) < STATUS_RANK.get(keeper[0], 0):
                conn.execute(text("UPDATE entries SET status = :s, detail = :d WHERE id = :i"),
                             {"s": loser[0], "d": loser[1], "i": keeper_id})
            conn.execute(text(
                "UPDATE entry_sources SET entry_id = :k WHERE entry_id = :l AND NOT EXISTS ("
                "SELECT 1 FROM entry_sources x WHERE x.entry_id = :k AND x.host = entry_sources.host "
                "AND x.source_id = entry_sources.source_id)"), {"k": keeper_id, "l": loser_id})
            conn.execute(text("DELETE FROM entry_sources WHERE entry_id = :l"), {"l": loser_id})
            conn.execute(text("DELETE FROM entries WHERE id = :l"), {"l": loser_id})
        if pairs:
            done.append(f"merged {len(pairs)} duplicate domain-root entr{'y' if len(pairs) == 1 else 'ies'}")
        n = conn.execute(text("UPDATE entries SET value = value || '/' WHERE value NOT LIKE '%/%'")).rowcount or 0
        if n:
            done.append(f"normalised {n} domain-root entr{'y' if n == 1 else 'ies'} to the trailing-slash form")

        orphans = conn.execute(text(
            "SELECT id, list_name, source, created_at FROM entries WHERE id NOT IN "
            "(SELECT entry_id FROM entry_sources)")).fetchall()
        if orphans:
            rows = []
            for i, list_name, source, created in orphans:
                host, _, note = (source or "legacy").partition(":")
                rows.append({"e": i, "l": list_name, "h": (host or "legacy")[:64], "s": note[:100], "c": created})
            for k in range(0, len(rows), 1000):
                conn.execute(text(
                    "INSERT INTO entry_sources (entry_id, list_name, kind, host, source_id, created_at) "
                    "VALUES (:e, :l, 'api', :h, :s, :c)"), rows[k:k + 1000])
            done.append(f"recorded an owner for {len(rows)} existing entr{'y' if len(rows) == 1 else 'ies'}")
        if done:
            conn.execute(text(
                "INSERT INTO audit_log (ts, kind, actor, action, target, detail) "
                "VALUES (:ts, 'admin', 'system', 'schema-upgrade', 'entries', :d)"
            ).bindparams(bindparam("ts", type_=DateTime(timezone=True))),
                {"ts": datetime.now(timezone.utc), "d": "; ".join(done)[:4000]})
    return done
