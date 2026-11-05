"""Database schema management.

The project does not use Alembic. Instead, startup runs this additive, idempotent step:
create any missing tables, then add any missing columns listed below. It never drops or
rewrites existing data, so it is safe to run on every start and on upgrade.
"""
import logging

from sqlalchemy import Boolean, DateTime, Text, inspect, text
from sqlalchemy.engine import Engine

from .db import Base

log = logging.getLogger("edl")

# (table, column, SQLAlchemy type) added after the first release of each table
ADDITIVE_COLUMNS = [
    ("allowed_hosts", "expires_at", DateTime(timezone=True)),           # v2.0.0
    ("edl_snapshots", "retained", Boolean()),                           # v2.1.0
    ("edl_snapshots", "note", Text()),                                  # v2.1.0
]


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
    for line in applied:
        log.info("schema: %s", line)
    return applied
