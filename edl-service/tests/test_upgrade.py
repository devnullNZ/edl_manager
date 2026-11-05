"""Upgrading a v2.0.0 database: additive, non-destructive."""
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import migrations, service, settings_store
from app import db as dbmod
from app.config import get_settings
from app.db import AppSetting, EdlSnapshot, Entry

V200_SNAPSHOT = """CREATE TABLE edl_snapshots (
  list_name VARCHAR(64) PRIMARY KEY, body TEXT NOT NULL, entry_count INTEGER, truncated INTEGER,
  etag VARCHAR(64) NOT NULL, generated_at DATETIME)"""


def v200_engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with eng.begin() as c:
        c.execute(text(V200_SNAPSHOT))
        c.execute(text("INSERT INTO edl_snapshots VALUES ('default','old.example.com\n',1,0,'etag1','2026-01-01 00:00:00')"))
    return eng


def test_migration_adds_columns_and_keeps_rows():
    eng = v200_engine()
    applied = migrations.run_migrations(eng)
    cols = {c["name"] for c in inspect(eng).get_columns("edl_snapshots")}
    assert {"retained", "note"} <= cols
    assert "added column edl_snapshots.retained" in applied and "added column edl_snapshots.note" in applied
    with eng.connect() as c:
        row = c.execute(text("SELECT body, entry_count, etag, retained, note FROM edl_snapshots")).one()
    assert tuple(row) == ("old.example.com\n", 1, "etag1", None, None)
    assert migrations.run_migrations(eng) == []                      # idempotent


def test_full_upgrade_preserves_entries_and_settings(client):
    """Start from a populated database as v2.0.0 left it: settings present, no wildcard policy,
    a stored max_concurrent_requests of 8, a legacy '*.com' entry, and an old-format snapshot."""
    with client.factory() as s:
        s.add_all([Entry(list_name="default", value="keep.example.com", status="active"),
                   Entry(list_name="default", value="*.example.org", status="active"),
                   Entry(list_name="default", value="*.com", status="active")])
        s.get(AppSetting, "max_concurrent_requests").value = "8"
        s.get(AppSetting, "app_name").value = "Customised"
        s.delete(s.get(AppSetting, "wildcard_classification_policy"))
        s.commit()

    client.main.init_app(client.engine, client.factory)

    s = get_settings()
    assert s.app_name == "Customised"                                 # existing values untouched
    assert s.max_concurrent_requests == 5                              # clamped
    assert s.wildcard_classification_policy == "exclude"               # new setting seeded with its default
    with client.factory() as db:
        rows = {e.value: (e.status, e.detail) for e in db.query(Entry)}
        assert set(rows) == {"keep.example.com", "*.example.org", "*.com"}      # nothing deleted
        assert rows["keep.example.com"][0] == "active"
        assert rows["*.example.org"][0] == "blocked" and "wildcard" in rows["*.example.org"][1]
        assert rows["*.com"][0] == "blocked" and "public suffix" in rows["*.com"][1]
        assert db.get(EdlSnapshot, "default").body == "keep.example.com\n"
    assert client.get("/edl/default").text == "keep.example.com\n"


def test_upgrade_is_idempotent(client):
    client.main.init_app(client.engine, client.factory)
    before = settings_store.current_values()
    client.main.init_app(client.engine, client.factory)
    assert settings_store.current_values() == before
