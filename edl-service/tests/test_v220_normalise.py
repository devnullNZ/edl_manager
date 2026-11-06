"""v2.2.0: canonical trailing-slash form, and the upgrade/backfill of data stored by v2.1.1."""
import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.pool import StaticPool

from app import migrations
from app.db import AuditLog, Entry, EntrySource
from app.normalize import is_root, normalize, split_value
from conftest import KEY, apex_policy, feed, post


@pytest.mark.parametrize("raw,canonical", [
    ("example.com", "example.com/"),
    ("www.example.com", "www.example.com/"),
    ("https://example.com", "example.com/"),
    ("http://example.com", "example.com/"),
    ("*.example.com", "*.example.com/"),
    ("example.com/", "example.com/"),
    ("HTTPS://Example.COM:443", "example.com/"),
    ("example.com?x=1", "example.com/"),
    ("example.com/#frag", "example.com/"),
    ("example.com//", "example.com/"),
    ("https://*.Example.com/", "*.example.com/"),
])
def test_domain_roots_get_a_trailing_slash(raw, canonical):
    assert normalize(raw) == canonical
    assert is_root(canonical)


@pytest.mark.parametrize("raw,canonical", [
    ("example.com/login", "example.com/login"),
    ("example.com/login/", "example.com/login/"),
    ("https://example.com/a/b", "example.com/a/b"),
    ("https://example.com/a/b/", "example.com/a/b/"),
    ("example.com/a/b///", "example.com/a/b/"),
    ("example.com/login?next=/x", "example.com/login"),
    ("example.com/login/?next=/x#top", "example.com/login/"),
    ("*.example.com/login", "*.example.com/login"),
])
def test_path_entries_are_not_given_a_slash_and_keep_theirs(raw, canonical):
    assert normalize(raw) == canonical
    assert not is_root(canonical)


def test_path_with_and_without_trailing_slash_are_different_entries():
    assert normalize("example.com/login") != normalize("example.com/login/")


def test_normalisation_is_idempotent():
    for raw in ("example.com", "https://x.example.com/p/", "*.example.com", "example.com/a"):
        once = normalize(raw)
        assert normalize(once) == once


def test_split_value_root_has_empty_path():
    assert split_value("example.com/") == ("example.com", "")
    assert split_value("example.com/login/") == ("example.com", "login/")


def test_duplicate_canonical_roots_are_deduplicated(client):
    out = post(client, ["example.com", "https://example.com", "http://example.com/", "EXAMPLE.com"])
    assert out["summary"] == {"added": 1, "duplicate": 3}
    assert {r["value"] for r in out["results"]} == {"example.com/"}
    assert feed(client).text == "example.com/\n"
    with client.factory() as s:
        assert s.query(Entry).count() == 1


def test_path_variants_are_stored_separately(client):
    out = post(client, ["example.com/login", "example.com/login/", "example.com/login?x=1"])
    assert out["summary"] == {"added": 2, "duplicate": 1}
    assert feed(client).text.splitlines() == ["example.com/login", "example.com/login/"]


def test_panorama_receives_the_host_not_the_slashed_value(client):
    post(client, ["https://example.com", "example.com/login/"])
    assert sorted(client.fake.calls) == ["example.com", "example.com/login/"]


def test_normalisation_happens_before_validation_and_delete(client):
    post(client, ["example.com"])
    r = client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["https://EXAMPLE.com/"]}, headers=KEY)
    assert r.json() == {"deleted": 1} and feed(client).text == ""


def test_path_trailing_slash_response_from_panorama_is_understood(client):
    out = post(client, ["bad.example.net/x/"])
    assert out["results"][0]["status"] == "blocked"          # the echoed URL may end in '/'


def test_normalised_before_shadow_analysis(client):
    apex_policy(client)
    post(client, ["*.example.com", "http://www.example.com"])
    assert feed(client).text == "*.example.com/\n"


# ------------------------------------------------------------------ upgrade from a v2.1.1 database
V211_DDL = [
    """CREATE TABLE entries (id INTEGER PRIMARY KEY, list_name VARCHAR(64) NOT NULL, value VARCHAR(2048) NOT NULL,
       status VARCHAR(16) NOT NULL, detail TEXT, source VARCHAR(128), created_at DATETIME NOT NULL, checked_at DATETIME,
       CONSTRAINT uq_list_value UNIQUE (list_name, value))""",
    """CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts DATETIME NOT NULL, kind VARCHAR(16) NOT NULL,
       actor VARCHAR(128) NOT NULL, action VARCHAR(64) NOT NULL, target VARCHAR(256) NOT NULL, detail TEXT NOT NULL,
       ip VARCHAR(64))""",
]


def v211_engine():
    eng = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    with eng.begin() as c:
        for ddl in V211_DDL:
            c.execute(text(ddl))
        rows = [
            ("default", "example.com", "active", "fine", "ticketing:feed", "2026-01-01 00:00:00"),
            ("default", "*.example.org", "active", "wildcard: only the base domain was classified", "ticketing", "2026-01-02 00:00:00"),
            ("default", "www.example.org", "active", None, "ticketing", "2026-01-03 00:00:00"),
            ("default", "example.net/login", "active", None, None, "2026-01-04 00:00:00"),
            ("default", "bad.example.net", "blocked", "malware", "ticketing", "2026-01-05 00:00:00"),
            ("other", "example.com", "pending", "awaiting", "scanner:daily", "2026-01-06 00:00:00"),
        ]
        for lst, v, st, d, src, ts in rows:
            c.execute(text("INSERT INTO entries (list_name, value, status, detail, source, created_at) "
                           "VALUES (:l, :v, :s, :d, :src, :ts)"), dict(l=lst, v=v, s=st, d=d, src=src, ts=ts))
        c.execute(text("INSERT INTO audit_log (ts, kind, actor, action, target, detail) VALUES "
                       "('2026-01-01 00:00:00', 'api', 'host:ticketing', 'submit', 'default', 'earlier history')"))
    return eng


def test_data_migration_on_a_v211_schema():
    eng = v211_engine()
    applied = migrations.run_migrations(eng)
    cols = {c["name"] for c in inspect(eng).get_columns("entries")}
    assert {"enabled", "suppressed_by", "class_method", "class_target", "class_result", "class_categories",
            "class_status"} <= cols
    assert {"entry_sources", "sync_sources", "sync_runs"} <= set(inspect(eng).get_table_names())
    assert any("normalised 5 domain-root" in a for a in applied)
    with eng.connect() as c:
        rows = {(r[0], r[1]): r[2:] for r in c.execute(text("SELECT list_name, value, status, detail, enabled FROM entries"))}
    assert set(rows) == {("default", "example.com/"), ("default", "*.example.org/"), ("default", "www.example.org/"),
                         ("default", "example.net/login"), ("default", "bad.example.net/"), ("other", "example.com/")}
    assert rows[("default", "example.net/login")][0] == "active"             # path entries are NOT rewritten
    assert rows[("default", "bad.example.net/")] == ("blocked", "malware", 1)   # status and reason preserved
    assert rows[("other", "example.com/")][0] == "pending"
    with eng.connect() as c:
        own = {(r[0], r[1]): r[2:] for r in c.execute(text(
            "SELECT e.list_name, e.value, s.kind, s.host, s.source_id FROM entry_sources s JOIN entries e ON e.id = s.entry_id"))}
        assert own[("default", "example.com/")] == ("api", "ticketing", "feed")      # owner derived from the source string
        assert own[("default", "example.net/login")] == ("api", "legacy", "")        # no source recorded
        assert own[("other", "example.com/")] == ("api", "scanner", "daily")
        assert len(own) == 6
        audit = [r[0] for r in c.execute(text("SELECT detail FROM audit_log ORDER BY id"))]
    assert audit[0] == "earlier history" and "schema-upgrade" in [
        r[0] for r in eng.connect().execute(text("SELECT action FROM audit_log"))]
    assert migrations.run_migrations(eng) == []                  # idempotent: a second start changes nothing


def test_migration_merges_a_root_and_its_slashed_twin_safely():
    eng = v211_engine()
    migrations.run_migrations(eng)
    with eng.begin() as c:       # impossible from v2.1.1 data, but a collision must never lose or relax anything
        c.execute(text("INSERT INTO entries (list_name, value, status, created_at, enabled) "
                       "VALUES ('default', 'twin.com', 'blocked', '2026-02-01 00:00:00', 1)"))
        c.execute(text("INSERT INTO entries (list_name, value, status, created_at, enabled) "
                       "VALUES ('default', 'twin.com/', 'active', '2026-02-02 00:00:00', 1)"))
        a = c.execute(text("SELECT id FROM entries WHERE value = 'twin.com'")).scalar()
        b = c.execute(text("SELECT id FROM entries WHERE value = 'twin.com/'")).scalar()
        c.execute(text("INSERT INTO entry_sources (entry_id, list_name, kind, host, source_id, created_at) VALUES "
                       "(:a, 'default', 'api', 'h1', '', '2026-02-01 00:00:00'), (:b, 'default', 'api', 'h2', '', '2026-02-01 00:00:00')"),
                  {"a": a, "b": b})
    done = migrations.migrate_data(eng)
    assert any("merged 1 duplicate" in d for d in done)
    with eng.connect() as c:
        rows = c.execute(text("SELECT value, status FROM entries WHERE value LIKE 'twin.com%'")).fetchall()
        assert [tuple(r) for r in rows] == [("twin.com/", "blocked")]       # the more restrictive status won
        owners = sorted(r[0] for r in c.execute(text(
            "SELECT host FROM entry_sources s JOIN entries e ON e.id = s.entry_id WHERE e.value = 'twin.com/'")))
        assert owners == ["h1", "h2"]                                        # ownership combined, none lost


def test_startup_after_upgrade_recomputes_suppression_and_the_feed(client):
    """Legacy rows (no slash, no suppression data) go through the real startup path."""
    apex_policy(client)
    with client.factory() as s:
        s.add_all([Entry(list_name="default", value="*.legacy.org", status="active"),
                   Entry(list_name="default", value="www.legacy.org", status="active"),
                   Entry(list_name="default", value="legacy.org", status="active"),
                   Entry(list_name="default", value="legacy.org/path", status="active")])
        s.commit()
    client.main.init_app(client.engine, client.factory)
    with client.factory() as s:
        sup = {e.value: e.suppressed_by for e in s.scalars(select(Entry))}
        assert sup["www.legacy.org/"] == "*.legacy.org/"
        assert sup["legacy.org/"] is None and sup["*.legacy.org/"] is None
        owners = s.scalars(select(EntrySource)).all()
        assert len(owners) == 4 and all(o.kind == "api" for o in owners)
        assert s.scalars(select(AuditLog).where(AuditLog.action == "schema-upgrade")).first() is not None
    assert feed(client).text.splitlines() == ["*.legacy.org/", "legacy.org/", "legacy.org/path"]
    client.main.init_app(client.engine, client.factory)                     # and a second start is a no-op
    assert feed(client).text.splitlines() == ["*.legacy.org/", "legacy.org/", "legacy.org/path"]
