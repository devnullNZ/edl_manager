"""v2.2.0: about 60,000 entries across lists - bulk statements, no N+1 queries, bounded Panorama use."""
import time

from sqlalchemy import event, func, select

from app.db import Entry, EntrySource
from conftest import apex_policy, feed, put_settings, sync

PER_LIST = 20_000


def make_entries(n, prefix):
    out = [f"host{i}.{prefix}{i % 500}.example.org" for i in range(n - 100)]
    out += [f"*.{prefix}w{i}.example.org" for i in range(100)]          # wildcards covering some of the hosts
    return out


def test_sixty_thousand_entries_across_three_lists(client):
    put_settings(client, {"classification_enabled": False, "max_sync_size": 100000, "edl_max_entries": 0}, confirm=True)
    put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)
    statements = []
    event.listen(client.engine, "before_cursor_execute", lambda *a: statements.append(a[2]))
    t0 = time.time()
    for name in ("a", "b", "c"):
        r = sync(client, make_entries(PER_LIST, name), list_name=name, sync_id="1", delete_missing=True)
        assert r["counts"]["new"] == PER_LIST and r["counts"]["processing_errors"] == 0
        assert len(r["entries"]) <= 2000 and r["entries_truncated"] is True    # the report itself stays bounded
    first = time.time() - t0
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(Entry)) == 3 * PER_LIST
        assert s.scalar(select(func.count()).select_from(EntrySource)) == 3 * PER_LIST
    # the whole import issued a bounded number of statements: bulk inserts, not one per entry
    assert len(statements) < 600, len(statements)
    assert first < 120

    # an identical re-sync: bulk reads only, no writes to entry data, quick
    statements.clear()
    t1 = time.time()
    r = sync(client, make_entries(PER_LIST, "a"), list_name="a", sync_id="2", delete_missing=True)
    assert r["status"] == "no_change" and r["counts"]["unchanged"] == PER_LIST
    writes = [s for s in statements if s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
              and ("entries" in s or "entry_sources" in s or "edl_snapshots" in s)]
    assert writes == []
    assert len(statements) < 60, len(statements)
    assert time.time() - t1 < 30
    assert len(feed(client, "a").text.splitlines()) == PER_LIST - 100          # wildcards excluded by the default policy


def test_wildcard_suppression_at_scale_uses_suffix_lookup(client):
    apex_policy(client)
    put_settings(client, {"classification_enabled": False}, confirm=True)
    put_settings(client, {"wildcard_classification_policy": "apex-classification"}, confirm=True)
    # classification is off, so wildcards stay pending; exercise the matcher directly on 60k rows
    from app.shadow import suppressed_by
    hosts = [f"h{i}.sub{i % 1000}.example.org/" for i in range(60_000)]
    wild = [f"*.sub{i}.example.org/" for i in range(0, 1000, 2)]
    t = time.time()
    got = suppressed_by(hosts, wild)
    assert time.time() - t < 5
    assert len(got) == 30_000 and got["h0.sub0.example.org/"] == "*.sub0.example.org/"
    assert "h1.sub1.example.org/" not in got


def test_queries_do_not_grow_with_entry_count(client):
    put_settings(client, {"classification_enabled": False}, confirm=True)
    counts = []
    for n, sid in ((200, "1"), (2000, "2")):
        stmts = []
        hook = lambda *a, _s=stmts: _s.append(a[2])  # noqa: E731
        event.listen(client.engine, "before_cursor_execute", hook)
        sync(client, [f"n{sid}x{i}.example.com" for i in range(n)], list_name=f"l{sid}", sync_id=sid)
        event.remove(client.engine, "before_cursor_execute", hook)
        counts.append(len(stmts))
    assert counts[1] <= counts[0] + 15, counts          # 10x the entries, (almost) the same number of statements
