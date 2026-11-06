"""v2.3.1: the removal limit is enforced by the server inside the commit transaction; dry runs change nothing."""
import threading

import pytest
from sqlalchemy import select

from app import service
from app.db import Base, Entry, EntrySource, SyncRun
from conftest import bearer, chunked, sync

NAMES = [f"h{i:02d}.example.org" for i in range(10)]
OWNED = NAMES[:10]


def dump(c, skip=()):
    """Every row of every table, as comparable tuples. allowed_hosts is skipped: authenticating a request
    legitimately stamps the host's last-used time."""
    skip = set(skip) | {"allowed_hosts"}
    out = {}
    with c.factory() as s:
        for t in Base.metadata.sorted_tables:
            if t.name in skip:
                continue
            cols = [col for col in t.c]
            out[t.name] = sorted(map(tuple, s.execute(select(*cols)).all()), key=repr)
    return out


def owned(c, source="yaml-import"):
    with c.factory() as s:
        q = select(Entry.value).join(EntrySource, EntrySource.entry_id == Entry.id).where(EntrySource.source_id == source)
        return sorted(s.scalars(q))


def seed(c, source="yaml-import"):
    sync(c, OWNED, source=source, sync_id="seed")
    assert len(owned(c, source)) == 10


class TestServerEnforcedLimit:
    def test_limit_is_checked_by_the_server_and_nothing_is_applied(self, client):
        seed(client)
        before = dump(client, skip={"audit_log", "sync_runs", "sync_sources"})
        r = sync(client, OWNED[:6], sync_id="x1", delete_missing=True, max_removals=3, expect=409)
        d = r["detail"]
        assert d["removal_limit_exceeded"] is True and d["would_remove"] == 4 and d["max_removals"] == 3
        assert dump(client, skip={"audit_log", "sync_runs", "sync_sources"}) == before
        assert len(owned(client)) == 10

    def test_at_the_limit_is_allowed_and_zero_means_remove_nothing(self, client):
        seed(client)
        sync(client, OWNED[:6], sync_id="x1", delete_missing=True, max_removals=0, expect=409)
        r = sync(client, OWNED[:7], sync_id="x2", delete_missing=True, max_removals=3)
        assert r["counts"]["removed"] == 3 and len(owned(client)) == 7

    def test_a_refused_sync_id_can_be_retried_with_a_higher_limit(self, client):
        seed(client)
        sync(client, OWNED[:5], sync_id="x1", delete_missing=True, max_removals=1, expect=409)
        r = sync(client, OWNED[:5], sync_id="x1", delete_missing=True, max_removals=5)
        assert r["counts"]["removed"] == 5 and r.get("duplicate") is False

    def test_limit_is_ignored_without_delete_missing(self, client):
        seed(client)
        r = sync(client, OWNED[:2], sync_id="x1", max_removals=0)
        assert r["counts"]["removed"] == 0 and len(owned(client)) == 10

    def test_negative_limit_is_refused(self, client):
        sync(client, ["a.example.org"], sync_id="x", delete_missing=True, max_removals=-1, expect=422)

    def test_stale_dry_run_cannot_cause_unexpected_deletion(self, client):
        """The preview said 'removes 2'. Before the real commit the same source grows to 10 owned entries; the
        commit would now remove 8 > the 2 the operator accepted, so the server refuses."""
        sync(client, OWNED[:3], sync_id="s0")
        pre = sync(client, OWNED[:1], sync_id="x", delete_missing=True, dry_run=True, max_removals=2)
        assert pre["counts"]["removed"] == 2 and pre["would_exceed_max_removals"] is False
        sync(client, OWNED, sync_id="grow")                                   # the world moves on
        sync(client, OWNED[:1], sync_id="x", delete_missing=True, max_removals=2, expect=409)
        assert len(owned(client)) == 10

    def test_chunked_commit_enforces_the_limit_keeps_the_session_open_and_retries(self, client):
        seed(client)
        h = bearer(client.token)
        sess, _ = chunked(client, OWNED[:4], source="yaml-import", sync_id="c1", delete_missing=True, commit=False)
        sid = sess["session_id"]
        body = {"total_chunks": 2, "total_entries": 4}
        r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h, json={**body, "max_removals": 2})
        assert r.status_code == 409 and r.json()["detail"]["removal_limit_exceeded"] is True
        assert len(owned(client)) == 10
        st = client.get(f"/v1/lists/default/sync/sessions/{sid}", headers=h).json()
        assert st["status"] == "receiving"                                    # nothing lost; staged data kept
        r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h, json={**body, "max_removals": 6})
        assert r.status_code == 200 and r.json()["counts"]["removed"] == 6 and len(owned(client)) == 4

    def test_other_sources_are_never_removed_even_without_a_limit(self, client):
        seed(client, source="a")
        sync(client, ["other.example.org"], source="b", sync_id="b1")
        sync(client, OWNED[:2], source="a", sync_id="a2", delete_missing=True, max_removals=8)
        assert owned(client, "b") == ["other.example.org/"]


class TestFailedCommitsDoNotPartiallyReconcile:
    def test_failure_while_applying_rolls_everything_back(self, client, monkeypatch):
        seed(client)
        before = dump(client, skip={"audit_log", "sync_runs", "sync_sources", "category_cache"})
        cache_before = dump(client)["category_cache"]

        def boom(*a, **k):
            raise RuntimeError("disk full")
        monkeypatch.setattr(service, "rebuild_snapshot", boom)
        sync(client, OWNED[:2] + ["new.example.org"], sync_id="f1", delete_missing=True, expect=500)
        monkeypatch.undo()
        assert dump(client, skip={"audit_log", "sync_runs", "sync_sources", "category_cache"}) == before
        # a Panorama answer is a fact, not list state: the cache may gain the new entry but loses/changes nothing
        assert set(cache_before) <= set(dump(client)["category_cache"])
        with client.factory() as s:
            runs = list(s.scalars(select(SyncRun).where(SyncRun.sync_id == "f1")))
            assert [r.status for r in runs] == ["failed"] and runs[0].dedup_key is None   # retryable
        r = sync(client, OWNED[:2] + ["new.example.org"], sync_id="f1", delete_missing=True)   # same id works
        assert r["counts"]["removed"] == 8

    def test_failure_at_the_chunked_commit_leaves_the_session_and_the_list_intact(self, client, monkeypatch):
        seed(client)
        sess, _ = chunked(client, OWNED[:2], source="yaml-import", sync_id="c1", delete_missing=True, commit=False)
        sid, h = sess["session_id"], bearer(client.token)
        skip = {"audit_log", "sync_runs", "sync_sources", "sync_sessions", "category_cache"}
        before = dump(client, skip=skip)
        monkeypatch.setattr(service, "rebuild_snapshot", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
        r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h,
                        json={"total_chunks": 1, "total_entries": 2})
        assert r.status_code == 500
        monkeypatch.undo()
        assert dump(client, skip=skip) == before
        r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h,
                        json={"total_chunks": 1, "total_entries": 2})
        assert r.status_code == 200 and len(owned(client)) == 2


class TestConcurrentSyncsCannotBypassTheLimit:
    @pytest.mark.parametrize("attempt", range(3))
    def test_two_racing_syncs_of_one_source_never_remove_more_than_the_limit_each(self, client, attempt):
        seed(client)
        results, barrier = {}, threading.Barrier(2)

        def go(name, keep):
            barrier.wait()
            r = client.post("/v1/lists/default/sync", headers=bearer(client.token),
                            json={"source": "yaml-import", "sync_id": f"{name}-{attempt}", "entries": keep,
                                  "delete_missing": True, "max_removals": 3})
            results[name] = r

        ts = [threading.Thread(target=go, args=("t1", OWNED[:7])), threading.Thread(target=go, args=("t2", OWNED[:4]))]
        [t.start() for t in ts]
        [t.join(60) for t in ts]
        for name, r in results.items():
            if r.status_code == 200:
                assert r.json()["counts"]["removed"] <= 3, (name, r.json()["counts"])
            else:
                assert r.status_code == 409 and r.json()["detail"]["removal_limit_exceeded"], r.text
        assert len(owned(client)) in (7, 4)           # either order; never an unreviewed bigger jump
        assert any(r.status_code == 200 for r in results.values())


class TestDryRunNeverChangesState:
    def test_single_request_dry_run_with_every_option_changes_no_row(self, client):
        seed(client)
        before = dump(client)
        r = sync(client, OWNED[:2] + ["new.example.org", "bad1.example.org"], sync_id="d1", delete_missing=True,
                 dry_run=True, reclassify=True, max_removals=1)
        assert r["dry_run"] is True and r["counts"]["removed"] == 8 and r["would_exceed_max_removals"] is True
        assert dump(client) == before                               # includes audit_log, caches, snapshots, jobs
        assert len(owned(client)) == 10

    def test_dry_run_does_not_consume_the_sync_id(self, client):
        seed(client)
        sync(client, OWNED[:2], sync_id="d1", delete_missing=True, dry_run=True)
        r = sync(client, OWNED[:2], sync_id="d1", delete_missing=True)
        assert r["duplicate"] is False and r["counts"]["removed"] == 8

    def test_chunked_dry_run_commit_changes_nothing_and_keeps_the_session(self, client):
        seed(client)
        sess, _ = chunked(client, OWNED[:2] + ["new.example.org"], source="yaml-import", sync_id="c1", delete_missing=True,
                          reclassify=True, commit=False)
        sid, h = sess["session_id"], bearer(client.token)
        before = dump(client, skip={"sync_sessions"})
        r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h,
                        json={"total_chunks": 1, "total_entries": 3, "dry_run": True})
        assert r.status_code == 200 and r.json()["dry_run"] is True and r.json()["counts"]["removed"] == 8
        assert dump(client, skip={"sync_sessions"}) == before
        assert client.get(f"/v1/lists/default/sync/sessions/{sid}", headers=h).json()["status"] == "receiving"
