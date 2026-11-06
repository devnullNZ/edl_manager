"""v2.3.0: `reclassify` in the sync API, resumable reclassification jobs, and the draining engine."""
import asyncio
import threading
import time

from sqlalchemy import func, select

from app.db import Entry, ReclassJob
from app.engine import ProcessingEngine, processing_engine as eng
from conftest import apex_policy, bearer, chunked, login, put_settings, sync

H = lambda c: bearer(c.token)  # noqa: E731


def stored(c):
    with c.factory() as s:
        return {e.value: e for e in s.scalars(select(Entry))}


def feed_lines(c):
    r = c.get("/edl/default")
    return [x for x in r.text.splitlines() if x]


def lookup_as(c, fn):
    """Replace what the fake Panorama answers (keeps recording calls)."""
    def lookup(target):
        c.fake.calls.append(target)
        return fn(target)
    c.fake.lookup = lookup


CLEAN = lambda t: f"{t} search-engines (Base db)"      # noqa: E731
MALWARE = lambda t: f"{t} malware (Cloud db)"          # noqa: E731


# ============================================================ the option itself
class TestReclassifyOption:
    def test_default_is_false_and_an_identical_sync_does_not_ask_panorama(self, client):
        sync(client, ["bad1.example.org"], sync_id="1")
        assert stored(client)["bad1.example.org/"].status == "blocked"
        lookup_as(client, CLEAN)                       # Panorama now says clean...
        client.fake.calls.clear()
        r = sync(client, ["bad1.example.org"], sync_id="2")
        assert client.fake.calls == [] and stored(client)["bad1.example.org/"].status == "blocked"
        assert r["reclassification"] == {"requested": False}

    def test_reclassify_asks_again_refreshes_the_cache_and_reconsiders_blocked_entries(self, client):
        sync(client, ["bad1.example.org", "ok.example.org"], sync_id="1")
        lookup_as(client, CLEAN)
        client.fake.calls.clear()
        r = sync(client, ["bad1.example.org", "ok.example.org"], sync_id="2", reclassify=True)
        assert sorted(client.fake.calls) == ["bad1.example.org", "ok.example.org"]   # the cache was bypassed
        rc = r["reclassification"]
        assert rc["requested"] and rc["in_scope"] == 2 and rc["changed_inline"] == 1 and rc["remaining"] == 0
        assert rc["status"] == "done"
        assert stored(client)["bad1.example.org/"].status == "active"
        assert feed_lines(client) == ["bad1.example.org/", "ok.example.org/"]
        client.fake.calls.clear()
        sync(client, ["bad1.example.org"], sync_id="3")                  # the cache holds the NEW answer
        assert client.fake.calls == []

    def test_reclassify_can_also_block_a_previously_approved_entry(self, client):
        sync(client, ["flip.example.org"], sync_id="1")
        assert feed_lines(client) == ["flip.example.org/"]
        lookup_as(client, MALWARE)
        r = sync(client, ["flip.example.org"], sync_id="2", reclassify=True)
        assert r["status"] == "applied" and stored(client)["flip.example.org/"].status == "blocked"
        assert feed_lines(client) == []

    def test_identical_reclassify_sync_id_is_idempotent_but_other_options_conflict(self, client):
        sync(client, ["a.example.org"], sync_id="1")
        r1 = sync(client, ["a.example.org"], sync_id="2", reclassify=True)
        n = len(client.fake.calls)
        r2 = sync(client, ["a.example.org"], sync_id="2", reclassify=True)
        assert r2["duplicate"] is True and r2["run_id"] == r1["run_id"] and len(client.fake.calls) == n
        sync(client, ["a.example.org"], sync_id="2", reclassify=False, expect=409)

    def test_dry_run_asks_nothing_changes_nothing_and_creates_no_job(self, client):
        sync(client, ["bad1.example.org"], sync_id="1")
        lookup_as(client, CLEAN)
        client.fake.calls.clear()
        r = sync(client, ["bad1.example.org"], sync_id="2", reclassify=True, dry_run=True)
        assert client.fake.calls == [] and r["status"] == "dry_run"
        assert r["reclassification"]["in_scope"] == 1 and r["reclassification"]["dry_run"] is True
        assert stored(client)["bad1.example.org/"].status == "blocked"
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(ReclassJob)) == 0

    def test_only_entries_of_the_desired_state_are_in_scope(self, client):
        sync(client, ["mine.example.org"], source="a", sync_id="1")
        sync(client, ["other.example.org"], source="b", sync_id="1")
        client.fake.calls.clear()
        r = sync(client, ["mine.example.org"], source="a", sync_id="2", reclassify=True)
        assert client.fake.calls == ["mine.example.org"] and r["reclassification"]["in_scope"] == 1

    def test_ownership_is_untouched(self, client):
        sync(client, ["x.example.org", "y.example.org"], source="a", sync_id="1")
        sync(client, ["y.example.org"], source="b", sync_id="1")
        sync(client, ["x.example.org"], source="a", sync_id="2", reclassify=True, delete_missing=True)
        assert sorted(stored(client)) == ["x.example.org/", "y.example.org/"]     # y kept: source b owns it


# ============================================================ fail closed
class TestFailClosed:
    def test_a_failed_lookup_changes_nothing_and_is_retried_by_the_engine(self, client):
        sync(client, ["bad1.example.org", "ok.example.org"], sync_id="1")
        lookup_as(client, CLEAN)
        client.fake.fail_next = 10_000
        client.fake.lookup_orig = None

        def failing(t):
            client.fake.calls.append(t)
            raise __import__("app.panorama", fromlist=["PanoramaError"]).PanoramaError("timeout")
        client.fake.lookup = failing
        r = sync(client, ["bad1.example.org", "ok.example.org"], sync_id="2", reclassify=True)
        rc = r["reclassification"]
        assert rc["kept_after_error"] == 2 and rc["remaining"] == 2 and rc["status"] == "running"
        st = stored(client)
        assert st["bad1.example.org/"].status == "blocked" and st["ok.example.org/"].status == "active"
        assert feed_lines(client) == ["ok.example.org/"]          # a timeout neither approved nor removed anything
        assert all(e.reclass_job_id == rc["job_id"] for e in st.values())
        # Panorama recovers: the engine works the job off
        lookup_as(client, CLEAN)
        eng.tick(force=True)
        st = stored(client)
        assert st["bad1.example.org/"].status == "active" and all(e.reclass_job_id is None for e in st.values())
        job = client.get(f"/v1/lists/default/sync/reclassifications/{rc['job_id']}", headers=H(client)).json()
        assert job["status"] == "done" and job["remaining"] == 0 and job["changed"] == 1

    def test_a_pending_entry_is_not_approved_by_a_failed_reclassification(self, client):
        client.fake.fail_next = 10_000
        sync(client, ["p.example.org"], sync_id="1")
        assert stored(client)["p.example.org/"].status == "pending"
        r = sync(client, ["p.example.org"], sync_id="2", reclassify=True)
        assert stored(client)["p.example.org/"].status == "pending" and feed_lines(client) == []
        assert r["reclassification"]["kept_after_error"] == 1

    def test_an_inconclusive_answer_does_not_release_a_blocked_entry(self, client):
        sync(client, ["bad1.example.org"], sync_id="1")
        lookup_as(client, lambda t: f"{t} unknown (Cloud db)")
        put_settings(client, {"unknown_category_behaviour": "publish"})
        r = sync(client, ["bad1.example.org"], sync_id="2", reclassify=True)
        assert stored(client)["bad1.example.org/"].status == "blocked" and feed_lines(client) == []
        assert r["reclassification"]["inconclusive_kept"] == 1
        lookup_as(client, CLEAN)                                  # a conclusive answer does release it
        sync(client, ["bad1.example.org"], sync_id="3", reclassify=True)
        assert stored(client)["bad1.example.org/"].status == "active"

    def test_removals_are_deferred_when_a_reclassification_lookup_fails(self, client):
        sync(client, ["a.example.org", "b.example.org"], sync_id="1")

        def failing(t):
            raise __import__("app.panorama", fromlist=["PanoramaError"]).PanoramaError("down")
        client.fake.lookup = failing
        r = sync(client, ["a.example.org"], sync_id="2", reclassify=True, delete_missing=True)
        assert r["removals_deferred"] is True and "b.example.org/" in stored(client)


# ============================================================ wildcards, suppression, snapshots
class TestWildcards:
    def test_suppression_and_the_feed_follow_a_reclassified_wildcard(self, client):
        apex_policy(client)
        lookup_as(client, MALWARE)                                # the apex is bad when first seen
        sync(client, ["*.example.com", "www.example.com"], sync_id="1")
        assert stored(client)["*.example.com/"].status == "blocked" and feed_lines(client) == []
        lookup_as(client, CLEAN)
        r = sync(client, ["*.example.com", "www.example.com"], sync_id="2", reclassify=True)
        st = stored(client)
        assert st["*.example.com/"].status == "active" and st["www.example.com/"].suppressed_by == "*.example.com/"
        assert feed_lines(client) == ["*.example.com/"]           # snapshot rebuilt, subdomain suppressed
        assert r["counts"]["suppressed_by_shadowing"] == 1
        lookup_as(client, MALWARE)                                # and the other way round
        sync(client, ["*.example.com", "www.example.com"], sync_id="3", reclassify=True)
        st = stored(client)
        assert st["*.example.com/"].status == "blocked" and st["www.example.com/"].suppressed_by is None
        assert feed_lines(client) == []                           # www is cached as bad too in this fake

    def test_policy_exclude_still_blocks_wildcards_on_reclassify(self, client):
        sync(client, ["*.example.com"], sync_id="1")
        client.fake.calls.clear()
        sync(client, ["*.example.com"], sync_id="2", reclassify=True)
        assert client.fake.calls == [] and stored(client)["*.example.com/"].status == "blocked"


# ============================================================ concurrency, budget, large jobs
class TestScale:
    def test_never_more_than_five_panorama_requests_at_once(self, client):
        lock, state = threading.Lock(), {"now": 0, "max": 0}

        def slow(t):
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.01)
            with lock:
                state["now"] -= 1
            return CLEAN(t)
        lookup_as(client, slow)
        ents = [f"h{i}.example.org" for i in range(60)]
        sync(client, ents, sync_id="1")
        state["max"] = 0
        sync(client, ents, sync_id="2", reclassify=True)
        assert 1 < state["max"] <= 5
        state["max"] = 0
        put_settings(client, {"sync_classification_budget": 0})
        sync(client, ents, sync_id="3", reclassify=True)           # all queued: the engine does it
        eng.tick(force=True)
        assert state["max"] <= 5

    def test_a_large_job_is_bounded_by_the_budget_then_resumed_by_the_engine(self, client):
        ents = [f"h{i:03d}.example.org" for i in range(40)]
        sync(client, ents, sync_id="1")
        lookup_as(client, MALWARE)
        put_settings(client, {"sync_classification_budget": 10, "max_batch_size": 8})
        client.fake.calls.clear()
        r = sync(client, ents, sync_id="2", reclassify=True)
        rc = r["reclassification"]
        assert len(client.fake.calls) == 10 and rc["reclassified_inline"] == 10 and rc["queued_for_engine"] == 30
        assert rc["status"] == "running"
        statuses = lambda: sorted(e.status for e in stored(client).values())  # noqa: E731
        assert statuses().count("blocked") == 10                   # the rest keep their approved status for now
        jid = rc["job_id"]
        url = f"/v1/lists/default/sync/reclassifications/{jid}"
        assert client.get(url, headers=H(client)).json()["remaining"] == 30
        eng.tick(force=True)                                       # one batch of 8
        assert client.get(url, headers=H(client)).json()["remaining"] == 22
        # "restart": the job lives in the database; a brand-new engine continues it
        fresh = ProcessingEngine()
        put_settings(client, {"processing_batch_delay_seconds": 0})
        res = fresh.tick(force=True, drain=True)
        assert res["drain"]["batches"] >= 3
        job = client.get(url, headers=H(client)).json()
        assert job["remaining"] == 0 and job["status"] == "done"
        assert statuses().count("blocked") == 40 and feed_lines(client) == []

    def test_job_status_is_private_to_the_host(self, client):
        r = sync(client, ["a.example.org"], sync_id="1")
        r = sync(client, ["a.example.org"], sync_id="2", reclassify=True)
        jid = r["reclassification"]["job_id"]
        assert client.get(f"/v1/lists/default/sync/reclassifications/{jid}").status_code in (401, 403)
        assert client.get("/v1/lists/default/sync/reclassifications/9999", headers=H(client)).status_code == 404

    def test_chunked_sync_supports_reclassify(self, client):
        ents = [f"c{i:02d}.example.org" for i in range(12)]
        chunked(client, ents, chunk=5, sync_id="c1")
        lookup_as(client, MALWARE)
        sess, out = chunked(client, ents, chunk=5, sync_id="c2", reclassify=True)
        assert sess["reclassify"] is True and out.status_code == 200, out.text
        assert out.json()["reclassification"]["changed_inline"] == 12
        assert feed_lines(client) == []

    def test_resuming_a_session_with_other_options_is_refused(self, client):
        h = H(client)
        body = {"source": "imp", "sync_id": "s1", "reclassify": True}
        assert client.post("/v1/lists/default/sync/sessions", json=body, headers=h).status_code == 200
        body["reclassify"] = False
        assert client.post("/v1/lists/default/sync/sessions", json=body, headers=h).status_code == 409


# ============================================================ chunk validation
class TestChunkValidation:
    def test_invalid_entries_are_reported_per_chunk_and_listed_with_their_position(self, client):
        h = H(client)
        s = client.post("/v1/lists/default/sync/sessions", json={"source": "imp", "sync_id": "v1",
                                                                  "delete_missing": True}, headers=h).json()
        sid = s["session_id"]
        r = client.put(f"/v1/lists/default/sync/sessions/{sid}/chunks/0", headers=h,
                       json={"entries": ["ok.example.org", "bad entry", "also ok.example.org", "http://"]}).json()
        assert r["invalid_in_chunk"] >= 1 and r["received_invalid"] == r["invalid_in_chunk"]
        r2 = client.put(f"/v1/lists/default/sync/sessions/{sid}/chunks/1", headers=h,
                        json={"entries": ["fine.example.org", "bad entry two"]}).json()
        assert r2["received_invalid"] == r["invalid_in_chunk"] + r2["invalid_in_chunk"]
        lst = client.get(f"/v1/lists/default/sync/sessions/{sid}/invalid", headers=h).json()
        assert lst["total_invalid"] == r2["received_invalid"]
        assert [(i["chunk"], i["position"]) for i in lst["items"]][:2] == [(0, 1), (0, 2)] or lst["items"][0]["chunk"] == 0
        page = client.get(f"/v1/lists/default/sync/sessions/{sid}/invalid?offset=1&limit=1", headers=h).json()
        assert len(page["items"]) == 1
        c = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h,
                        json={"total_chunks": 2, "total_entries": 6})
        assert c.status_code == 422 and c.json()["detail"]["invalid_total"] == lst["total_invalid"]
        with client.factory() as s_:
            assert s_.scalar(select(func.count()).select_from(Entry)) == 0         # nothing applied

    def test_invalid_list_is_private_to_the_host(self, client):
        assert client.get("/v1/lists/default/sync/sessions/1/invalid").status_code in (401, 403)


# ============================================================ the engine
class TestDrainingEngine:
    def pend(self, client, n):
        client.fake.fail_next = 10_000
        sync(client, [f"p{i:03d}.example.org" for i in range(n)], sync_id="p")
        client.fake.fail_next = 0

    def test_one_cycle_works_through_every_batch(self, client):
        put_settings(client, {"max_batch_size": 10, "processing_batch_delay_seconds": 0})
        self.pend(client, 35)
        assert eng.tick(force=True)["pending"]["checked"] == 10          # a plain tick is still one batch
        res = eng.tick(force=True, drain=True)
        assert res["drain"]["batches"] == 3 and res["drain"]["processed"] == 25   # 10 + 10 + 5 remaining
        assert all(e.status == "active" for e in stored(client).values()) and len(feed_lines(client)) == 35

    def test_each_entry_is_tried_once_per_cycle_and_an_outage_ends_the_cycle(self, client):
        put_settings(client, {"max_batch_size": 10, "processing_batch_delay_seconds": 0, "retry_attempts": 0})
        self.pend(client, 30)
        client.fake.calls.clear()
        client.fake.fail_next = 10_000
        res = eng.tick(force=True, drain=True)
        assert "unavailable" in res["drain"]["ended"] and res["drain"]["batches"] == 1
        assert len(client.fake.calls) <= 10                              # not 30, and not looping forever

    def test_partial_failures_still_visit_every_entry_exactly_once(self, client):
        put_settings(client, {"max_batch_size": 10, "processing_batch_delay_seconds": 0, "retry_attempts": 0})
        self.pend(client, 30)
        client.fake.calls.clear()
        client.fake.fail = {f"p{i:03d}.example.org" for i in range(0, 30, 2)}      # half keep failing
        res = eng.tick(force=True, drain=True)
        assert res["drain"]["processed"] == 30 and len(client.fake.calls) == 30
        assert sum(e.status == "active" for e in stored(client).values()) == 15

    def test_batch_size_delay_and_the_switch_are_read_before_every_batch(self, client, monkeypatch):
        put_settings(client, {"max_batch_size": 5, "processing_batch_delay_seconds": 7})
        self.pend(client, 20)
        waits = []
        monkeypatch.setattr(eng._stop, "wait", lambda t=None: waits.append(t) or False)
        orig = eng._progress

        def switch_off_after_two(db, **kw):
            if kw.get("batches") == 2:
                put_settings(client, {"background_processing_enabled": False}, confirm=True)
            return orig(db, **kw)
        monkeypatch.setattr(eng, "_progress", switch_off_after_two)
        res = eng.tick(force=True, drain=True)
        assert waits and set(waits) == {7} and "switched off" in res["drain"]["ended"]
        assert res["drain"]["batches"] == 2

    def test_progress_is_exposed_to_the_admin_interface(self, client):
        put_settings(client, {"max_batch_size": 10, "processing_batch_delay_seconds": 0})
        self.pend(client, 12)
        sync(client, ["z.example.org"], sync_id="z0")
        sync(client, ["z.example.org"], sync_id="z1", reclassify=True)
        eng.tick(force=True, drain=True)
        login(client)
        html = client.get("/admin/settings/processing").text
        assert "Entries awaiting reclassification" in html and "Last cycle" in html and "batch(es)" in html
        assert "Reclassification jobs" in html
        assert "Delay between batches" in html
        assert "Awaiting reclassification" in client.get("/admin/settings").text

    def test_shutdown_lets_the_batch_in_progress_finish(self, client):
        put_settings(client, {"max_batch_size": 5, "processing_batch_delay_seconds": 0, "processing_interval_seconds": 5})
        self.pend(client, 20)

        async def go():
            e = ProcessingEngine()
            e.start()
            e.wake()
            await asyncio.sleep(0.3)
            await asyncio.wait_for(e.stop(), timeout=30)
            return e
        e = asyncio.run(go())
        assert e._task is None and e._inflight is None
        n_active = sum(1 for x in stored(client).values() if x.status == "active")
        assert n_active % 5 == 0                                          # whole batches only, all committed
        assert not any(t.name.startswith("asyncio_") and t.is_alive() for t in threading.enumerate())


# ============================================================ concurrency of chunked syncs
class TestConcurrentSessions:
    def test_two_simultaneous_commits_of_one_session_apply_it_once(self, client):
        h = H(client)
        ents = [f"k{i:03d}.example.org" for i in range(30)]
        sid = client.post("/v1/lists/default/sync/sessions", headers=h,
                          json={"source": "imp", "sync_id": "dup"}).json()["session_id"]
        for i in range(0, 30, 10):
            assert client.put(f"/v1/lists/default/sync/sessions/{sid}/chunks/{i // 10}", headers=h,
                              json={"entries": ents[i:i + 10]}).status_code == 200
        results = []

        def commit():
            r = client.post(f"/v1/lists/default/sync/sessions/{sid}/commit", headers=h,
                            json={"total_chunks": 3, "total_entries": 30})
            results.append((r.status_code, r.json()))
        ts = [threading.Thread(target=commit) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert [c for c, _ in results] == [200, 200]
        assert sorted(j.get("duplicate", False) for _, j in results) == [False, True]
        assert len(stored(client)) == 30
        with client.factory() as s:
            from app.db import SyncRun
            assert s.scalar(select(func.count()).select_from(SyncRun).where(SyncRun.status != "failed")) == 1

    def test_sessions_of_different_sources_do_not_interfere(self, client):
        h = H(client)
        a = client.post("/v1/lists/default/sync/sessions", headers=h, json={"source": "a", "sync_id": "1"}).json()
        b = client.post("/v1/lists/default/sync/sessions", headers=h, json={"source": "b", "sync_id": "1"}).json()
        assert a["session_id"] != b["session_id"]
        for sess, ents in ((a, ["only-a.example.org"]), (b, ["only-b.example.org"])):
            client.put(f"/v1/lists/default/sync/sessions/{sess['session_id']}/chunks/0", headers=h, json={"entries": ents})
        for sess in (a, b):
            r = client.post(f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit", headers=h,
                            json={"total_chunks": 1, "total_entries": 1, "dry_run": False})
            assert r.status_code == 200
        assert sorted(stored(client)) == ["only-a.example.org/", "only-b.example.org/"]
