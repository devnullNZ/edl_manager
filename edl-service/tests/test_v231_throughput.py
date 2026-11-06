"""v2.3.1: how requests reach the server and Panorama - the inbound per-host limit, cache use, backoff, retries by
the engine, and what the admin pages report. (The 120 requests/minute default is the INBOUND limit per host; there
is no request-rate limit towards Panorama, only the 5-concurrent cap.)"""
import asyncio

import httpx
import pytest
from sqlalchemy import select

from app import config, hosts, panorama
from app.db import Entry
from app.engine import ProcessingEngine, processing_engine as eng
from app.panorama import PanoramaClient, PanoramaError
from conftest import KEY as ADMIN_H, apex_policy, bearer, login, post, put_settings, sync


def entries_of(c):
    with c.factory() as s:
        return {e.value: e for e in s.scalars(select(Entry))}


# ============================================================ inbound per-host rate limit
class TestInboundRateLimit:
    def test_default_is_120_per_minute_per_host(self, client):
        s = config.get_settings()
        assert (s.rate_limit_requests, s.rate_limit_interval_seconds) == (120, 60)

    def test_every_host_endpoint_draws_on_one_budget_and_a_refusal_changes_nothing(self, client):
        put_settings(client, {"rate_limit_requests": 6, "rate_limit_interval_seconds": 60})
        h = bearer(client.token)
        base = "/v1/lists/default"
        calls = [
            lambda: client.post(f"{base}/sync", headers=h, json={"source": "s", "sync_id": "1", "entries": ["a.example.org"],
                                                              "dry_run": True}),
            lambda: client.post(f"{base}/sync/sessions", headers=h, json={"source": "s", "sync_id": "2"}),
            lambda: client.put(f"{base}/sync/sessions/1/chunks/0", headers=h, json={"entries": ["b.example.org"]}),
            lambda: client.get(f"{base}/sync/sessions/1", headers=h),
            lambda: client.get(f"{base}/sync/sessions/1/invalid", headers=h),
            lambda: client.delete(f"{base}/sync/sessions/1", headers=h),
        ]
        codes = [c().status_code for c in calls]
        assert 429 not in codes and len(codes) == 6
        r = client.post(f"{base}/entries", headers=h, json={"urls": ["late.example.org"]})
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
        r = client.post(f"{base}/sync", headers=h, json={"source": "s", "sync_id": "9", "entries": ["late.example.org"]})
        assert r.status_code == 429
        assert "late.example.org/" not in entries_of(client)                 # nothing was applied
        assert client.get("/edl/default").status_code in (200, 503)         # feeds are not rate limited (firewalls poll)

    def test_the_budget_is_per_host_not_global(self, client):
        put_settings(client, {"rate_limit_requests": 2, "rate_limit_interval_seconds": 60})
        with client.factory() as s:
            _, other = hosts.create_host(s, "other", "10.0.0.0/24", "*")
        for _ in range(2):
            assert client.get("/v1/lists/default/sync/sessions/1", headers=bearer(client.token)).status_code != 429
        assert client.get("/v1/lists/default/sync/sessions/1", headers=bearer(client.token)).status_code == 429
        assert client.get("/v1/lists/default/sync/sessions/1", headers=bearer(other)).status_code != 429

    def test_zero_means_unlimited_and_admin_api_is_not_counted(self, client):
        put_settings(client, {"rate_limit_requests": 0})
        h = bearer(client.token)
        assert all(client.get("/v1/lists/default/sync/sessions/1", headers=h).status_code != 429 for _ in range(150))
        put_settings(client, {"rate_limit_requests": 1})
        client.get("/v1/lists/default/sync/sessions/1", headers=h)
        assert client.get("/v1/admin/edl", headers=KEY_H).status_code == 200


KEY_H = ADMIN_H
PAN_KEY = "SECRET-PAN-KEY-123456"


# ============================================================ cache use and Panorama request volume
class TestPanoramaRequestVolume:
    def test_one_lookup_per_distinct_target_even_when_listed_many_times(self, client):
        sync(client, ["dup.example.org"] * 5 + ["HTTP://DUP.EXAMPLE.ORG/", "other.example.org"], sync_id="1")
        assert sorted(client.fake.calls) == ["dup.example.org", "other.example.org"]

    def test_wildcards_with_the_same_base_domain_share_one_lookup(self, client):
        # a wildcard is classified by its base domain (the host after "*."), so wildcards that differ only in
        # path share one request; different base domains are different questions
        apex_policy(client)
        sync(client, ["*.a.example.com", "*.a.example.com/p1", "*.a.example.com/p2", "*.b.example.com"], sync_id="1")
        assert sorted(client.fake.calls) == ["a.example.com", "b.example.com"]

    def test_a_cached_answer_serves_later_syncs_even_after_the_entry_was_removed(self, client):
        sync(client, ["keep.example.org", "gone.example.org"], sync_id="1")
        assert len(client.fake.calls) == 2
        sync(client, ["keep.example.org"], sync_id="2", delete_missing=True)
        sync(client, ["keep.example.org", "gone.example.org"], sync_id="3")     # back again within the cache lifetime
        assert len(client.fake.calls) == 2                                      # no new Panorama request

    def test_the_cache_can_be_bypassed_only_on_request(self, client):
        sync(client, ["a.example.org"], sync_id="1")
        sync(client, ["a.example.org"], sync_id="2")
        assert len(client.fake.calls) == 1
        sync(client, ["a.example.org"], sync_id="3", reclassify=True)
        assert len(client.fake.calls) == 2

    def test_the_inline_budget_bounds_one_request_and_the_rest_waits_unpublished(self, client):
        put_settings(client, {"sync_classification_budget": 3})
        sync(client, [f"n{i}.example.org" for i in range(10)], sync_id="1")
        assert len(client.fake.calls) == 3
        st = [e.status for e in entries_of(client).values()]
        assert st.count("active") == 3 and st.count("pending") == 7              # never published unclassified
        assert len(client.get("/edl/default").text.split()) == 3


# ============================================================ failed requests and backoff
class TestBackoff:
    @pytest.fixture
    def pclient(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(panorama.time, "sleep", sleeps.append)

        def build(handler, **over):
            s = config.settings_from({"panorama_host": "pan.test", "panorama_api_key": PAN_KEY, **over})
            c = PanoramaClient(s)
            c._client = httpx.Client(base_url="https://pan.test:443", transport=httpx.MockTransport(handler),
                                     headers={"X-PAN-KEY": PAN_KEY})
            return c, sleeps
        return build

    def test_server_errors_back_off_exponentially_up_to_five_seconds(self, pclient):
        n = []
        c, sleeps = pclient(lambda r: (n.append(1), httpx.Response(503))[1], panorama_retry_count=6)
        with pytest.raises(PanoramaError):
            c.lookup("example.com")
        assert len(n) == 7 and sleeps == [0.5, 1.0, 2.0, 4.0, 5, 5]

    def test_api_errors_and_unparsable_replies_are_not_retried(self, pclient):
        n = []
        body = '<response status="error" code="13"><msg>nope</msg></response>'
        c, sleeps = pclient(lambda r: (n.append(1), httpx.Response(200, text=body))[1], panorama_retry_count=5)
        with pytest.raises(PanoramaError):
            c.lookup("example.com")
        assert len(n) == 1 and sleeps == []

    def test_concurrent_requests_stay_within_five_while_failing(self, client):
        # covered in depth by tests/test_concurrency.py; here only that failures release their slot
        from app.panorama import panorama_limiter
        client.fake.fail_next = 10
        post(client, [f"f{i}.example.com" for i in range(10)])
        assert panorama_limiter.in_flight == 0


# ============================================================ the engine does not hammer failing entries
class TestEngineRetries:
    def pending(self, client, n, fail=True):
        put_settings(client, {"retry_attempts": 0, "retry_delay_seconds": 0, "max_batch_size": 10,
                              "processing_batch_delay_seconds": 0})
        if fail:
            client.fake.fail_next = 10_000
        post(client, [f"p{i:02d}.example.com" for i in range(n)])
        client.fake.fail_next = 0
        client.fake.calls.clear()

    def test_panorama_down_one_failed_batch_ends_the_cycle(self, client):
        self.pending(client, 25)
        client.fake.fail_next = 10_000
        r = eng.tick(force=True, drain=True)
        assert len(client.fake.calls) == 10                                  # one batch, not 25, not repeated
        assert "unavailable" in r["drain"]["ended"]
        assert all(e.status == "pending" for e in entries_of(client).values())   # never approved by an error
        client.fake.calls.clear()
        eng.tick(force=True, drain=True)                                     # the next scheduled cycle: one batch again
        assert len(client.fake.calls) == 10

    def test_an_entry_that_keeps_failing_is_tried_once_per_cycle_and_the_rest_progress(self, client):
        self.pending(client, 12)
        client.fake.fail.add("p03.example.com")
        r = eng.tick(force=True, drain=True)
        assert client.fake.calls.count("p03.example.com") == 1               # not once per batch, not in a loop
        assert len(client.fake.calls) == 12 and r["drain"]["batches"] >= 2
        left = {v for v, e in entries_of(client).items() if e.status == "pending"}
        assert left == {"p03.example.com/"}

    def test_retry_rounds_within_a_cycle_are_bounded_by_the_setting(self, client):
        self.pending(client, 3)
        put_settings(client, {"retry_attempts": 2, "retry_delay_seconds": 0})
        client.fake.fail_next = 10_000
        eng.tick(force=True)
        assert len(client.fake.calls) == 3 * (1 + 2)

    def test_the_loop_waits_for_the_interval_and_is_not_woken_by_failures(self, client, monkeypatch):
        ticks = []

        class S:
            processing_interval_seconds = 0.2
        monkeypatch.setattr("app.engine.get_settings", lambda: S)

        async def go():
            e = ProcessingEngine()
            monkeypatch.setattr(e, "tick", lambda **kw: ticks.append(kw) or {})
            e.start()
            await asyncio.sleep(1.05)
            await e.stop()
        asyncio.run(go())
        assert 3 <= len(ticks) <= 6                                          # periodic, not spinning


# ============================================================ what the admin pages report
class TestAdminBreakdown:
    def seed(self, client):
        apex_policy(client)
        put_settings(client, {"sync_classification_budget": 100, "retry_attempts": 0})
        client.fake.fail.add("pend.example.org")
        sync(client, ["ok1.example.org", "ok2.example.org", "bad1.example.org", "bad2.example.org", "bad3.example.org",
                      "pend.example.org", "*.wild.example.net", "sub.wild.example.net", "sub2.wild.example.net"],
             sync_id="1")

    def test_service_breakdown_distinguishes_each_state(self, client):
        from app import service
        self.seed(client)
        with client.factory() as s:
            (row,) = service.entry_breakdown(s)
        assert row["list_name"] == "default" and row["uploaded"] == 9
        assert row["approved"] == 5 and row["blocked"] == 3 and row["pending"] == 1 and row["unverified"] == 0
        assert row["suppressed"] == 2                     # the two subdomains hidden by the approved wildcard
        assert row["published"] == 3                      # ok1, ok2 and the wildcard itself
        assert row["uploaded"] == row["approved"] + row["blocked"] + row["pending"] + row["unverified"]

    def test_admin_api_and_pages_show_it_with_the_backlog(self, client):
        self.seed(client)
        j = client.get("/v1/admin/edl", headers=KEY_H).json()
        assert j["entries"][0]["pending"] == 1 and j["entries"][0]["suppressed"] == 2
        assert j["processing"]["pending"] == 1 and "engine" in j["processing"]
        login(client)
        for path in ("/admin/settings", "/admin/settings/processing"):
            html = client.get(path).text
            assert "Uploaded" in html and "Approved" in html and "Blocked" in html and "Pending" in html
            assert "Suppressed" in html and "Published" in html
        assert "Entries by state" in client.get("/admin/settings").text
