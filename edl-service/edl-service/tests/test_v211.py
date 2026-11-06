"""v2.1.1 regression tests: wildcard exclusion independent of Panorama, length validation,
rate-limiter memory management, version."""
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import __version__, hosts, ratelimit, service
from app.config import get_settings
from app.db import AppSetting, Entry
from app.engine import processing_engine as eng
from app.normalize import MAX_ENTRY_LENGTH, EntryTooLong, normalize
from conftest import KEY, apex_policy, bearer, feed, login, post, put_settings, ui_post


def canon(value):
    """The stored (canonical) form; public-suffix wildcards (legacy data only) just gain the slash."""
    try:
        return normalize(value)
    except ValueError:
        return value if "/" in value else value + "/"


def row(client, value):
    with client.factory() as s:
        e = s.scalars(select(Entry).where(Entry.value == canon(value))).one()
        return e.status, e.detail


def count(client):
    with client.factory() as s:
        return s.scalar(select(func.count()).select_from(Entry))


def no_classification(client):
    put_settings(client, {"classification_enabled": False}, confirm=True)


def add_raw(client, value, status="active"):
    """A stored entry as an earlier version could have left it."""
    with client.factory() as s:
        s.add(Entry(list_name="default", value=canon(value), status=status))
        s.commit()
        service.rebuild_snapshot(s, "default")


# =========================================================================== 1. wildcard exclusion
class TestWildcardExclusionIndependentOfPanorama:
    def test_1_submission_classification_enabled_policy_exclude(self, client):
        out = post(client, ["*.example.com", "plain.example.com"])
        assert out["results"][0]["status"] == "blocked"
        assert row(client, "*.example.com")[0] == "blocked"
        assert "wildcard excluded by policy" in row(client, "*.example.com")[1]
        assert feed(client).text.splitlines() == ["plain.example.com/"]

    def test_2_submission_classification_disabled_policy_exclude(self, client):
        no_classification(client)
        assert get_settings().classification_enabled is False
        assert get_settings().wildcard_classification_policy == "exclude"
        out = post(client, ["*.example.com", "*.sub.example.org/path"])
        assert [r["status"] for r in out["results"]] == ["blocked", "blocked"]
        assert row(client, "*.example.com")[0] == "blocked"
        assert row(client, "*.sub.example.org/path")[0] == "blocked"
        assert feed(client).text == ""                                            # nothing published
        assert client.get("/v1/lists/default/entries?status=active", headers=KEY).json()["total"] == 0

    def test_3_existing_active_wildcard_policy_changes_to_exclude_with_classification_disabled(self, client):
        no_classification(client)
        apex_policy(client)
        post(client, ["*.example.com", "ok.example.net"])
        assert row(client, "*.example.com")[0] == "pending"                       # v2.2.0: not published unclassified
        assert feed(client).text.splitlines() == ["ok.example.net/"]

        r = client.put("/v1/admin/settings", json={"values": {"wildcard_classification_policy": "exclude"}}, headers=KEY)
        assert r.status_code == 409                                               # still a confirmed change
        put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)

        assert row(client, "*.example.com")[0] == "blocked"                       # re-statused...
        assert count(client) == 2                                                  # ...never deleted
        assert feed(client).text.splitlines() == ["ok.example.net/"]               # immediately gone from the snapshot

    def test_3b_same_with_classification_enabled(self, client):
        apex_policy(client)
        post(client, ["*.example.com"])
        assert feed(client).text.splitlines() == ["*.example.com/"]
        put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)
        assert feed(client).text == "" and row(client, "*.example.com/")[0] == "blocked"

    @pytest.mark.parametrize("enabled", [True, False])
    def test_4_existing_wildcard_during_reclassification_is_not_revived(self, client, enabled):
        if not enabled:
            no_classification(client)
        add_raw(client, "*.example.com", "active")                                # as left by v2.1.0's defect
        add_raw(client, "ok.example.com", "active")
        for run in (lambda: client.post("/v1/lists/default/recheck", headers=KEY),
                    lambda: eng.tick(force=True, reclassify=True, refresh=True),
                    lambda: eng.tick(force=True, reclassify=True)):
            run()
            assert row(client, "*.example.com")[0] == "blocked", run
            assert feed(client).text.splitlines() == ["ok.example.com/"], run

    def test_4b_blocked_wildcard_stays_blocked_after_classification_is_switched_off_and_rechecked(self, client):
        post(client, ["*.example.com"])
        assert row(client, "*.example.com")[0] == "blocked"
        no_classification(client)
        client.post("/v1/lists/default/recheck", headers=KEY)
        assert row(client, "*.example.com/")[0] == "blocked" and feed(client).text == ""

    def test_5_ordinary_domains_when_classification_disabled(self, client):
        no_classification(client)
        n = len(client.fake.calls)
        out = post(client, ["bad.evil.net", "x.example.com", "example.com", "y.example.org/path"])
        assert {r["status"] for r in out["results"]} == {"added"}
        assert len(client.fake.calls) == n                                         # Panorama never consulted
        assert feed(client).text.splitlines() == ["bad.evil.net/", "example.com/", "x.example.com/", "y.example.org/path"]
        assert {row(client, v)[0] for v in ("bad.evil.net", "x.example.com", "example.com")} == {"active"}

    def test_5b_apex_and_wildcard_listed_together_only_apex_published(self, client):
        no_classification(client)
        post(client, ["example.com", "*.example.com"])
        assert feed(client).text.splitlines() == ["example.com/"]

    def test_6_submission_policy_apex_classification(self, client):
        apex_policy(client)
        out = post(client, ["*.example.com", "*.bad.example.net"])
        assert [r["status"] for r in out["results"]] == ["added", "blocked"]
        status, detail = row(client, "*.example.com")
        assert status == "active" and "NOT verified" in detail
        assert row(client, "*.bad.example.net")[0] == "blocked"
        assert feed(client).text.splitlines() == ["*.example.com/"]

    def test_6b_apex_policy_with_classification_disabled_stays_pending(self, client):
        # v2.2.0 (changed from v2.1.1, which published here): apex classification is required by this
        # policy, so a wildcard is never published while classification is switched off.
        no_classification(client)
        apex_policy(client)
        n = len(client.fake.calls)
        out = post(client, ["*.example.com"])
        assert len(client.fake.calls) == n
        assert out["results"][0]["status"] == "pending"
        assert row(client, "*.example.com/")[0] == "pending" and feed(client).text == ""

    def test_switching_back_to_apex_with_classification_disabled_stays_pending(self, client):
        # v2.2.0: this policy requires the base domain to be classified, so with classification off the
        # wildcard is released from the exclusion but is NOT published (it was published in v2.1.1).
        no_classification(client)
        post(client, ["*.example.com"])
        apex_policy(client)
        eng.tick(force=True)
        assert row(client, "*.example.com/")[0] == "pending" and feed(client).text == ""

    def test_pending_and_unverified_wildcards_are_excluded_too(self, client):
        no_classification(client)
        add_raw(client, "*.a.example.com", "pending")
        add_raw(client, "*.b.example.com", "unverified")
        with client.factory() as s:
            service.reconcile_wildcards(s)
        assert row(client, "*.a.example.com")[0] == "blocked" and row(client, "*.b.example.com")[0] == "blocked"
        eng.tick(force=True)
        assert feed(client).text == ""

    def test_upgrade_from_v210_defect_state(self, client):
        """v2.1.0 with classification off and policy exclude had published wildcards."""
        no_classification(client)
        add_raw(client, "*.example.com", "active")
        add_raw(client, "keep.example.com", "active")
        assert "*.example.com/" in feed(client).text
        client.main.init_app(client.engine, client.factory)                       # start the new version
        assert row(client, "*.example.com")[0] == "blocked" and count(client) == 2
        assert feed(client).text.splitlines() == ["keep.example.com/"]

    def test_public_suffix_wildcard_still_blocked_when_classification_disabled(self, client):
        no_classification(client)
        apex_policy(client)
        add_raw(client, "*.com", "active")
        client.post("/v1/lists/default/recheck", headers=KEY)
        assert row(client, "*.com")[0] == "blocked"


# =========================================================================== 2. URL length
def url_of_length(n: int) -> str:
    base = "long.example.com/"
    return base + "p" * (n - len(base))


class TestUrlLength:
    def test_normalize_boundary(self):
        assert len(normalize(url_of_length(2048))) == 2048
        with pytest.raises(EntryTooLong) as e:
            normalize(url_of_length(2049))
        assert e.value.length == 2049 and "2048" in str(e.value)
        assert MAX_ENTRY_LENGTH == 2048

    def test_exactly_2048_is_accepted_and_published(self, client):
        u = url_of_length(2048)
        out = post(client, [u])
        assert out["results"][0]["status"] == "added"
        assert feed(client).text.strip() == u

    def test_2049_is_rejected_with_422_and_nothing_stored(self, client):
        r = client.post("/v1/lists/default/entries", json={"urls": [url_of_length(2049)]}, headers=bearer(client.token))
        assert r.status_code == 422
        err = r.json()["detail"]["errors"]
        assert len(err) == 1 and "urls[0]" in err[0] and "2049" in err[0] and "2048" in err[0]
        assert count(client) == 0 and feed(client).text == ""

    def test_batch_with_valid_and_overlong_is_all_or_nothing(self, client):
        batch = ["good1.example.com", url_of_length(2049), "good2.example.com", url_of_length(3000), "not a url!"]
        r = client.post("/v1/lists/default/entries", json={"urls": batch}, headers=bearer(client.token))
        assert r.status_code == 422
        assert [e.split(":")[0] for e in r.json()["detail"]["errors"]] == ["urls[1]", "urls[3]"]   # all offenders listed
        assert count(client) == 0                                                 # the valid ones were NOT stored either
        assert feed(client).text == ""
        assert client.fake.calls == []                                            # and Panorama was not asked

    def test_other_invalid_urls_keep_per_url_behaviour(self, client):
        out = post(client, ["good.example.com", "not a url!", "*.com"])
        assert {r["url"]: r["status"] for r in out["results"]} == {"good.example.com": "added",
                                                                    "not a url!": "invalid", "*.com": "invalid"}

    def test_length_is_measured_after_normalisation(self, client):
        raw = "HTTPS://user:pw@Long.Example.com/path?" + "q=1&" * 2000 + "#frag"
        assert len(raw) > 2048
        out = post(client, [raw])
        assert out["results"][0]["status"] == "added" and out["results"][0]["value"] == "long.example.com/path"

    def test_absurd_raw_input_rejected_by_schema(self, client):
        r = client.post("/v1/lists/default/entries", json={"urls": ["a.example.com/" + "x" * 70000]},
                        headers=bearer(client.token))
        assert r.status_code == 422 and count(client) == 0

    def test_delete_route_validates_too(self, client):
        post(client, ["keep.example.com"])
        r = client.request("DELETE", "/v1/lists/default/entries",
                           json={"urls": ["keep.example.com", url_of_length(2049)]}, headers=KEY)
        assert r.status_code == 422 and "urls[1]" in r.json()["detail"]["errors"][0]
        assert feed(client).text.splitlines() == ["keep.example.com/"]            # nothing was deleted
        ok = client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["keep.example.com"]}, headers=KEY)
        assert ok.json() == {"deleted": 1}

    def test_every_submission_path_goes_through_the_same_check(self, client):
        with client.factory() as s:
            with pytest.raises(service.SubmissionError):
                service.add_urls(s, "default", [url_of_length(2049)], "src")
            with pytest.raises(service.SubmissionError):
                service.remove_urls(s, "default", [url_of_length(2049)])
        assert count(client) == 0

    def test_anonymous_submission_mode_validates_too(self, client):
        put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
        r = client.post("/v1/lists/default/entries", json={"urls": [url_of_length(2049)]})
        assert r.status_code == 422 and count(client) == 0

    def test_error_body_is_json_with_errors_list(self, client):
        r = client.post("/v1/lists/default/entries", json={"urls": [url_of_length(2050)]}, headers=bearer(client.token))
        assert r.headers["content-type"].startswith("application/json")
        assert isinstance(r.json()["detail"]["errors"], list)


# =========================================================================== 3. source length
def make_host(client, name, addresses="10.0.0.0/24"):
    with client.factory() as s:
        _, token = hosts.create_host(s, name, addresses, "*")
    return token


def submit(client, token, urls, source=None):
    body = {"urls": urls}
    if source is not None:
        body["source"] = source
    return client.post("/v1/lists/default/entries", json=body, headers=bearer(token))


def stored_sources(client):
    with client.factory() as s:
        return sorted(x for x in s.scalars(select(Entry.source)))


class TestSourceLength:
    def test_existing_attribution_format_unchanged(self, client):
        assert submit(client, client.token, ["a.example.com"], "ticket-1").status_code == 200
        assert submit(client, client.token, ["b.example.com"]).status_code == 200
        assert stored_sources(client) == ["ticketing", "ticketing:ticket-1"]

    def test_exactly_128_characters_is_accepted(self, client):
        host = "h" * 27
        token = make_host(client, host)
        src = "s" * 100                                                           # 27 + 1 + 100 = 128
        r = submit(client, token, ["a.example.com"], src)
        assert r.status_code == 200
        assert stored_sources(client) == [f"{host}:{src}"] and len(stored_sources(client)[0]) == 128

    def test_129_characters_is_rejected_not_truncated(self, client):
        host = "h" * 28
        token = make_host(client, host)
        r = submit(client, token, ["a.example.com"], "s" * 100)                    # 28 + 1 + 100 = 129
        assert r.status_code == 422
        err = r.json()["detail"]["errors"][0]
        assert "129" in err and "128" in err and "source" in err
        assert count(client) == 0 and feed(client).text == ""

    def test_maximum_length_host_identifier_with_source(self, client):
        host = "H" * 64                                                             # longest host name
        token = make_host(client, host)
        ok = submit(client, token, ["a.example.com"], "s" * 63)                     # 64 + 1 + 63 = 128
        assert ok.status_code == 200
        bad = submit(client, token, ["b.example.com"], "s" * 64)                    # 129
        assert bad.status_code == 422
        assert submit(client, token, ["c.example.com"]).status_code == 200          # host alone is fine (64)
        assert stored_sources(client) == [host, host + ":" + "s" * 63]

    def test_batch_with_invalid_source_metadata_stores_nothing(self, client):
        token = make_host(client, "h" * 64)
        r = submit(client, token, ["a.example.com", "b.example.com", "c.example.com"], "s" * 100)
        assert r.status_code == 422
        assert count(client) == 0 and feed(client).text == "" and client.fake.calls == []

    def test_source_and_url_errors_reported_together(self, client):
        token = make_host(client, "h" * 64)
        r = submit(client, token, ["a.example.com", url_of_length(2049)], "s" * 100)
        assert r.status_code == 422 and len(r.json()["detail"]["errors"]) == 2 and count(client) == 0

    def test_anonymous_mode_source(self, client):
        put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
        r = client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"], "source": "x" * 100})
        assert r.status_code == 200 and stored_sources(client) == ["anonymous:" + "x" * 100]

    def test_schema_still_caps_supplied_source_at_100(self, client):
        assert submit(client, client.token, ["a.example.com"], "x" * 101).status_code == 422

    def test_service_level_check(self, client):
        with client.factory() as s:
            with pytest.raises(service.SubmissionError, match="129"):
                service.add_urls(s, "default", ["a.example.com"], "x" * 129)
        assert count(client) == 0

    def test_failed_validation_does_not_consume_a_rate_limit_slot_incorrectly_or_leak_entries(self, client):
        token = make_host(client, "h" * 64)
        for _ in range(3):
            assert submit(client, token, ["a.example.com"], "s" * 100).status_code == 422
        assert count(client) == 0


# =========================================================================== 4. rate limiter memory
class Clock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(ratelimit, "time", SimpleNamespace(monotonic=c.monotonic))
    return c


class TestSlidingWindow:
    def test_expired_entries_and_empty_keys_are_removed(self, clock):
        w = ratelimit.SlidingWindow()
        for i in range(100):
            assert w.hit(f"10.0.{i // 250}.{i % 250}", 5, 60) == 0
        assert len(w) == 100
        clock.t += 61
        assert w.peek("10.9.9.9", 5, 60) == 0                      # any call triggers an opportunistic sweep
        assert len(w) == 0

    def test_peek_does_not_create_entries(self, clock):
        w = ratelimit.SlidingWindow()
        for i in range(500):
            assert w.peek(f"ip{i}", 5, 60) == 0
        assert len(w) == 0

    def test_a_key_is_deleted_as_soon_as_its_own_window_expires(self, clock):
        w = ratelimit.SlidingWindow()
        w.hit("a", 3, 60)
        clock.t += 61
        assert w.hit("b", 3, 60) == 0
        assert "a" not in w._hits and len(w) == 1

    def test_rate_limiting_works_after_cleanup(self, clock):
        w = ratelimit.SlidingWindow()
        assert [w.hit("ip", 2, 60) for _ in range(3)][:2] == [0, 0]
        assert w.hit("ip", 2, 60) > 0
        clock.t += 61
        assert w.hit("other", 2, 60) == 0                           # sweep removes expired "ip"
        assert "ip" not in w._hits
        assert w.hit("ip", 2, 60) == 0 and w.hit("ip", 2, 60) == 0 and w.hit("ip", 2, 60) > 0

    def test_different_addresses_are_independent(self, clock):
        w = ratelimit.SlidingWindow()
        assert w.hit("1.1.1.1", 1, 60) == 0 and w.hit("1.1.1.1", 1, 60) > 0
        assert w.hit("2.2.2.2", 1, 60) == 0 and w.hit("2.2.2.2", 1, 60) > 0
        assert w.peek("3.3.3.3", 1, 60) == 0

    def test_cleanup_does_not_reset_an_active_window(self, clock):
        w = ratelimit.SlidingWindow(sweep_interval=0)               # sweep on every call
        w.hit("busy", 2, 100)
        clock.t += 40
        w.hit("busy", 2, 100)
        for i in range(50):                                          # lots of unrelated traffic and sweeps
            w.hit(f"noise{i}", 5, 100)
        clock.t += 40                                                 # t=80: both hits still inside the window
        assert w.hit("busy", 2, 100) > 0
        clock.t += 21                                                 # t=101: first hit expired, second still counts
        assert w.hit("busy", 2, 100) == 0
        assert w.hit("busy", 2, 100) > 0

    def test_different_windows_per_key_are_respected_by_the_sweep(self, clock):
        w = ratelimit.SlidingWindow(sweep_interval=0)
        w.hit("short", 1, 10)
        w.hit("long", 1, 1000)
        clock.t += 50
        w.peek("x", 1, 10)
        assert "short" not in w._hits and "long" in w._hits and w.hit("long", 1, 1000) > 0

    def test_sweep_is_opportunistic_not_every_call(self, clock):
        w = ratelimit.SlidingWindow(sweep_interval=30)
        w.hit("a", 1, 5)
        clock.t += 6
        w.peek("zzz", 1, 5)                                           # < 30s since last sweep: no global sweep...
        assert "a" in w._hits                                          # ...the expired key is only removed when touched
        clock.t += 30
        w.peek("zzz", 1, 5)
        assert "a" not in w._hits

    def test_hard_bound_evicts_least_recently_active(self, clock):
        w = ratelimit.SlidingWindow(max_keys=10, sweep_interval=1000)
        for i in range(25):
            clock.t += 1
            w.hit(f"ip{i}", 1, 10_000)
        assert len(w) <= 11
        assert "ip24" in w._hits and "ip0" not in w._hits

    def test_discard_and_clear(self, clock):
        w = ratelimit.SlidingWindow()
        w.hit("a", 1, 60)
        w.hit("b", 1, 60)
        w.discard("a")
        assert list(w._hits) == ["b"] and not w._window.get("a")
        w.clear()
        assert len(w) == 0

    def test_zero_limit_means_unlimited_and_tracks_nothing(self, clock):
        w = ratelimit.SlidingWindow()
        assert all(w.hit("x", 0, 60) == 0 for _ in range(10)) and len(w) == 0

    def test_concurrent_requests_cannot_bypass_limit_even_with_constant_cleanup(self):
        w = ratelimit.SlidingWindow(sweep_interval=0)               # a full sweep on every call
        allowed, lock = [], threading.Lock()

        def worker(n):
            for i in range(50):
                w.hit(f"noise-{n}-{i}", 1, 60)                        # churn that triggers cleanup/eviction
                if w.hit("target", 40, 60) == 0:
                    with lock:
                        allowed.append(1)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert len(allowed) == 40       # exactly the limit: cleanup never shortened or reset the window

    def test_ipv6_addresses_share_one_key_per_64(self):
        k = ratelimit.source_key
        assert k("2001:db8:1:2:aaaa::1") == k("2001:db8:1:2:bbbb:cccc:dddd:eeee") == "2001:db8:1:2::/64"
        assert k("2001:db8:1:3::1") != k("2001:db8:1:2::1")
        assert k("::ffff:10.0.0.7") == "10.0.0.7" == k("10.0.0.7")
        assert k(None) == "unknown" and k("not-an-ip") == "not-an-ip"

    def test_one_ipv6_subscriber_cannot_mint_unlimited_identities(self, client):
        ratelimit.reset()
        for i in range(25):
            TestClient(client.main.app, client=(f"2001:db8:aaaa:bbbb::{i + 1:x}", 1)).post(
                "/v1/lists/default/entries", json={"urls": ["a.com"]}, headers=bearer("bad"))
        assert ratelimit.tracked_keys() == 1
        blocked = TestClient(client.main.app, client=("2001:db8:aaaa:bbbb::ffff", 1)).post(
            "/v1/lists/default/entries", json={"urls": ["a.com"]}, headers=bearer("bad"))
        assert blocked.status_code == 429

    def test_default_module_functions_still_work(self, clock):
        ratelimit.reset()
        assert ratelimit.hit("k", 1, 60) == 0 and ratelimit.hit("k", 1, 60) > 0
        assert ratelimit.peek("k", 1, 60) > 0 and ratelimit.tracked_keys() == 1
        clock.t += 61
        ratelimit.peek("other", 1, 60)
        assert ratelimit.tracked_keys() == 0


class TestTrackersUseCleanup:
    def test_host_failed_auth_tracking_is_cleaned(self, client, clock):
        ratelimit.reset()
        for i in range(30):
            other = TestClient(client.main.app, client=(f"192.0.2.{i + 1}", 1))
            assert other.post("/v1/lists/default/entries", json={"urls": ["a.com"]},
                              headers=bearer("bad-token")).status_code == 401
        assert ratelimit.tracked_keys() == 30
        clock.t += 61                                                 # AUTH_FAIL_WINDOW is 60
        TestClient(client.main.app, client=("10.0.0.5", 1)).post(
            "/v1/lists/default/entries", json={"urls": ["a.com"]}, headers=bearer(client.token))
        assert [k for k in ratelimit._default._hits if k.startswith("authfail:")] == []

    def test_requests_that_only_peek_leave_no_residue(self, client):
        ratelimit.reset()
        for i in range(40):
            TestClient(client.main.app, client=(f"198.51.100.{i + 1}", 1)).post(
                "/v1/lists/default/entries", json={"urls": ["a.com"]})        # no token: counts as a failure
        assert ratelimit.tracked_keys() == 40                                  # one key per offender, bounded by sources

    def test_valid_host_traffic_expires(self, client, clock):
        ratelimit.reset()
        assert client.post("/v1/lists/default/entries", json={"urls": ["a.com"]}, headers=bearer(client.token)).status_code == 200
        assert any(k.startswith("host:") for k in ratelimit._default._hits)
        clock.t += 61
        ratelimit.peek("x", 1, 1)
        assert not any(k.startswith("host:") for k in ratelimit._default._hits)

    def test_admin_login_failures_are_tracked_cleaned_and_throttled(self, client, clock):
        from app import admin
        admin._FAILS.clear()
        for _ in range(5):
            assert client.post("/admin/login", data={"csrf_token": "x", "username": "admin", "password": "bad"}).status_code in (401, 403)
        # CSRF-less posts are refused earlier; use proper login helper for real failures
        from conftest import csrf
        admin._FAILS.clear()
        codes = []
        for _ in range(7):
            r = client.post("/admin/login", data={"csrf_token": csrf(client), "username": "admin", "password": "nope"})
            codes.append(r.status_code)
        assert codes[:5] == [401] * 5 and set(codes[5:]) <= {429, 401}
        assert len(admin._FAILS) == 1                                  # one source -> one key
        clock.t += admin._WINDOW + 1
        admin._FAILS.peek("zzz", 5, 300)
        assert len(admin._FAILS) == 0                                  # expired + empty entry removed
        assert login(client).status_code == 303                       # and the source can sign in again

    def test_successful_login_clears_failure_record(self, client):
        from app import admin
        from conftest import csrf
        admin._FAILS.clear()
        client.post("/admin/login", data={"csrf_token": csrf(client), "username": "admin", "password": "nope"})
        assert len(admin._FAILS) == 1
        assert login(client).status_code == 303
        assert len(admin._FAILS) == 0

    def test_admin_login_sources_are_independent(self, client):
        from app import admin
        from conftest import csrf
        admin._FAILS.clear()
        for _ in range(5):
            client.post("/admin/login", data={"csrf_token": csrf(client), "username": "admin", "password": "nope"})
        other = TestClient(client.main.app, client=("203.0.113.9", 1))
        assert login(other).status_code == 303                          # a different address is not throttled


# =========================================================================== 5. version
class TestVersion:
    def test_version_constant(self):
        assert __version__ == "2.2.0"

    def test_openapi_reports_current_version(self, client):
        assert client.main.app.version == "2.2.0"
        assert client.main.app.openapi()["info"]["version"] == "2.2.0"
        assert client.get("/openapi.json").json()["info"]["version"] == "2.2.0"

    def test_healthz_reports_version(self, client):
        assert client.get("/healthz").json()["version"] == "2.2.0"

    def test_documentation_identifies_the_release(self):
        readme = Path(__file__).resolve().parent.parent.joinpath("README.md").read_text()
        assert "2.2.0" in readme.split("\n## ", 1)[0] and "Upgrading from v2.1.0" in readme and "Upgrading from v2.1.1" in readme

    def test_no_stale_version_strings(self):
        for p in Path(__file__).resolve().parent.parent.joinpath("app").glob("*.py"):
            assert 'version="2.0.0"' not in p.read_text() and 'version="2.1.0"' not in p.read_text(), p


# =========================================================================== 7. compatibility
class TestCompatibility:
    def test_no_schema_changes_needed_from_v210(self, client):
        from app import migrations
        assert migrations.run_migrations(client.engine) == []

    def test_existing_endpoints_still_present(self, client):
        paths = set(client.main.app.openapi()["paths"])
        assert {"/healthz", "/edl/{name}", "/v1/lists/{name}/entries", "/v1/lists/{name}/recheck",
                "/v1/admin/settings", "/v1/admin/settings/{section}", "/v1/admin/panorama/test-connection",
                "/v1/admin/audit", "/v1/admin/edl"} <= paths

    def test_compose_and_dockerfile_keep_volumes_and_env(self):
        root = Path(__file__).resolve().parent.parent
        compose = root.joinpath("docker-compose.yml").read_text()
        assert "pgdata:/var/lib/postgresql/data" in compose and "postgres:16-alpine" in compose
        assert "DATABASE_URL: postgresql+psycopg://" in compose and "env_file: .env" in compose
        assert "--workers" not in root.joinpath("Dockerfile").read_text()
