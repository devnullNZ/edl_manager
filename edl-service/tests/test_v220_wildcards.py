"""v2.2.0: wildcard classification through the apex domain, and wildcard shadowing/suppression."""
import threading
import time

import pytest
from sqlalchemy import select

from app.db import Entry
from app.engine import processing_engine as eng
from conftest import KEY, apex_policy, feed, post, put_settings


def row(client, value, list_name="default"):
    with client.factory() as s:
        return s.scalars(select(Entry).where(Entry.list_name == list_name, Entry.value == value)).one()


def values(client, list_name="default"):
    with client.factory() as s:
        return {e.value: e for e in s.scalars(select(Entry).where(Entry.list_name == list_name))}


# =========================================================================== classification
class TestApexClassification:
    def test_default_policy_is_exclude_and_makes_no_lookup(self, client):
        out = post(client, ["*.example.com"])
        assert out["results"][0]["status"] == "blocked" and client.fake.calls == []
        e = row(client, "*.example.com/")
        assert e.class_status == "excluded" and e.class_result == "excluded" and e.class_target is None
        assert feed(client).text == ""

    def test_the_apex_is_submitted_never_the_literal_wildcard(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "*.sub.example.org"])
        assert sorted(client.fake.calls) == ["example.com", "sub.example.org"]
        assert not any("*" in c for c in client.fake.calls)

    def test_metadata_is_stored_and_exposed(self, client):
        apex_policy(client)
        post(client, ["*.sub.example.com"])
        e = row(client, "*.sub.example.com/")
        assert (e.status, e.class_status, e.class_method, e.class_target, e.class_result) == \
            ("active", "approved", "wildcard_apex", "sub.example.com", "clean")
        assert e.class_categories == "search-engines" and e.checked_at is not None
        assert "subdomains is NOT verified" in e.detail
        item = client.get("/v1/lists/default/entries", headers=KEY).json()["entries"][0]
        assert item["value"] == "*.sub.example.com/"                      # the original wildcard
        assert item["classification"] == {
            "method": "wildcard_apex", "target": "sub.example.com", "result": "clean",
            "categories": ["search-engines"], "status": "approved", "reason": e.detail,
            "at": item["classification"]["at"]}
        assert feed(client).text == "*.sub.example.com/\n"

    def test_high_risk_apex_blocks_the_wildcard(self, client):
        apex_policy(client)
        out = post(client, ["*.bad.example.net"])
        assert out["results"][0]["status"] == "blocked"
        e = row(client, "*.bad.example.net/")
        assert (e.class_status, e.class_result, e.class_categories) == ("blocked", "blocked", "malware")
        assert "malware" in e.detail and "(base domain)" in e.detail and feed(client).text == ""

    @pytest.mark.parametrize("failure", ["fail", "fail_next"])
    @pytest.mark.parametrize("behaviour", ["fail-closed", "fail-open"])
    def test_unavailable_panorama_leaves_the_wildcard_pending(self, client, failure, behaviour):
        apex_policy(client)
        put_settings(client, {"classification_failure_behaviour": behaviour}, confirm=True)
        if failure == "fail":
            client.fake.fail.add("example.com")
        else:
            client.fake.fail_next = 10_000
        out = post(client, ["*.example.com"])
        assert out["results"][0]["status"] == "pending"                   # fail-open does NOT apply to wildcards
        assert row(client, "*.example.com/").status == "pending" and feed(client).text == ""

    @pytest.mark.parametrize("unknown_behaviour", ["publish", "exclude"])
    def test_inconclusive_result_is_never_approval(self, client, unknown_behaviour):
        apex_policy(client)
        put_settings(client, {"unknown_category_behaviour": unknown_behaviour}, confirm=True)
        client.fake.lookup = lambda t: f"{t} unknown (Cloud db)"
        post(client, ["*.example.com"])
        e = row(client, "*.example.com/")
        assert e.status == "pending" and "inconclusive" in e.detail and feed(client).text == ""

    def test_unparseable_answer_is_not_approval(self, client):
        apex_policy(client)
        client.fake.lookup = lambda t: "<html>captive portal</html>"
        post(client, ["*.example.com"])
        assert row(client, "*.example.com/").status == "pending" and feed(client).text == ""

    def test_pending_wildcard_is_classified_by_the_engine_once_panorama_returns(self, client):
        apex_policy(client)
        client.fake.fail_next = 10_000
        post(client, ["*.example.com"])
        client.fake.fail_next = 0
        eng.tick(force=True)
        assert row(client, "*.example.com/").status == "active" and feed(client).text == "*.example.com/\n"

    def test_classification_disabled_never_publishes_a_wildcard(self, client):
        apex_policy(client)
        put_settings(client, {"classification_enabled": False}, confirm=True)
        out = post(client, ["*.example.com", "plain.example.org"])
        by = {r["value"]: r["status"] for r in out["results"]}
        assert by == {"*.example.com/": "pending", "plain.example.org/": "added"} and client.fake.calls == []
        assert feed(client).text == "plain.example.org/\n"

    def test_identical_apex_is_requested_once_and_then_cached(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "*.example.com/login", "example.com"])
        assert client.fake.calls.count("example.com") == 1
        n = len(client.fake.calls)
        post(client, ["*.example.com/other"])                              # cached apex: no new request
        assert len(client.fake.calls) == n

    def test_lookups_never_exceed_the_concurrency_limit(self, client):
        apex_policy(client)
        active, peak, lock = 0, 0, threading.Lock()
        orig = client.fake.lookup

        def slow(target):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            try:
                return orig(target)
            finally:
                with lock:
                    active -= 1
        client.fake.lookup = slow
        post(client, [f"*.site{i}.example.org" for i in range(40)])
        assert 1 < peak <= 5

    def test_policy_change_to_apex_releases_wildcards_for_classification_without_deleting(self, client):
        post(client, ["*.example.com", "*.bad.example.net", "keep.example.org"])
        assert set(values(client)) == {"*.example.com/", "*.bad.example.net/", "keep.example.org/"}
        apex_policy(client)
        assert {k: v.status for k, v in values(client).items()}["*.example.com/"] in ("pending", "active")
        eng.tick(force=True)
        got = {k: v.status for k, v in values(client).items()}
        assert got == {"*.example.com/": "active", "*.bad.example.net/": "blocked", "keep.example.org/": "active"}
        assert feed(client).text.splitlines() == ["*.example.com/", "keep.example.org/"]

    def test_policy_change_to_exclude_withdraws_wildcards_but_keeps_the_rows_and_metadata_rows(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com", "keep.example.org"])
        assert feed(client).text.splitlines() == ["*.example.com/", "keep.example.org/"]
        put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)
        got = values(client)
        assert len(got) == 3 and got["*.example.com/"].status == "blocked"
        assert got["*.example.com/"].class_status == "excluded"
        assert got["www.example.com/"].suppressed_by is None               # the wildcard no longer suppresses
        assert feed(client).text.splitlines() == ["keep.example.org/", "www.example.com/"]

    def test_blocked_wildcards_are_reevaluated_by_a_wildcard_recheck(self, client):
        apex_policy(client)
        client.fake.lookup = lambda t: f"{t} malware (Cloud db)"
        post(client, ["*.example.com"])
        assert row(client, "*.example.com/").status == "blocked"
        client.fake.lookup = lambda t: f"{t} search-engines (Base db)"      # Panorama's view changed
        r = client.post("/v1/admin/wildcards/recheck", headers=KEY)
        assert r.status_code == 200 and r.json()["changed"] == 1
        assert row(client, "*.example.com/").status == "active" and feed(client).text == "*.example.com/\n"

    def test_wildcard_recheck_only_touches_wildcards_and_deletes_nothing(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "plain.example.org", "*.bad.example.net"])
        client.fake.calls.clear()
        r = client.post("/v1/admin/wildcards/recheck", headers=KEY).json()
        assert r["checked"] == 2 and sorted(client.fake.calls) == ["bad.example.net", "example.com"]
        assert len(values(client)) == 3

    def test_wildcard_recheck_in_an_outage_keeps_decisions(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "*.bad.example.net"])
        put_settings(client, {"retry_delay_seconds": 0})
        client.fake.fail_next = 10_000
        r = client.post("/v1/admin/wildcards/recheck", headers=KEY).json()
        assert r["changed"] == 0
        got = {k: v.status for k, v in values(client).items()}
        assert got == {"*.example.com/": "active", "*.bad.example.net/": "blocked"}
        assert feed(client).text == "*.example.com/\n"                      # an outage never empties or widens the feed

    def test_recheck_of_one_list_only(self, client):
        apex_policy(client)
        post(client, ["*.example.com"], list_name="a")
        post(client, ["*.example.org"], list_name="b")
        client.fake.calls.clear()
        client.post("/v1/admin/wildcards/recheck", json={"list": "a"}, headers=KEY)
        assert client.fake.calls == ["example.com"]


# =========================================================================== shadowing / suppression
class TestSuppression:
    def lines(self, client, name="default"):
        return feed(client, name).text.splitlines()

    def test_strict_domain_boundaries(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com", "mail.example.com", "example.com", "example.com.au",
                      "example.com.evil.net", "notexample.com", "xexample.com/login"])
        assert self.lines(client) == ["*.example.com/", "example.com.au/", "example.com.evil.net/", "example.com/",
                                      "notexample.com/", "xexample.com/login"]
        got = values(client)
        assert got["www.example.com/"].suppressed_by == "*.example.com/"
        assert got["mail.example.com/"].suppressed_by == "*.example.com/"
        for kept in ("example.com/", "example.com.au/", "example.com.evil.net/", "notexample.com/"):
            assert got[kept].suppressed_by is None

    def test_subdomain_wildcard_only_covers_its_own_subtree(self, client):
        apex_policy(client)
        post(client, ["*.sub.example.com", "www.sub.example.com", "www.example.com", "sub.example.com"])
        assert self.lines(client) == ["*.sub.example.com/", "sub.example.com/", "www.example.com/"]

    def test_multi_level(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "*.b.example.com", "a.b.example.com", "x.y.b.example.com"])
        got = values(client)
        assert got["*.b.example.com/"].suppressed_by == "*.example.com/"
        assert got["a.b.example.com/"].suppressed_by == "*.b.example.com/"      # nearest wildcard reported
        assert got["x.y.b.example.com/"].suppressed_by == "*.b.example.com/"
        assert self.lines(client) == ["*.example.com/"]

    def test_apex_is_preserved(self, client):
        apex_policy(client)
        post(client, ["example.com", "*.example.com"])
        assert self.lines(client) == ["*.example.com/", "example.com/"]

    def test_wildcard_with_a_path_only_covers_that_path(self, client):
        apex_policy(client)
        post(client, ["*.example.com/login", "a.example.com/login", "a.example.com/other", "a.example.com/login/"])
        assert self.lines(client) == ["*.example.com/login", "a.example.com/login/", "a.example.com/other"]

    def test_a_wildcard_in_another_list_does_not_suppress(self, client):
        apex_policy(client)
        post(client, ["*.example.com"], list_name="a")
        post(client, ["www.example.com"], list_name="b")
        assert self.lines(client, "b") == ["www.example.com/"]
        assert values(client, "b")["www.example.com/"].suppressed_by is None

    def test_nothing_is_deleted_and_ownership_is_kept(self, client):
        apex_policy(client)
        post(client, ["www.example.com", "mail.example.com"])
        post(client, ["*.example.com"])
        assert len(values(client)) == 3
        item = {e["value"]: e for e in client.get("/v1/lists/default/entries", headers=KEY).json()["entries"]}
        assert item["www.example.com/"]["suppressed_by"] == "*.example.com/" and item["www.example.com/"]["published"] is False
        assert item["www.example.com/"]["owners"][0]["host"] == "ticketing"

    def test_pending_wildcard_does_not_suppress_until_approved(self, client):
        apex_policy(client)
        client.fake.fail_next = 10_000
        post(client, ["*.example.com"])
        client.fake.fail_next = 0
        client.fake.calls.clear()
        post(client, ["www.example.com"])
        assert self.lines(client) == ["www.example.com/"]                        # wildcard pending: no suppression
        assert values(client)["www.example.com/"].suppressed_by is None
        eng.tick(force=True)                                                       # now approved
        assert self.lines(client) == ["*.example.com/"]
        assert values(client)["www.example.com/"].suppressed_by == "*.example.com/"

    def test_blocked_wildcard_does_not_suppress(self, client):
        apex_policy(client)
        post(client, ["*.bad.example.net", "ok.bad.example.net"])
        assert row(client, "*.bad.example.net/").status == "blocked"        # apex 'bad.example.net' is high risk
        assert row(client, "ok.bad.example.net/").suppressed_by is None
        assert self.lines(client) == ["ok.bad.example.net/"]

    def test_excluded_wildcard_does_not_suppress(self, client):
        post(client, ["*.example.com", "www.example.com"])
        assert self.lines(client) == ["www.example.com/"]

    def test_removing_the_wildcard_restores_subdomains_subject_to_their_own_classification(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com", "bad.example.com"])
        assert self.lines(client) == ["*.example.com/"]
        assert row(client, "bad.example.com/").status == "blocked"
        client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["*.example.com"]}, headers=KEY)
        assert self.lines(client) == ["www.example.com/"]                       # restored; the blocked one stays out
        assert all(e.suppressed_by is None for e in values(client).values())

    def test_wildcard_blocked_by_a_later_recheck_releases_subdomains(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com"])
        assert self.lines(client) == ["*.example.com/"]
        client.fake.lookup = lambda t: f"{t} malware (Cloud db)" if t == "example.com" else f"{t} search-engines (Base db)"
        client.post("/v1/admin/wildcards/recheck", headers=KEY)
        assert self.lines(client) == ["www.example.com/"]
        client.fake.lookup = lambda t: f"{t} search-engines (Base db)"
        client.post("/v1/admin/wildcards/recheck", headers=KEY)
        assert self.lines(client) == ["*.example.com/"]

    def test_disabling_a_wildcard_releases_its_subdomains(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com"])
        r = client.post("/v1/admin/entries/enabled", json={"list": "default", "values": ["*.example.com"], "enabled": False},
                        headers=KEY)
        assert r.json() == {"changed": 1} and self.lines(client) == ["www.example.com/"]
        client.post("/v1/admin/entries/enabled", json={"list": "default", "values": ["*.example.com"], "enabled": True}, headers=KEY)
        assert self.lines(client) == ["*.example.com/"]

    def test_public_suffix_lookalikes_never_suppress(self, client):
        apex_policy(client)
        post(client, ["*.example.co.uk", "foo.co.uk", "www.example.co.uk", "example.co.uk"])
        assert self.lines(client) == ["*.example.co.uk/", "example.co.uk/", "foo.co.uk/"]

    def test_max_entries_applies_after_suppression(self, client):
        apex_policy(client)
        put_settings(client, {"edl_max_entries": 2}, confirm=True)
        post(client, ["*.example.com", "a.example.com", "b.example.com", "c.example.org", "d.example.org"])
        assert self.lines(client) == ["*.example.com/", "c.example.org/"]       # oldest two eligible, suppressed ones not counted


class TestPolicyAndAvailabilityTransitions:
    def test_switching_classification_off_withdraws_approved_wildcards_immediately(self, client):
        apex_policy(client)
        post(client, ["*.example.com", "www.example.com", "plain.example.org"])
        assert feed(client).text.splitlines() == ["*.example.com/", "plain.example.org/"]
        put_settings(client, {"classification_enabled": False}, confirm=True)
        got = values(client)
        assert got["*.example.com/"].status == "pending" and len(got) == 3        # re-statused, nothing deleted
        assert got["www.example.com/"].suppressed_by is None                       # a pending wildcard suppresses nothing
        assert feed(client).text.splitlines() == ["plain.example.org/", "www.example.com/"]

    def test_switching_classification_back_on_reapproves_via_the_engine(self, client):
        apex_policy(client)
        post(client, ["*.example.com"])
        put_settings(client, {"classification_enabled": False}, confirm=True)
        put_settings(client, {"classification_enabled": True}, confirm=True)
        eng.tick(force=True)
        assert values(client)["*.example.com/"].status == "active" and feed(client).text == "*.example.com/\n"

    def test_startup_demotes_legacy_unverified_wildcards_under_apex_policy(self, client):
        apex_policy(client)
        with client.factory() as s:
            s.add(Entry(list_name="default", value="*.legacy.example.org/", status="unverified"))
            s.commit()
        client.main.init_app(client.engine, client.factory)
        assert values(client)["*.legacy.example.org/"].status == "pending" and feed(client).text == ""


def test_admin_pages_escape_hostile_entry_text(client):
    from conftest import login
    apex_policy(client)
    r = client.post("/v1/lists/default/sync", json={"source": "<b>src</b>", "sync_id": "x1", "entries": ["<script>alert(1)</script>", "ok.example.com"]},
                    headers={"Authorization": f"Bearer {client.token}"})
    assert r.status_code == 200
    login(client)
    for path in ("/admin/sync", f"/admin/sync/runs/{r.json()['run_id']}", "/admin/audit", "/admin/entries?q=%3Cscript%3E"):
        html = client.get(path).text
        assert "<script>alert(1)" not in html and "<b>src</b>" not in html
