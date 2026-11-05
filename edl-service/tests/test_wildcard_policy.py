"""Wildcard classification policy."""
from sqlalchemy import select

from app import service
from app.db import Entry
from app.panorama import lookup_target
from conftest import KEY, apex_policy, feed, post, put_settings


def entry(client, value):
    with client.factory() as s:
        e = s.scalars(select(Entry).where(Entry.value == value)).one()
        return e.status, e.detail


def test_default_policy_is_conservative(client):
    from app.config import get_settings
    assert get_settings().wildcard_classification_policy == "exclude"


def test_exclude_policy_never_publishes_wildcards_and_makes_no_lookup(client):
    n = len(client.fake.calls)
    out = post(client, ["*.example.com", "example.com"])
    by = {r["url"]: r for r in out["results"]}
    assert by["*.example.com"]["status"] == "blocked"
    assert "cannot vouch for every subdomain" in by["*.example.com"]["detail"]
    assert by["example.com"]["status"] == "added"
    assert feed(client).text.splitlines() == ["example.com"]
    assert client.fake.calls[n:] == ["example.com"]           # no query for the wildcard


def test_exclude_policy_even_when_apex_is_clean_and_subdomain_is_not(client):
    # apex 'example.com' is clean but bad.example.com is malware: the apex answer proves nothing
    post(client, ["*.example.com"])
    assert feed(client).text == ""


def test_apex_policy_classifies_base_domain_only_and_says_so(client):
    apex_policy(client)
    n = len(client.fake.calls)
    out = post(client, ["*.example.com"])
    assert client.fake.calls[n:] == ["example.com"]
    assert out["results"][0]["status"] == "added"
    status, detail = entry(client, "*.example.com")
    assert status == "active" and "NOT verified" in detail
    assert feed(client).text.splitlines() == ["*.example.com"]


def test_apex_policy_blocks_wildcard_when_base_domain_is_high_risk(client):
    apex_policy(client)
    out = post(client, ["*.bad.example.net"])
    assert out["results"][0]["status"] == "blocked"
    assert "base domain" in entry(client, "*.bad.example.net")[1]


def test_ordinary_urls_unchanged_by_policy(client):
    for policy in ("exclude", "apex-classification"):
        put_settings(client, {"wildcard_classification_policy": policy}, confirm=True)
        out = post(client, [f"{policy[:3]}-ok.example.com", f"bad.{policy[:3]}.net", f"{policy[:3]}.example.org/path"])
        assert [r["status"] for r in out["results"]] == ["added", "blocked", "added"]


def test_switching_to_exclude_removes_published_wildcards_immediately(client):
    apex_policy(client)
    post(client, ["*.example.com", "plain.example.org"])
    assert "*.example.com" in feed(client).text
    r = client.put("/v1/admin/settings", json={"values": {"wildcard_classification_policy": "exclude"}}, headers=KEY)
    assert r.status_code == 409 and "Wildcard" in r.json()["detail"]["requires_confirmation"][0]
    put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)
    assert feed(client).text.splitlines() == ["plain.example.org"]
    status, detail = entry(client, "*.example.com")                  # row kept, reason recorded
    assert status == "blocked" and "wildcard excluded by policy" in detail


def test_switching_back_to_apex_requeues_wildcards_for_classification(client):
    post(client, ["*.example.com"])
    assert entry(client, "*.example.com")[0] == "blocked"
    apex_policy(client)
    from app.engine import processing_engine as eng
    eng.tick(force=True)
    assert entry(client, "*.example.com")[0] == "active"
    assert feed(client).text.splitlines() == ["*.example.com"]


def test_lookup_target_documents_apex_proxy():
    assert lookup_target("*.example.com") == "example.com"
    assert lookup_target("*.example.com/p") == "example.com/p"
    assert lookup_target("a.example.com") == "a.example.com"


def test_ui_and_api_explain_the_limitation(client):
    sec = client.get("/v1/admin/settings/classification", headers=KEY).json()
    item = next(x for x in sec["settings"] if x["key"] == "wildcard_classification_policy")
    assert item["choices"] == ["exclude", "apex-classification"] and item["value"] == "exclude"
    assert "does NOT prove" in item["description"] and "subdomain" in item["description"]


def test_classification_disabled_publishes_wildcards_only_when_apex_policy_is_explicit(client):
    # v2.1.1: with the default 'exclude' policy a wildcard is never published, even with classification
    # off (see test_v211.py). Publishing it requires explicitly choosing apex-classification.
    put_settings(client, {"classification_enabled": False}, confirm=True)
    apex_policy(client)
    post(client, ["*.example.com"])
    assert feed(client).text.splitlines() == ["*.example.com"]


def test_recheck_keeps_policy(client):
    post(client, ["*.example.com"])
    client.post("/v1/lists/default/recheck", headers=KEY)
    assert feed(client).text == ""
