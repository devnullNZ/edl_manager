"""v2.2.0 end to end: real FastAPI client, mocked Panorama, assertions on the actual published EDL."""
import json
import random

from sqlalchemy import select

from app import __version__
from app.db import EdlSnapshot, Entry
from app.engine import processing_engine as eng
from conftest import KEY, apex_policy, feed, post, put_settings, sync


def lines(client, name="default"):
    r = feed(client, name)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    return r.text.splitlines()


def test_version_is_2_2_0_everywhere(client):
    assert __version__ == "2.2.0"
    assert client.get("/healthz").json()["version"] == "2.2.0"
    spec = client.get("/openapi.json").json()
    assert spec["info"]["version"] == "2.2.0"
    assert "/v1/lists/{name}/sync" in spec["paths"] and "post" in spec["paths"]["/v1/lists/{name}/sync"]
    for path in ("/v1/admin/wildcards", "/v1/admin/wildcards/recheck", "/v1/admin/sync/runs", "/v1/admin/sync/sources"):
        assert path in spec["paths"]


def test_full_story_with_legacy_submission_sync_and_policy_changes(client):
    # 1. legacy endpoint still works exactly as before (apart from the canonical slash)
    out = post(client, ["https://legacy.example.org", "bad.example.net"], source="nightly")
    assert out["summary"] == {"added": 1, "blocked": 1}
    assert lines(client) == ["legacy.example.org/"]

    # 2. a sync adds its own entries next to the legacy ones; the wildcard is excluded by default
    r = sync(client, ["*.corp.example.com", "www.corp.example.com", "legacy.example.org", "tools.example.net/login"],
             sync_id="2026-11-06-001", delete_missing=True)
    assert r["counts"]["blocked_by_policy"] == 1
    assert lines(client) == ["legacy.example.org/", "tools.example.net/login", "www.corp.example.com/"]

    # 3. switch to apex classification: the wildcard is classified (cached/live), approved and suppresses
    apex_policy(client)
    eng.tick(force=True)
    assert lines(client) == ["*.corp.example.com/", "legacy.example.org/", "tools.example.net/login"]
    assert "corp.example.com" in client.fake.calls and "*.corp.example.com" not in client.fake.calls

    # 4. the sync is idempotent under the new policy
    r = sync(client, ["*.corp.example.com", "www.corp.example.com", "legacy.example.org", "tools.example.net/login"],
             sync_id="2026-11-06-002", delete_missing=True)
    assert r["status"] == "no_change" and r["counts"]["suppressed_by_shadowing"] == 1

    # 5. back to exclude: wildcard withdrawn, the subdomain returns, nothing deleted
    put_settings(client, {"wildcard_classification_policy": "exclude"}, confirm=True)
    assert lines(client) == ["legacy.example.org/", "tools.example.net/login", "www.corp.example.com/"]
    with client.factory() as s:
        assert len(s.scalars(select(Entry)).all()) == 5

    # 6. the legacy entry survived every sync (it also has a sync owner now, plus its api owner)
    r = sync(client, ["tools.example.net/login"], sync_id="2026-11-06-003", delete_missing=True)
    assert r["counts"]["removed"] == 3 and r["counts"]["entries_deleted"] == 2 and r["counts"]["kept_other_owners"] == 1
    assert lines(client) == ["legacy.example.org/", "tools.example.net/login"]


def test_rollback_is_a_sync_of_the_previous_desired_state(client):
    apex_policy(client)
    v1 = ["a.example.com", "b.example.com", "*.example.org"]
    v2 = ["a.example.com", "c.example.com"]
    sync(client, v1, sync_id="v1", delete_missing=True)
    good = feed(client).text
    sync(client, v2, sync_id="v2", delete_missing=True)
    assert feed(client).text != good
    sync(client, v1, sync_id="rollback-to-v1", delete_missing=True)
    assert feed(client).text == good


def test_effective_output_is_deterministic_and_stable(client):
    apex_policy(client)
    entries = [f"h{i}.example.org" for i in range(40)] + ["*.wild.example.com", "x.wild.example.com", "example.com", "example.com/p"]
    random.Random(1).shuffle(entries)
    sync(client, entries, sync_id="1")
    first = feed(client)
    body = first.text.splitlines()
    assert body == sorted(body) and len(body) == len(set(body))
    random.Random(2).shuffle(entries)
    r = sync(client, entries, sync_id="2", delete_missing=True)
    assert r["status"] == "no_change"
    second = feed(client)
    assert second.text == first.text and second.headers["etag"] == first.headers["etag"]
    assert second.headers["last-modified"] == first.headers["last-modified"]          # not regenerated
    assert client.get("/edl/default", headers={"If-None-Match": first.headers["etag"]}).status_code == 304


def test_feed_contains_only_validated_approved_enabled_unsuppressed_entries(client):
    apex_policy(client)
    sync(client, ["ok.example.com", "bad.example.net", "*.example.org", "sub.example.org", "off.example.com",
                  "pending.example.com", "*.bad.example.info"], sync_id="1")
    client.post("/v1/admin/entries/enabled", json={"list": "default", "values": ["off.example.com"], "enabled": False},
                headers=KEY)
    with client.factory() as s:               # one entry still awaiting classification
        e = s.scalars(select(Entry).where(Entry.value == "pending.example.com/")).one()
        e.status = "pending"
        s.commit()
    from app import service
    with client.factory() as s:
        service.rebuild_snapshot(s, "default")
    assert lines(client) == ["*.example.org/", "ok.example.com/"]


def test_snapshot_is_not_rewritten_when_the_effective_list_is_unchanged(client):
    apex_policy(client)
    sync(client, ["*.example.com", "a.example.com"], sync_id="1")
    with client.factory() as s:
        before = s.get(EdlSnapshot, "default").generated_at
    sync(client, ["*.example.com", "a.example.com", "b.example.com"], sync_id="2")     # b is suppressed: feed unchanged
    with client.factory() as s:
        assert s.get(EdlSnapshot, "default").generated_at == before
    assert lines(client) == ["*.example.com/"]


def test_mock_panorama_mode_end_to_end(client):
    """The built-in mock Panorama (no real Panorama): category labels in host names drive the outcome."""
    put_settings(client, {"panorama_mode": "mock", "wildcard_classification_policy": "apex-classification"}, confirm=True)
    r = sync(client, ["fine.example.com", "cat-malware.example.net", "*.cat-phishing.example.org", "*.safe.example.org",
                      "www.safe.example.org", "cat-error.example.io"], sync_id="1")
    by = {e["entry"]: e for e in r["entries"]}
    assert by["cat-malware.example.net/"]["status"] == "blocked"
    assert by["*.cat-phishing.example.org/"]["status"] == "blocked"                    # the apex has a high-risk label
    assert by["*.safe.example.org/"]["status"] == "active"
    assert by["cat-error.example.io/"]["status"] == "pending"                          # simulated outage -> not approval
    assert lines(client) == ["*.safe.example.org/", "fine.example.com/"]
    assert r["counts"]["processing_errors"] == 1


def test_legacy_endpoint_contract_is_unchanged(client):
    out = post(client, ["example.com", "example.com", "not a url!", "*.com"])
    assert out["summary"] == {"added": 1, "duplicate": 1, "invalid": 2}
    r = client.get("/v1/lists/default/entries", headers=KEY).json()
    assert r["total"] == 1 and r["entries"][0]["value"] == "example.com/"
    assert {"value", "status", "detail", "source", "created_at", "checked_at", "published", "shadowed_by"} <= set(r["entries"][0])
    assert client.post("/v1/lists/default/recheck", headers=KEY).json() == {"checked": 1, "changed": 0}
    assert client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["example.com"]}, headers=KEY).json() == {"deleted": 1}
    assert client.post("/v1/lists/default/entries", json={"urls": ["x.com"]}).status_code == 401


def test_sync_and_legacy_agree_on_what_a_duplicate_is(client):
    post(client, ["https://Example.com"])
    r = sync(client, ["example.com/"])
    assert r["counts"]["existing"] == 1 and r["counts"]["new"] == 0 and r["counts"]["ownership_added"] == 1


def test_sync_report_is_json_serialisable_and_stored(client):
    apex_policy(client)
    r = sync(client, ["*.example.com", "www.example.com"], sync_id="stored-1")
    stored = client.get(f"/v1/admin/sync/runs/{r['run_id']}", headers=KEY).json()
    assert stored["report"]["counts"] == r["counts"] and json.dumps(stored)
