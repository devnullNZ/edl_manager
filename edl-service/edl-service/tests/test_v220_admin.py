"""v2.2.0: admin pages and admin API for wildcards, sync history and entry details."""
import pytest
from sqlalchemy import select

from app.db import AuditLog
from conftest import KEY, apex_policy, bearer, login, post, put_settings, sync, ui_post

PAGES = ["/admin/wildcards", "/admin/sync", "/admin/entries", "/admin/entries?show=wildcards",
         "/admin/entries?show=suppressed&status=active&q=www&list=default"]


@pytest.fixture
def populated(client):
    apex_policy(client)
    post(client, ["manual.example.com"], source="legacy-batch")
    r = sync(client, [{"url": "*.example.com", "yaml_list": "wild"}, "www.example.com", "bad.example.net",
                      "*.bad.example.org", "manual.example.com"], sync_id="run-1", delete_missing=True)
    client.run_id = r["run_id"]
    login(client)
    return client


def test_pages_require_login(client):
    for path in ["/admin/wildcards", "/admin/sync", "/admin/entries", "/admin/sync/runs/1"]:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"
    r = client.post("/admin/wildcards/recheck", follow_redirects=False)
    assert r.status_code in (303, 403)


@pytest.mark.parametrize("path", PAGES)
def test_pages_render(populated, path):
    r = populated.get(path)
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
    assert "<script" not in r.text                                            # still no JavaScript


def test_wildcard_page_shows_policy_and_classification_outcomes(populated):
    html = populated.get("/admin/wildcards").text
    assert "Classify Apex Domain" in html
    assert "<code>*.example.com/</code>" in html and "<code>example.com</code>" in html      # original and apex submitted
    assert "wildcard_apex" in html and "search-engines" in html
    assert "<code>*.bad.example.org/</code>" in html and "malware" in html
    assert "does <strong>not</strong> prove" in html                           # the limitation is stated where it is used
    assert ">2</td>" in html                      # *.example.com suppresses www. and manual.


def test_wildcard_recheck_button(populated):
    populated.fake.calls.clear()
    r = ui_post(populated, "/admin/wildcards/recheck", token_page="/admin/wildcards")
    assert r.status_code == 303 and r.headers["location"] == "/admin/wildcards"
    assert sorted(populated.fake.calls) == ["bad.example.org", "example.com"]
    assert "Wildcard recheck finished" in populated.get("/admin/wildcards").text
    with populated.factory() as s:
        assert s.scalars(select(AuditLog).where(AuditLog.action == "wildcards.recheck")).one().actor


def test_wildcard_recheck_requires_csrf(populated):
    r = populated.post("/admin/wildcards/recheck", data={"csrf_token": "forged"}, follow_redirects=False)
    assert r.status_code == 403
    assert populated.fake.calls.count("example.com") == 1


def test_sync_page_shows_sources_counts_and_history(populated):
    html = populated.get("/admin/sync").text
    assert "ticketing" in html and "yaml-import" in html and "run-1" in html
    assert f'/admin/sync/runs/{populated.run_id}' in html
    sync(populated, ["www.example.com"], sync_id="run-2", delete_missing=True)
    html = populated.get("/admin/sync").text
    assert "run-1" in html and "run-2" in html                                 # previous reports stay visible


def test_sync_errors_are_visible(populated):
    sync(populated, [], sync_id="run-bad", delete_missing=True, expect=422)
    html = populated.get("/admin/sync").text
    assert "failed" in html and "run-bad" in html and "confirm_empty" in html


def test_sync_report_page(populated):
    html = populated.get(f"/admin/sync/runs/{populated.run_id}").text
    assert "<code>*.example.com/</code>" in html and "suppressed by approved wildcard" in html and "added" in html
    assert populated.get("/admin/sync/runs/9999").status_code == 404


def test_entries_page_shows_ownership_classification_and_suppression(populated):
    html = populated.get("/admin/entries?q=www.example").text
    assert "<code>www.example.com/</code>" in html and "suppressed by" in html and "<code>*.example.com/</code>" in html
    assert "ticketing" in html and "yaml-import" in html and "url:" in html
    html = populated.get("/admin/entries?q=manual").text
    assert "legacy-batch" in html and "yaml-import" in html                     # two owners of one entry
    assert "wild" in populated.get("/admin/entries?q=*.example").text          # original YAML list name
    assert "No entries match" in populated.get("/admin/entries?q=nothing-like-this").text


def test_entries_filters(populated):
    assert "www.example.com/" in populated.get("/admin/entries?show=suppressed").text
    assert "www.example.com/" not in populated.get("/admin/entries?show=wildcards").text
    assert "bad.example.net/" in populated.get("/admin/entries?status=blocked").text
    assert "bad.example.net/" not in populated.get("/admin/entries?status=active").text


def test_policy_choices_show_friendly_labels_but_store_the_same_values(populated):
    html = populated.get("/admin/settings/classification").text
    assert ">Exclude</option>" in html and ">Classify Apex Domain</option>" in html
    assert 'value="apex-classification" selected' in html


def test_no_secrets_in_any_page_or_api_response(populated):
    token = populated.token
    blobs = [populated.get(p).text for p in PAGES + [f"/admin/sync/runs/{populated.run_id}", "/admin/audit", "/admin/hosts"]]
    for path in ("/v1/admin/wildcards", "/v1/admin/sync/sources", "/v1/admin/sync/runs", f"/v1/admin/sync/runs/{populated.run_id}",
                 "/v1/admin/entries", "/v1/lists/default/entries", "/v1/admin/audit", "/v1/admin/settings"):
        blobs.append(populated.get(path, headers=KEY).text)
    for blob in blobs:
        assert token not in blob and "token_hash" not in blob and "encryption" not in blob.lower().replace("encryption_key", "")


def test_warning_when_apex_policy_meets_disabled_classification(populated):
    put_settings(populated, {"classification_enabled": False}, confirm=True)
    assert "cannot be approved and stay pending" in populated.get("/admin/settings").text


# =========================================================================== admin API
def test_admin_api_requires_the_management_key(populated):
    for path in ("/v1/admin/wildcards", "/v1/admin/sync/sources", "/v1/admin/sync/runs", "/v1/admin/entries"):
        assert populated.get(path).status_code == 401
        assert populated.get(path, headers=bearer(populated.token)).status_code == 401      # a host token is not enough
    assert populated.post("/v1/admin/wildcards/recheck").status_code == 401


def test_admin_api_wildcards(populated):
    d = populated.get("/v1/admin/wildcards", headers=KEY).json()
    assert d["policy"] == "apex-classification" and d["total"] == 2
    by = {w["wildcard"]: w for w in d["wildcards"]}
    assert by["*.example.com/"]["suppresses"] == 2 and by["*.example.com/"]["classification"]["target"] == "example.com"
    assert by["*.bad.example.org/"]["status"] == "blocked" and by["*.bad.example.org/"]["classification"]["categories"] == ["malware"]
    assert d["summary"] == {"approved": 1, "blocked": 1}


def test_admin_api_sync_sources_and_runs(populated):
    src = populated.get("/v1/admin/sync/sources", headers=KEY).json()["sources"]
    assert len(src) == 1 and src[0]["host"] == "ticketing" and src[0]["source"] == "yaml-import"
    assert src[0]["status"] == "applied" and src[0]["last_sync_id"] == "run-1" and src[0]["counts"]["new"] == 4
    runs = populated.get("/v1/admin/sync/runs?list=default&source=yaml-import", headers=KEY).json()
    assert runs["total"] == 1 and runs["runs"][0]["counts"]["suppressed_by_shadowing"] == 2
    detail = populated.get(f"/v1/admin/sync/runs/{populated.run_id}", headers=KEY).json()
    assert detail["report"]["entries"] and detail["report"]["counts"] == detail["counts"]
    assert populated.get("/v1/admin/sync/runs/9999", headers=KEY).status_code == 404
    assert populated.get("/v1/admin/sync/runs?list=nope", headers=KEY).json()["total"] == 0


def test_admin_api_entries_filters_and_details(populated):
    d = populated.get("/v1/admin/entries?suppressed=true", headers=KEY).json()
    assert [e["value"] for e in d["entries"]] == ["manual.example.com/", "www.example.com/"]
    e = d["entries"][1]
    assert e["suppressed_by"] == "*.example.com/" and e["published"] is False
    assert e["classification"]["method"] == "url" and e["classification"]["target"] == "www.example.com"
    assert e["owners"][0]["kind"] == "sync" and e["owners"][0]["source_last_sync_at"] is not None
    d = populated.get("/v1/admin/entries?wildcard=true&status=active", headers=KEY).json()
    assert [e["value"] for e in d["entries"]] == ["*.example.com/"]
    d = populated.get("/v1/admin/entries?q=manual", headers=KEY).json()
    assert len(d["entries"][0]["owners"]) == 2


def test_admin_api_recheck_validates_input(populated):
    assert populated.post("/v1/admin/wildcards/recheck", json={"bogus": 1}, headers=KEY).status_code == 422
    assert populated.post("/v1/admin/wildcards/recheck", json={"list": "default", "refresh": False}, headers=KEY).status_code == 200


def test_enable_disable_endpoint_validates_input(populated):
    assert populated.post("/v1/admin/entries/enabled", json={"list": "default", "values": [], "enabled": False},
                          headers=KEY).status_code == 422
    r = populated.post("/v1/admin/entries/enabled", json={"list": "default", "values": ["not a url!"], "enabled": False},
                       headers=KEY)
    assert r.json() == {"changed": 0}
