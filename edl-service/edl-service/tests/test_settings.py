"""Admin Settings: defaults, persistence, validation, access control, secrets, Panorama test,
cache invalidation, and the behaviour switches."""
import logging

import pytest
from sqlalchemy import select

from app import service, settings_store
from app.config import get_settings
from app.db import AppSetting, AuditLog, CategoryCache
from conftest import apex_policy, KEY, bearer, feed, login, post, put_settings, section_form, ui_post


def stored(client, key):
    with client.factory() as s:
        row = s.get(AppSetting, key)
        return row.value if row else None


# ------------------------------------------------------------------ defaults / seeding
def test_defaults_created_on_first_start(client):
    with client.factory() as s:
        keys = set(s.scalars(select(AppSetting.key)))
    assert set(settings_store.EDITABLE) <= keys
    r = client.get("/v1/admin/settings", headers=KEY)
    assert [x["id"] for x in r.json()["sections"]] == ["general", "panorama", "classification", "edl",
                                                         "processing", "security"]
    flat = {x["key"]: x for sec in r.json()["sections"] for x in sec["settings"]}
    assert flat["panorama_port"]["value"] == 443 and flat["panorama_port"]["default"] == 443
    assert flat["edl_name"]["value"] == "default"
    for x in flat.values():
        assert x["description"] and x["type"]


def test_seed_does_not_overwrite_existing(client):
    put_settings(client, {"app_name": "Mine", "max_batch_size": 7})
    with client.factory() as s:
        settings_store.seed_defaults(s)
        settings_store.reload(s)
    assert get_settings().app_name == "Mine" and get_settings().max_batch_size == 7


def test_startup_with_existing_db_settings(client):
    put_settings(client, {"app_name": "Persisted", "edl_max_entries": 5}, confirm=True)
    client.main.init_app(client.engine, client.factory)       # a restart
    assert get_settings().app_name == "Persisted"
    assert get_settings().edl_max_entries == 5


def test_settings_survive_cache_reset(client):
    put_settings(client, {"app_name": "Persisted"})
    from app import config
    config.set_effective(None)
    with client.factory() as s:
        settings_store.reload(s)
    assert get_settings().app_name == "Persisted"


# ------------------------------------------------------------------ updates
def test_individual_update_changes_only_that_setting(client):
    before = settings_store.current_values()
    r = put_settings(client, {"max_batch_size": 25}, section="processing")
    assert r.json()["changed"] == ["max_batch_size"]
    after = settings_store.current_values()
    assert after["max_batch_size"] == "25"
    assert {k for k in before if before[k] != after[k]} == {"max_batch_size"}
    assert stored(client, "max_batch_size") == "25"


def test_unchanged_update_reports_nothing_and_does_not_audit(client):
    put_settings(client, {"max_batch_size": 25})
    n = len(client.get("/v1/admin/audit", headers=KEY).json()["records"])
    assert put_settings(client, {"max_batch_size": 25}).json()["changed"] == []
    assert len(client.get("/v1/admin/audit", headers=KEY).json()["records"]) == n


def test_unknown_section_and_key(client):
    assert client.get("/v1/admin/settings/nope", headers=KEY).status_code == 404
    put_settings(client, {"nope": 1}, expect=422)
    put_settings(client, {"max_batch_size": 5}, section="general", expect=422)  # wrong section


def test_reset_to_defaults_via_ui(client):
    login(client)
    put_settings(client, {"app_name": "Mine"})
    ui_post(client, "/admin/settings/reset-defaults", section="general")
    assert get_settings().app_name != "Mine"


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("values", [
    {"app_timezone": "Mars/Base"},
    {"log_level": "LOUD"},
    {"processing_interval_seconds": "abc"},
    {"max_batch_size": 0},
    {"max_batch_size": -3},
    {"rate_limit_requests": -1},
    {"panorama_port": 70000},
    {"edl_name": "bad name!"},
    {"edl_empty_behaviour": "explode"},
    {"classification_failure_behaviour": "maybe"},
    {"edl_endpoint": "no-leading-slash"},
    {"edl_endpoint": "/healthz"},
    {"edl_endpoint": "/admin/x"},
    {"edl_endpoint": "/edl/foo"},
    {"edl_endpoint": "/v1/lists/x/entries"},
    {"edl_endpoint": "/docs"},
])
def test_invalid_values_rejected_and_not_saved(client, values):
    before = settings_store.current_values()
    r = client.put("/v1/admin/settings", json={"values": values, "confirm": True}, headers=KEY)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["errors"]
    assert settings_store.current_values() == before


def test_high_risk_must_be_known_categories(client):
    put_settings(client, {"high_risk_categories": ["not-a-category"]}, expect=422)
    put_settings(client, {"high_risk_categories": ["malware", "phishing"]}, confirm=True)
    assert get_settings().high_risk_set == {"malware", "phishing"}


def test_classification_categories_are_configurable(client):
    put_settings(client, {"known_categories": ["malware", "gambling"], "high_risk_categories": ["gambling"]},
                 confirm=True)
    assert "gambling" in get_settings().high_risk_set


def test_valid_endpoint_accepted_and_served(client):
    post(client, ["a.example.com"])
    put_settings(client, {"edl_endpoint": "/feeds/blocklist.txt"}, confirm=True)
    r = client.get("/feeds/blocklist.txt")
    assert r.status_code == 200 and r.text.splitlines() == ["a.example.com/"]
    assert client.get("/feeds/other.txt").status_code == 404
    assert client.get("/edl/default").text == r.text          # built-in path still works


def test_alias_endpoint_honours_feed_auth(client):
    post(client, ["a.example.com"])
    put_settings(client, {"edl_endpoint": "/feeds/b.txt", "edl_user": "fw", "edl_password": "s3cret"}, confirm=True)
    assert client.get("/feeds/b.txt").status_code == 401
    assert client.get("/feeds/b.txt", auth=("fw", "s3cret")).status_code == 200


# ------------------------------------------------------------------ access control
def test_admin_api_requires_management_key(client):
    for method, path in (("GET", "/v1/admin/settings"), ("PUT", "/v1/admin/settings"),
                         ("GET", "/v1/admin/settings/edl"), ("POST", "/v1/admin/panorama/test-connection"),
                         ("GET", "/v1/admin/audit")):
        assert client.request(method, path, json={} if method != "GET" else None).status_code == 401, path
        assert client.request(method, path, headers={"X-API-Key": "wrong"}).status_code == 401, path
        # a host token is not an admin credential
        assert client.request(method, path, headers=bearer(client.token)).status_code == 401, path


def test_admin_ui_requires_login(client):
    for path in ("/admin/settings", "/admin/settings/edl", "/admin/audit"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 303) and "/admin/login" in r.headers["location"], path
    r = client.post("/admin/settings/edl", data={"csrf_token": "x"}, follow_redirects=False)
    assert r.status_code in (302, 303, 403)


def test_ui_save_and_sections_render(client):
    login(client)
    for sid in settings_store.SECTION_BY_ID:
        assert client.get(f"/admin/settings/{sid}").status_code == 200
    r = ui_post(client, "/admin/settings/processing", **section_form("processing", max_batch_size=12))
    assert r.status_code in (302, 303)
    assert get_settings().max_batch_size == 12


def test_ui_validation_error_keeps_form_and_saves_nothing(client):
    login(client)
    r = ui_post(client, "/admin/settings/general", **section_form("general", app_timezone="Mars/Base"))
    assert r.status_code == 422 or "Mars/Base" in r.text
    assert get_settings().app_timezone != "Mars/Base"


def test_ui_disruptive_change_needs_confirmation(client):
    login(client)
    r = ui_post(client, "/admin/settings/edl", **section_form("edl", edl_publishing_enabled=False))
    assert get_settings().edl_publishing_enabled is True       # not applied yet
    assert "confirm" in r.text.lower()


# ------------------------------------------------------------------ disruptive confirmation (API)
def test_disruptive_change_requires_confirm(client):
    r = client.put("/v1/admin/settings", json={"values": {"edl_publishing_enabled": False}}, headers=KEY)
    assert r.status_code == 409 and r.json()["detail"]["requires_confirmation"]
    assert get_settings().edl_publishing_enabled is True
    put_settings(client, {"edl_publishing_enabled": False}, confirm=True)
    assert get_settings().edl_publishing_enabled is False


# ------------------------------------------------------------------ secrets
SECRET = "super-secret-panorama-key-123"


def test_secret_encrypted_at_rest_masked_everywhere(client, caplog):
    caplog.set_level(logging.DEBUG)
    login(client)
    put_settings(client, {"panorama_api_key": SECRET}, section="panorama")
    raw = stored(client, "panorama_api_key")
    assert raw and SECRET not in raw
    assert get_settings().panorama_api_key == SECRET            # decrypted for use

    bodies = [client.get("/v1/admin/settings", headers=KEY).text,
              client.get("/v1/admin/settings/panorama", headers=KEY).text,
              client.get("/admin/settings/panorama").text,
              client.get("/admin/settings").text,
              client.get("/v1/admin/audit", headers=KEY).text,
              client.get("/admin/audit").text]
    for b in bodies:
        assert SECRET not in b
        assert raw not in b
    sec = client.get("/v1/admin/settings/panorama", headers=KEY).json()
    item = next(x for x in sec["settings"] if x["key"] == "panorama_api_key")
    assert item["value"] != SECRET and item.get("configured") is True
    with client.factory() as s:
        for row in s.scalars(select(AuditLog)):
            assert SECRET not in (row.detail or "")
    assert SECRET not in caplog.text


def test_blank_secret_keeps_and_clear_removes(client):
    put_settings(client, {"panorama_api_key": SECRET})
    put_settings(client, {"panorama_api_key": "", "max_batch_size": 9})
    assert get_settings().panorama_api_key == SECRET
    # live mode needs a key, so clearing it alone is refused and nothing changes
    put_settings(client, clear=["panorama_api_key"], confirm=True, expect=422)
    assert get_settings().panorama_api_key == SECRET
    put_settings(client, {"panorama_mode": "mock"}, clear=["panorama_api_key"], confirm=True)
    assert not get_settings().panorama_api_key


def test_secret_never_in_ui_form_value(client):
    login(client)
    put_settings(client, {"edl_password": SECRET})
    assert SECRET not in client.get("/admin/settings/edl").text


def test_wrong_encryption_key_does_not_leak_or_crash(client):
    put_settings(client, {"panorama_api_key": SECRET})
    raw = stored(client, "panorama_api_key")
    assert settings_store.decrypt(raw) == (SECRET, 0)
    assert settings_store.decrypt("enc:garbage") == (None, -1)


# ------------------------------------------------------------------ Panorama connection test
def test_panorama_test_success_and_failure(client):
    r = client.post("/v1/admin/panorama/test-connection", headers=KEY)
    assert r.status_code == 200 and r.json()["ok"] is True
    client.fake.conn_error = "authentication failed"
    r = client.post("/v1/admin/panorama/test-connection", headers=KEY)
    assert r.status_code == 502 and r.json()["ok"] is False
    assert "authentication failed" in r.json()["message"]


def test_panorama_test_with_unsaved_values_does_not_save_or_leak(client):
    r = client.post("/v1/admin/panorama/test-connection", headers=KEY,
                    json={"mode": "mock"})
    assert r.status_code == 200 and r.json().get("mock") is True
    assert get_settings().panorama_mode == "live"               # unchanged
    r = client.post("/v1/admin/panorama/test-connection", headers=KEY,
                    json={"mode": "live", "host": "p.example.net", "api_key": SECRET})
    assert SECRET not in r.text


def test_panorama_test_via_ui(client):
    login(client)
    r = ui_post(client, "/admin/settings/panorama/test")
    assert r.status_code in (200, 302, 303)


def test_status_indicator_updates(client):
    client.post("/v1/admin/panorama/test-connection", headers=KEY)
    login(client)
    assert "pano-1" in client.get("/admin/settings/panorama").text or \
        "onnected" in client.get("/admin/settings/panorama").text


# ------------------------------------------------------------------ cache invalidation
def test_settings_cache_invalidated_on_change(client):
    assert get_settings().max_batch_size != 3
    put_settings(client, {"max_batch_size": 3})
    assert get_settings().max_batch_size == 3
    sec = client.get("/v1/admin/settings/processing", headers=KEY).json()
    assert next(x for x in sec["settings"] if x["key"] == "max_batch_size")["value"] == 3


def test_classification_cache_cleared_when_source_changes(client):
    post(client, ["a.example.com"])
    with client.factory() as s:
        assert s.scalars(select(CategoryCache)).first() is not None
    put_settings(client, {"panorama_host": "other.example.net"}, section="panorama")
    with client.factory() as s:
        assert s.scalars(select(CategoryCache)).first() is None


def test_cache_kept_when_unrelated_setting_changes(client):
    post(client, ["a.example.com"])
    put_settings(client, {"app_name": "Renamed"})
    with client.factory() as s:
        assert s.scalars(select(CategoryCache)).first() is not None


def test_feed_rebuilt_when_high_risk_set_changes(client):
    post(client, ["bad.evil.net", "ok.example.com"])
    assert feed(client).text.splitlines() == ["ok.example.com/"]
    put_settings(client, {"high_risk_categories": ["phishing"]}, confirm=True)
    client.post("/v1/lists/default/recheck", headers=KEY)
    assert sorted(feed(client).text.splitlines()) == ["bad.evil.net/", "ok.example.com/"]


def test_snapshot_rebuilt_when_max_entries_changes(client):
    post(client, ["a.example.com", "b.example.com", "c.example.com"])
    assert len(feed(client).text.splitlines()) == 3
    put_settings(client, {"edl_max_entries": 2}, confirm=True)
    assert feed(client).text.splitlines() == ["a.example.com/", "b.example.com/"]   # oldest kept
    put_settings(client, {"edl_max_entries": 0}, confirm=True)
    assert len(feed(client).text.splitlines()) == 3


# ------------------------------------------------------------------ classification disabled
def test_classification_disabled_makes_no_panorama_calls(client):
    put_settings(client, {"classification_enabled": False}, confirm=True)
    n = len(client.fake.calls)
    out = post(client, ["bad.evil.net", "x.example.com"])
    assert {r["status"] for r in out["results"]} == {"added"}
    assert len(client.fake.calls) == n
    assert sorted(feed(client).text.splitlines()) == ["bad.evil.net/", "x.example.com/"]


def test_reenabling_classification_filters_again(client):
    put_settings(client, {"classification_enabled": False}, confirm=True)
    post(client, ["bad.evil.net"])
    put_settings(client, {"classification_enabled": True}, confirm=True)
    client.post("/v1/lists/default/recheck", headers=KEY)
    assert feed(client).text.strip() == ""


# ------------------------------------------------------------------ failure / unknown policy
def test_fail_closed_vs_fail_open(client):
    client.fake.fail.add("flaky.com")
    assert post(client, ["flaky.com"])["results"][0]["status"] == "pending"
    assert feed(client).text.strip() == ""
    put_settings(client, {"classification_failure_behaviour": "fail-open"}, confirm=True)
    assert post(client, ["flaky2.com"])["results"][0]["status"] in ("added", "unverified")
    client.fake.fail.add("flaky2.com")
    client.fake.fail.discard("flaky.com")


def test_unknown_category_policy(client):
    client.fake.lookup = lambda t: f"{t} unknown (Base db)"
    r = post(client, ["u1.example.com"])["results"][0]
    assert r["status"] in ("added", "active")
    put_settings(client, {"unknown_category_behaviour": "exclude"}, confirm=True)
    r = post(client, ["u2.example.com"])["results"][0]
    assert r["status"] == "blocked"


# ------------------------------------------------------------------ EDL behaviour
def test_publishing_disabled_returns_503_and_reenable_restores(client):
    post(client, ["a.example.com"])
    put_settings(client, {"edl_publishing_enabled": False}, confirm=True)
    assert feed(client).status_code == 503
    put_settings(client, {"edl_publishing_enabled": True})
    assert feed(client).text.splitlines() == ["a.example.com/"]


def test_feed_is_plain_text_one_per_line_with_etag(client):
    apex_policy(client)
    post(client, ["a.example.com", "*.b.example.com"])
    r = feed(client)
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text.splitlines() == ["*.b.example.com/", "a.example.com/"]
    assert feed(client, headers={"If-None-Match": r.headers["etag"]}).status_code == 304


def test_empty_behaviours(client):
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    assert feed(client).status_code == 200 and feed(client).text == ""      # publish-empty (default)
    put_settings(client, {"edl_empty_behaviour": "return-error"}, confirm=True)
    assert feed(client).status_code == 503
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    post(client, ["b.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["b.example.com"]}, headers=KEY)
    assert feed(client).text.splitlines() == ["b.example.com/"]


def test_existing_feed_survives_rebuild_failure(client, monkeypatch):
    post(client, ["a.example.com"])
    good = feed(client).text

    def boom(*a, **k):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(service, "build_body", boom)
    with client.factory() as s:
        try:
            service.rebuild_snapshot(s, "default")
        except Exception:
            pass
    assert feed(client).status_code == 200 and feed(client).text == good


def test_feed_basic_auth_setting(client):
    post(client, ["a.example.com"])
    put_settings(client, {"edl_user": "fw", "edl_password": "pw1"})
    assert feed(client).status_code == 401
    assert feed(client, auth=("fw", "pw1")).status_code == 200
    assert feed(client, auth=("fw", "bad")).status_code == 401


# ------------------------------------------------------------------ security / API settings
def test_host_auth_disabled_allows_anonymous(client):
    put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
    r = client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]})
    assert r.status_code == 200
    put_settings(client, {"host_api_auth_enabled": True})
    assert client.post("/v1/lists/default/entries", json={"urls": ["b.example.com"]}).status_code == 401


def test_ip_restrictions_toggle(client):
    from fastapi.testclient import TestClient
    other = TestClient(client.main.app, client=("192.0.2.9", 1))
    h = bearer(client.token)
    assert other.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=h).status_code == 403
    put_settings(client, {"host_ip_restrictions_enabled": False}, confirm=True)
    assert other.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=h).status_code == 200


def test_max_submission_size(client):
    put_settings(client, {"max_submission_size": 2})
    r = client.post("/v1/lists/default/entries", json={"urls": ["a.com", "b.com", "c.com"]},
                    headers=bearer(client.token))
    assert r.status_code == 413
    assert client.post("/v1/lists/default/entries", json={"urls": ["a.com", "b.com"]},
                       headers=bearer(client.token)).status_code == 200


def test_rate_limit(client):
    put_settings(client, {"rate_limit_requests": 2, "rate_limit_interval_seconds": 60})
    h = bearer(client.token)
    codes = [client.post("/v1/lists/default/entries", json={"urls": [f"a{i}.com"]}, headers=h).status_code
             for i in range(4)]
    assert codes[:2] == [200, 200] and codes[2:] == [429, 429]
    r = client.post("/v1/lists/default/entries", json={"urls": ["z.com"]}, headers=h)
    assert int(r.headers["retry-after"]) >= 1
    put_settings(client, {"rate_limit_requests": 0})        # 0 = unlimited
    assert client.post("/v1/lists/default/entries", json={"urls": ["y.com"]}, headers=h).status_code == 200


def test_host_token_expiry(client):
    from datetime import datetime, timedelta, timezone
    from app.db import AllowedHost
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        h.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        s.commit()
    r = client.post("/v1/lists/default/entries", json={"urls": ["a.com"]}, headers=bearer(client.token))
    assert r.status_code == 401


def test_default_token_expiry_applied_to_new_hosts(client):
    from app import hosts
    from app.db import AllowedHost
    put_settings(client, {"host_token_expiry_days": 30})
    with client.factory() as s:
        hosts.create_host(s, "second", "10.1.0.0/16", "*")
        h = s.scalars(select(AllowedHost).where(AllowedHost.name == "second")).one()
        assert h.expires_at is not None


# ------------------------------------------------------------------ audit
def test_settings_changes_are_audited_without_secrets(client):
    put_settings(client, {"max_batch_size": 11, "panorama_api_key": SECRET})
    recs = client.get("/v1/admin/audit?kind=admin", headers=KEY).json()["records"]
    rec = next(r for r in recs if r["action"] == "settings.update")
    assert "max_batch_size" in rec["detail"] and SECRET not in rec["detail"]


def test_api_submissions_audited_only_when_enabled(client):
    post(client, ["a.example.com"])                          # default: on
    recs = client.get("/v1/admin/audit?kind=api", headers=KEY).json()["records"]
    assert [r["action"] for r in recs] == ["submit"] and recs[0]["actor"] == "host:ticketing"
    put_settings(client, {"audit_api_submissions": False})
    post(client, ["b.example.com"])
    assert len(client.get("/v1/admin/audit?kind=api", headers=KEY).json()["records"]) == 1


def test_audit_logging_can_be_disabled(client):
    put_settings(client, {"audit_logging_enabled": False}, confirm=True)
    n = len(client.get("/v1/admin/audit", headers=KEY).json()["records"])
    put_settings(client, {"max_batch_size": 4})
    assert len(client.get("/v1/admin/audit", headers=KEY).json()["records"]) == n


def test_log_level_and_timezone_applied(client):
    put_settings(client, {"log_level": "WARNING", "app_timezone": "Australia/Brisbane"})
    assert logging.getLogger().level == logging.WARNING
    put_settings(client, {"log_level": "INFO"})
