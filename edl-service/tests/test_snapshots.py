"""EDL snapshot integrity and administrator visibility."""
import logging

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import service
from app.db import AppSetting, EdlSnapshot, Entry
from app.engine import processing_engine as eng
from conftest import KEY, feed, login, post, put_settings


def snap_row(client):
    with client.factory() as s:
        r = s.get(EdlSnapshot, "default")
        return (r.body, r.etag, r.entry_count, r.retained) if r else None


def status(client):
    return client.get("/v1/admin/edl", headers=KEY).json()["lists"][0]


# ------------------------------------------------------------------ failures never replace a valid snapshot
def test_failed_rebuild_keeps_last_valid_snapshot(client, monkeypatch, caplog):
    post(client, ["a.example.com", "b.example.com"])
    good = feed(client)
    monkeypatch.setattr(service, "build_body", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with client.factory() as s:
        snap = service.rebuild_snapshot(s, "default")
        assert snap.body == good.text
    assert feed(client).text == good.text and feed(client).headers["etag"] == good.headers["etag"]
    assert status(client)["last_error"]["error"] == "RuntimeError"
    assert any("previous version is still served" in r.getMessage() for r in caplog.records)


def test_snapshot_recovers_after_failure(client, monkeypatch):
    post(client, ["a.example.com"])
    real = service.build_body
    monkeypatch.setattr(service, "build_body", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    assert feed(client).text.splitlines() == ["a.example.com"]       # stale but valid; DB already changed
    assert status(client)["last_error"]                              # the failure is visible to administrators
    monkeypatch.setattr(service, "build_body", real)
    with client.factory() as s:
        service.rebuild_snapshot(s, "default")
    assert feed(client).text == "" and not status(client)["last_error"] and not status(client)["differs"]


def test_snapshot_update_is_one_transaction(client, monkeypatch):
    post(client, ["a.example.com"])
    before = snap_row(client)
    real_commit = Session.commit
    calls = []

    def failing_commit(self):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("commit failed")
        return real_commit(self)

    # make the DB change committed, then fail the snapshot's commit
    with client.factory() as s:
        s.add(Entry(list_name="default", value="new.example.com", status="active"))
        real_commit(s)
        monkeypatch.setattr(Session, "commit", failing_commit)
        service.rebuild_snapshot(s, "default")
        monkeypatch.setattr(Session, "commit", real_commit)
    assert snap_row(client) == before                                  # body, etag, count all unchanged together
    with client.factory() as s:
        service.rebuild_snapshot(s, "default")
    assert "new.example.com" in feed(client).text


def test_processing_exception_does_not_touch_the_feed(client, monkeypatch):
    post(client, ["a.example.com", "b.example.com"])
    before = feed(client)
    monkeypatch.setattr(service, "lookup_with_retries", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    res = eng.tick(force=True, reclassify=True, refresh=True)
    assert res == {"error": "RuntimeError"} or "error" in res
    assert feed(client).text == before.text and feed(client).headers["etag"] == before.headers["etag"]


def test_panorama_outage_during_reclassification_does_not_empty_the_feed(client):
    post(client, ["a.example.com", "b.example.com", "bad.example.net"])
    before = feed(client).text
    put_settings(client, {"retry_delay_seconds": 0})
    client.fake.fail_next = 10_000                                    # Panorama down for the whole run
    res = eng.tick(force=True, reclassify=True, refresh=True)
    assert feed(client).text == before and before.splitlines() == ["a.example.com", "b.example.com"]
    with client.factory() as s:
        statuses = {e.value: e.status for e in s.scalars(select(Entry))}
    assert statuses == {"a.example.com": "active", "b.example.com": "active", "bad.example.net": "blocked"}
    assert res["reclassification"]["checked"] == 3


def test_new_entries_during_outage_are_still_held_back(client):
    client.fake.fail_next = 10_000
    assert post(client, ["new.example.com"])["results"][0]["status"] == "pending"
    assert feed(client).text == ""


def test_recheck_endpoint_survives_outage_too(client):
    post(client, ["a.example.com"])
    client.fake.fail_next = 10_000
    client.post("/v1/lists/default/recheck", headers=KEY)
    assert feed(client).text.splitlines() == ["a.example.com"]


# ------------------------------------------------------------------ empty behaviour is explicit
def test_publish_empty_is_the_default_and_reported(client):
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    r = feed(client)
    assert r.status_code == 200 and r.text == ""
    st = status(client)
    assert not st["retained"] and not st["differs"] and st["serving"] == "current"


def test_return_error_reported(client):
    put_settings(client, {"edl_empty_behaviour": "return-error"}, confirm=True)
    assert feed(client).status_code == 503
    assert "HTTP 503" in status(client)["serving"] and "return-error" in status(client)["serving"]


def test_keep_previous_is_flagged_not_silent(client, caplog):
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    assert feed(client).text.splitlines() == ["a.example.com"]       # old entries still served...
    st = status(client)                                              # ...but administrators are told
    assert st["retained"] is True and st["differs"] is True and st["only_published"] == 1
    assert "keep-previous" in st["note"] and "still being served" in st["note"]
    assert st["serving"] == "previous list retained (keep-previous)"
    assert st["sample_only_published"] == ["a.example.com"] and st["eligible_count"] == 0

    login(client)
    assert "still being served" in client.get("/admin/settings").text            # overview warning
    page = client.get("/admin/settings/edl").text
    assert "retained" in page and "a.example.com" in page


def test_keep_previous_clears_when_valid_entries_return(client):
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    post(client, ["b.example.com"])
    assert feed(client).text.splitlines() == ["b.example.com"]
    st = status(client)
    assert not st["retained"] and not st["differs"] and st["note"] is None


def test_switching_away_from_keep_previous_publishes_the_empty_list(client):
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    put_settings(client, {"edl_empty_behaviour": "publish-empty"}, confirm=True)
    assert feed(client).text == "" and not status(client)["retained"]


def test_keep_previous_with_nothing_previous_publishes_empty(client):
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    assert feed(client).status_code == 200 and feed(client).text == ""


def test_retained_state_survives_restart(client):
    put_settings(client, {"edl_empty_behaviour": "keep-previous"}, confirm=True)
    post(client, ["a.example.com"])
    client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
    client.main.init_app(client.engine, client.factory)
    assert feed(client).text.splitlines() == ["a.example.com"] and status(client)["retained"]


# ------------------------------------------------------------------ visibility of drift
def test_admin_sees_when_published_differs_from_eligible(client):
    post(client, ["a.example.com"])
    assert status(client)["differs"] is False
    with client.factory() as s:                                      # eligible entry that never reached a rebuild
        s.add(Entry(list_name="default", value="late.example.com", status="active"))
        s.commit()
    st = status(client)
    assert st["differs"] and st["only_eligible"] == 1 and st["sample_only_eligible"] == ["late.example.com"]
    login(client)
    assert "differs" in client.get("/admin/settings/edl").text
    assert "differs" in client.get("/admin/settings").text
    with client.factory() as s:
        service.rebuild_snapshot(s, "default")
    assert status(client)["differs"] is False


def test_publishing_disabled_status(client):
    post(client, ["a.example.com"])
    put_settings(client, {"edl_publishing_enabled": False}, confirm=True)
    assert "HTTP 503" in status(client)["serving"]


def test_concurrent_rebuilds_are_serialised(client):
    assert service._snapshot_lock.acquire(blocking=False)
    service._snapshot_lock.release()


def test_admin_edl_endpoint_requires_management_key(client):
    assert client.get("/v1/admin/edl").status_code == 401
