"""Background processing engine: pending resolution, batching, retries, disabled switch."""
import asyncio

from conftest import KEY, feed, post, put_settings
from app.engine import processing_engine as eng


def test_tick_resolves_pending(client):
    client.fake.fail.add("flaky.com")
    assert post(client, ["flaky.com"])["results"][0]["status"] == "pending"
    assert feed(client).text.strip() == ""
    client.fake.fail.clear()
    res = eng.tick()
    assert res["pending"]["checked"] == 1 and res["pending"]["changed"] == 1
    assert feed(client).text.splitlines() == ["flaky.com"]


def test_tick_retries_transient_failures(client):
    client.fake.fail.add("flaky.com")
    post(client, ["flaky.com"])
    put_settings(client, {"retry_attempts": 3, "retry_delay_seconds": 0})
    client.fake.fail.clear()
    client.fake.fail_next = 2                       # fails twice, third attempt succeeds
    eng.tick()
    assert feed(client).text.splitlines() == ["flaky.com"]


def test_batch_size_limits_one_run(client):
    client.fake.fail_next = 5
    post(client, [f"h{i}.example.com" for i in range(5)])
    client.fake.fail.clear()
    put_settings(client, {"max_batch_size": 2})
    assert eng.tick()["pending"]["checked"] == 2
    assert eng.tick()["pending"]["checked"] == 2
    assert eng.tick()["pending"]["checked"] == 1
    assert eng.tick()["pending"]["checked"] == 0
    assert len(feed(client).text.splitlines()) == 5


def test_disabled_background_processing_skips_but_manual_run_works(client):
    client.fake.fail.add("flaky.com")
    post(client, ["flaky.com"])
    client.fake.fail.clear()
    put_settings(client, {"background_processing_enabled": False}, confirm=True)
    assert "skipped" in eng.tick()
    assert feed(client).text.strip() == ""
    assert eng.tick(force=True)["pending"]["changed"] == 1
    assert feed(client).text.splitlines() == ["flaky.com"]


def test_scheduled_loop_does_not_run_when_disabled(client):
    client.fake.fail.add("flaky.com")
    post(client, ["flaky.com"])
    client.fake.fail.clear()
    put_settings(client, {"background_processing_enabled": False, "processing_interval_seconds": 5}, confirm=True)

    async def go():
        eng.start()
        await asyncio.sleep(0.3)
        await eng.stop()
    asyncio.run(go())
    assert feed(client).text.strip() == ""


def test_unverified_entries_are_rechecked_and_removed_when_bad(client):
    put_settings(client, {"classification_failure_behaviour": "fail-open"}, confirm=True)
    client.fake.fail.add("bad.later.com")
    assert post(client, ["bad.later.com"])["results"][0]["status"] == "added"      # published, unverified
    assert feed(client).text.splitlines() == ["bad.later.com"]        # published while unverified
    client.fake.fail.clear()
    eng.tick()
    assert feed(client).text.strip() == ""                            # classified malware -> pulled


def test_reclassification_on_demand(client):
    post(client, ["turned.bad.com"])
    client.fake.lookup_orig = client.fake.lookup
    client.fake.lookup = lambda t: f"{t} malware (Cloud db)"
    res = eng.tick(reclassify=True, refresh=True)
    assert res["reclassification"]["changed"] == 1
    assert feed(client).text.strip() == ""


def test_run_now_via_admin_ui(client):
    from conftest import login, ui_post
    login(client)
    client.fake.fail.add("flaky.com")
    post(client, ["flaky.com"])
    client.fake.fail.clear()
    r = ui_post(client, "/admin/processing/run")
    assert r.status_code in (302, 303)
    assert feed(client).text.splitlines() == ["flaky.com"]


def test_concurrent_tick_is_skipped(client):
    assert eng._lock.acquire(blocking=False)
    try:
        assert "skipped" in eng.tick()
    finally:
        eng._lock.release()


def test_audit_purge(client):
    from datetime import datetime, timedelta, timezone
    from app.db import AuditLog
    put_settings(client, {"audit_retention_days": 1})
    with client.factory() as s:
        s.add(AuditLog(ts=datetime.now(timezone.utc) - timedelta(days=5), actor="x", action="old", kind="admin"))
        s.commit()
    eng.tick()
    recs = client.get("/v1/admin/audit?limit=500", headers=KEY).json()["records"]
    assert all(r["action"] != "old" for r in recs)
