"""Panorama request concurrency is capped at 5 across all processing paths."""
import threading
import time

import httpx
import pytest

from app import config, panorama, service
from app.config import MAX_PANORAMA_CONCURRENCY, get_settings
from app.engine import processing_engine as eng
from app.panorama import ConcurrencyLimiter, PanoramaClient, panorama_limiter
from conftest import KEY, post, put_settings, section_form

ANSWER = '<response status="success"><result>{t} search-engines (Base db)</result></response>'


def test_default_and_maximum_are_five(client):
    assert MAX_PANORAMA_CONCURRENCY == 5
    assert get_settings().max_concurrent_requests == 5
    sec = client.get("/v1/admin/settings/processing", headers=KEY).json()
    item = next(x for x in sec["settings"] if x["key"] == "max_concurrent_requests")
    assert item["value"] == 5 and item["default"] == 5 and "5" in item["description"]


@pytest.mark.parametrize("bad", [6, 8, 64, 0, -1])
def test_cannot_configure_more_than_five(client, bad):
    r = client.put("/v1/admin/settings", json={"values": {"max_concurrent_requests": bad}, "confirm": True}, headers=KEY)
    assert r.status_code == 422
    assert get_settings().max_concurrent_requests == 5


def test_lower_values_allowed_and_applied_to_the_limiter(client):
    put_settings(client, {"max_concurrent_requests": 2})
    assert panorama_limiter.limit == 2
    put_settings(client, {"max_concurrent_requests": 5})
    assert panorama_limiter.limit == 5


def test_limiter_enforces_its_limit_and_cannot_exceed_five():
    lim = ConcurrencyLimiter(50)
    assert lim.limit == 5
    lim.set_limit(99)
    assert lim.limit == 5
    lim.set_limit(0)
    assert lim.limit == 1
    lim.set_limit(3)
    gate = threading.Event()

    def worker():
        with lim.slot():
            gate.wait(2)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    time.sleep(0.2)
    assert lim.in_flight == 3                                       # the rest are queued
    gate.set()
    [t.join() for t in threads]
    assert lim.peak == 3 and lim.in_flight == 0


def test_limiter_releases_on_error():
    lim = ConcurrencyLimiter(1)
    with pytest.raises(RuntimeError):
        with lim.slot():
            raise RuntimeError
    with lim.slot():
        pass
    assert lim.in_flight == 0


@pytest.fixture
def slow_real_client(monkeypatch):
    """A real PanoramaClient whose HTTP layer is a slow mock that records in-flight requests."""
    state = {"now": 0, "peak": 0, "total": 0}
    lock = threading.Lock()

    def handler(req: httpx.Request):
        with lock:
            state["now"] += 1
            state["total"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.02)
        with lock:
            state["now"] -= 1
        cmd = httpx.QueryParams(req.content.decode())["cmd"]
        if "<url>" not in cmd:                                      # connection test: system info
            return httpx.Response(200, text='<response status="success"><result><system><devicename>p</devicename></system></result></response>')
        target = cmd.split("<url>")[1].split("</url>")[0]
        return httpx.Response(200, text=ANSWER.format(t=target))

    s = config.settings_from({"panorama_host": "pan.test", "panorama_api_key": "k" * 20})
    c = PanoramaClient(s)
    c._client = httpx.Client(base_url="https://pan.test", transport=httpx.MockTransport(handler))
    monkeypatch.setattr(service, "_client", c)
    panorama_limiter.set_limit(5)
    panorama_limiter.reset_peak()
    return state


def test_bulk_lookup_never_exceeds_five_in_flight(client, slow_real_client):
    post(client, [f"h{i}.example.com" for i in range(60)])
    assert slow_real_client["total"] >= 60
    assert slow_real_client["peak"] <= 5
    assert panorama_limiter.peak <= 5


def test_concurrent_callers_share_one_limit(client, slow_real_client):
    """API submissions, background processing, rechecks and connection tests all call the same
    client; however many callers run at once, in-flight requests total at most 5. (Called at the
    client level because the in-memory test database cannot be shared across threads.)"""
    c = service.get_client()
    errors = []

    def caller(prefix):
        try:
            for i in range(15):
                c.lookup(f"{prefix}{i}.example.com")
        except Exception as exc:                                    # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=caller, args=(p,)) for p in "abcdefgh"]
    threads += [threading.Thread(target=c.test_connection) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert slow_real_client["peak"] <= 5 and panorama_limiter.peak <= 5
    assert slow_real_client["total"] >= 120 - len(errors)


def test_worker_pool_respects_lower_setting(client):
    put_settings(client, {"max_concurrent_requests": 2})
    now, peak, lock = [0], [0], threading.Lock()
    orig = client.fake.lookup

    def tracked(t):
        with lock:
            now[0] += 1
            peak[0] = max(peak[0], now[0])
        time.sleep(0.01)
        with lock:
            now[0] -= 1
        return orig(t)

    client.fake.lookup = tracked
    post(client, [f"h{i}.example.com" for i in range(20)])
    assert 1 <= peak[0] <= 2


def test_stored_value_above_five_is_clamped_on_upgrade(client):
    from app.db import AppSetting
    with client.factory() as s:
        s.get(AppSetting, "max_concurrent_requests").value = "8"
        s.commit()
    client.main.init_app(client.engine, client.factory)             # an upgrade restart
    assert get_settings().max_concurrent_requests == 5


def test_env_value_above_five_is_clamped_not_fatal(monkeypatch):
    monkeypatch.setenv("LOOKUP_WORKERS", "16")
    assert config.settings_from().max_concurrent_requests == 5
    monkeypatch.setenv("MAX_CONCURRENT_REQUESTS", "9")
    assert config.settings_from().max_concurrent_requests == 5


def test_ui_rejects_more_than_five(client):
    from conftest import login, ui_post
    login(client)
    r = ui_post(client, "/admin/settings/processing", **section_form("processing", max_concurrent_requests=6))
    assert get_settings().max_concurrent_requests == 5
