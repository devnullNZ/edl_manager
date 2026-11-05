"""Shared test setup: environment, fake Panorama, and an API client that is registered as an
allowed host (10.0.0.0/24) with a token. Each test gets a fresh in-memory database that has gone
through the real startup path (migrations, seeding, settings load, feed snapshots)."""
import os
import re

# Must be set before the app is imported. PANORAMA_* only seed the first-start defaults.
os.environ.update(
    DATABASE_URL="sqlite://", API_KEY="k", SECRET_KEY="test-secret-key", ENCRYPTION_KEY="test-encryption-key",
    ADMIN_PASSWORD="pw", ADMIN_COOKIE_SECURE="false", CLASSIFICATION_ENABLED="true",
    PANORAMA_HOST="x", PANORAMA_API_KEY="x",
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import config, hosts, ratelimit, service, settings_store
from app import db as dbmod
from app.config import get_settings
from app.engine import processing_engine
from app.panorama import MockPanoramaClient, PanoramaError

KEY = {"X-API-Key": "k"}
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


class FakePanorama:
    def __init__(self):
        self.calls = []
        self.fail = set()
        self.fail_next = 0          # fail this many upcoming lookups, then recover
        self.conn_error = None

    def lookup(self, target):
        self.calls.append(target)
        if self.fail_next > 0:
            self.fail_next -= 1
            raise PanoramaError("boom")
        if target in self.fail:
            raise PanoramaError("boom")
        if target.startswith("bad"):
            return f"{target} malware (Cloud db)"
        return f"{target} search-engines (Base db)"

    def test_connection(self):
        if self.conn_error:
            raise PanoramaError(self.conn_error)
        return {"ok": True, "message": "Connected and authenticated.", "devicename": "pano-1",
                "sw_version": "11.1.0", "latency_ms": 5, "mock": False}

    def close(self):
        pass


def _session(factory):
    s = factory()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def client(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    factory = sessionmaker(eng, expire_on_commit=False)
    monkeypatch.setattr(dbmod, "engine", eng)
    monkeypatch.setattr(dbmod, "SessionLocal", factory)
    config.set_effective(None)

    fake = FakePanorama()
    monkeypatch.setattr(service, "_client", fake)
    monkeypatch.setattr(service, "make_client",
                        lambda s: MockPanoramaClient(s) if s.panorama_mode == "mock" else fake)

    from app import admin, main
    main.init_app(eng, factory)

    def override_get_db():
        yield from _session(factory)

    main.app.dependency_overrides[dbmod.get_db] = override_get_db
    admin._FAILS.clear()
    admin._PENDING.clear()
    ratelimit.reset()
    processing_engine._reclassify_requested = False
    processing_engine._last_purge = float("-inf")
    processing_engine.status.update(last_run=None, last_result=None, last_error=None)

    with factory() as s:
        _, token = hosts.create_host(s, "ticketing", "10.0.0.0/24", "*")

    # the app lifespan is not run, so no real Panorama client or background loop is created
    c = TestClient(main.app, client=("10.0.0.5", 5000))
    c.fake, c.token, c.factory, c.main, c.engine = fake, token, factory, main, eng
    yield c
    main.app.dependency_overrides.clear()
    config.set_effective(None)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def post(c, urls, list_name="default", **extra):
    r = c.post(f"/v1/lists/{list_name}/entries", json={"urls": urls, **extra}, headers=bearer(c.token))
    assert r.status_code == 200, r.text
    return r.json()


def put_settings(c, values=None, section=None, confirm=False, clear=(), expect=200):
    url = f"/v1/admin/settings/{section}" if section else "/v1/admin/settings"
    r = c.put(url, json={"values": values or {}, "confirm": confirm, "clear_secrets": list(clear)}, headers=KEY)
    assert r.status_code == expect, r.text
    return r


def apex_policy(c):
    """Wildcard entries are excluded by default; tests of shadowing and of wildcards in the feed
    opt in to the apex-classification policy."""
    put_settings(c, {"wildcard_classification_policy": "apex-classification"}, confirm=True)


def feed(c, name="default", **kw):
    return c.get(f"/edl/{name}", **kw)


# ---- admin UI helpers
def csrf(c, path="/admin/login"):
    return CSRF.search(c.get(path).text).group(1)


def login(c, password="pw", user="admin"):
    return c.post("/admin/login", data={"csrf_token": csrf(c), "username": user, "password": password},
                  follow_redirects=False)


def ui_post(c, path, token_page=None, **data):
    token_page = token_page or ("/admin/hosts" if path.startswith("/admin/hosts") else "/admin/settings")
    return c.post(path, data={"csrf_token": csrf(c, token_page), **data}, follow_redirects=False)


def section_form(section_id, **over):
    """A complete form for a settings section from current values, with overrides applied."""
    s = get_settings()
    data = {}
    for f in settings_store.SECTION_BY_ID[section_id].fields:
        if f.kind == "secret":
            if f.key in over:
                data[f.key] = over[f.key]
            continue
        value = over.get(f.key, getattr(s, f.key))
        if f.kind == "bool":
            if value:
                data[f.key] = "on"
        elif f.kind == "multiselect":
            data[f.key] = value if isinstance(value, list) else [c for c in str(value).split(",") if c]
        else:
            data[f.key] = str(value)
    return data
