"""Test setup.

Unit and protocol tests need nothing but this package. The INTEGRATION tests run the importer against the
real EDL Publisher application code (an in-process FastAPI app with an in-memory database and a fake
Panorama), so they need the server source tree: set EDL_SERVER_SRC to it (default: ../edl-service).
They are skipped, with that reason, when it cannot be found."""
import contextlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

SERVER_SRC = Path(os.environ.get("EDL_SERVER_SRC", HERE.parent.parent / "edl-service")).resolve()
HAVE_SERVER = (SERVER_SRC / "app" / "main.py").is_file()
if HAVE_SERVER:
    sys.path.insert(0, str(SERVER_SRC))
    os.environ.update(
        DATABASE_URL="sqlite://", API_KEY="k", SECRET_KEY="test-secret-key", ENCRYPTION_KEY="test-encryption-key",
        ADMIN_PASSWORD="pw", ADMIN_COOKIE_SECURE="false", CLASSIFICATION_ENABLED="true",
        PANORAMA_HOST="x", PANORAMA_API_KEY="x")

ADMIN = {"X-API-Key": "k"}


class Killed(BaseException):
    """Simulates the importer process dying (not catchable by the importer's own error handling)."""


class FakePanorama:
    def __init__(self):
        self.calls = []

    def lookup(self, target):
        self.calls.append(target)
        if target.startswith("bad"):
            return f"{target} malware (Cloud db)"
        return f"{target} search-engines (Base db)"

    def test_connection(self):
        return {"ok": True, "message": "ok", "devicename": "p", "sw_version": "1", "latency_ms": 1, "mock": False}

    def close(self):
        pass


class Spy:
    """Wraps the server's test client: records every request the importer makes and can inject failures."""

    def __init__(self, inner):
        self.inner, self.log, self.before, self.after = inner, [], None, None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def request(self, method, url, json=None, timeout=None, **kw):
        path = url.split("testserver", 1)[-1]
        rec = {"method": method, "path": path, "json": json}
        self.log.append(rec)
        if self.before:
            self.before(rec)
        resp = self.inner.request(method, url, json=json, **kw)
        rec["status"] = resp.status_code
        if self.after:
            self.after(rec, resp)
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def session_starts(self):
        return [r for r in self.log if r["method"] == "POST" and r["path"].endswith("/sync/sessions")]

    def calls(self, method=None, contains=""):
        return [r for r in self.log if (method is None or r["method"] == method) and contains in r["path"]]


@pytest.fixture
def server(monkeypatch):
    if not HAVE_SERVER:
        pytest.skip(f"EDL Publisher source not found at {SERVER_SRC}; set EDL_SERVER_SRC")
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import config, hosts, ratelimit, service
    from app import db as dbmod
    from app.engine import processing_engine
    from app.panorama import MockPanoramaClient

    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    factory = sessionmaker(eng, expire_on_commit=False)
    monkeypatch.setattr(dbmod, "engine", eng)
    monkeypatch.setattr(dbmod, "SessionLocal", factory)
    config.set_effective(None)
    fake = FakePanorama()
    monkeypatch.setattr(service, "_client", fake)
    monkeypatch.setattr(service, "make_client", lambda s: MockPanoramaClient(s) if s.panorama_mode == "mock" else fake)
    from app import admin, main
    main.init_app(eng, factory)

    def override_get_db():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    main.app.dependency_overrides[dbmod.get_db] = override_get_db
    admin._FAILS.clear()
    admin._PENDING.clear()
    ratelimit.reset()
    processing_engine._stop.clear()
    processing_engine.status.update(last_run=None, last_result=None, last_error=None)
    with factory() as s:
        _, token = hosts.create_host(s, "importer", "10.0.0.0/24", "*")
    c = TestClient(main.app, base_url="http://testserver", client=("10.0.0.5", 5000))
    c.headers["Authorization"] = f"Bearer {token}"
    c.fake, c.token, c.factory, c.engine = fake, token, factory, processing_engine
    yield c
    main.app.dependency_overrides.clear()
    config.set_effective(None)


class Runner:
    """Runs the importer's main() against the server fixture and captures its output."""

    def __init__(self, server, tmp_path):
        self.server, self.tmp = server, tmp_path
        self.spy = Spy(server)
        self.lines: list[str] = []
        self.sleeps: list[float] = []

    def write_yaml(self, text, name="lists.yaml"):
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def run(self, yaml_path, *args, spy=None):
        import import_edl
        self.lines = []
        spy = spy or self.spy
        argv = [str(yaml_path), "--base-url", "http://testserver", "--token", self.server.token, *args]
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                return import_edl.main(argv, client_factory=lambda token, timeout, verify: spy,
                                       sleep=self.sleeps.append,
                                       out=lambda *a, **k: self.lines.append(" ".join(map(str, a))))
        finally:  # messages the importer writes to stderr (errors, warnings) are part of what an operator sees
            self.lines.extend(err.getvalue().splitlines())

    @property
    def text(self):
        return "\n".join(self.lines)

    def feed(self, name):
        r = self.server.get(f"/edl/{name}", headers=ADMIN)
        assert r.status_code == 200, (name, r.status_code, r.text)
        return r.text.splitlines()

    def state(self, yaml_path):
        return json.loads(Path(str(yaml_path) + ".import-state.json").read_text())

    def db(self, sql, **p):
        from sqlalchemy import text
        with self.server.factory() as s:
            return s.execute(text(sql), p).all()


@pytest.fixture
def runner(server, tmp_path):
    return Runner(server, tmp_path)


def yaml_doc(lists: dict[str, list[str]]) -> str:
    out = ["---", "url:"]
    for name, members in lists.items():
        out += [f"  - name: {name}", "    type: URL List", "    list:", "      member:" if members else "      member: []"]
        out += [f'        - "{m}"' for m in members]
    return "\n".join(out) + "\n"
