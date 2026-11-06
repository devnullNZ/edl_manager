"""PostgreSQL 16 integration tests: a real `uvicorn app.main:app` process on a real PostgreSQL database.

These complement (never replace) the SQLite suite. They drive the HTTP API directly; no importer is involved.
They SKIP, with the reason, unless a PostgreSQL 16 server can be reached or started:

    EDL_PG_URL=postgresql://user:pw@host:5432/postgres   an existing server; the role needs CREATEDB, each module
                                                         run creates and drops its own databases
    EDL_PG_BIN=/usr/lib/postgresql/16/bin                a PostgreSQL 16 installation: a throw-away cluster is
                                                         initialised and started in a temporary directory
                                                         (as the `postgres` user when run as root)
    EDL_SERVER_DIR=/path/to/extracted/edl-service       the server tree to run (default: this repository), so the
                                                         same file can verify the PACKAGED archive after extraction
    EDL_LEGACY_ARCHIVE=/path/to/edl-service-2.2.0.tar.gz  enables the v2.2.0 -> current upgrade test

    pytest tests/test_postgres.py -v -s

The tests share one server and database and run in file order on purpose (each uses its own EDL list); the
upgrade test uses a database of its own. The 64,000-entry tests take a few minutes.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg", reason="psycopg is not installed")

HERE = Path(__file__).resolve().parent
SERVER_DIR = Path(os.environ.get("EDL_SERVER_DIR", HERE.parent)).resolve()
LEGACY = os.environ.get("EDL_LEGACY_ARCHIVE")
API_KEY = "pg-test-api-key-0123456789abcdef"
LOG = print


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- PostgreSQL provisioning
class Cluster:
    """A PostgreSQL server we can create databases in."""

    def __init__(self, admin_dsn: str, cleanup=None):
        self.admin_dsn, self._cleanup = admin_dsn, cleanup
        with psycopg.connect(self.admin_dsn, autocommit=True) as c:
            self.version = c.execute("show server_version").fetchone()[0]
        major = int(self.version.split(".")[0])
        want = int(os.environ.get("EDL_PG_REQUIRE_MAJOR", "16"))
        assert major == want, f"PostgreSQL {want} is required (server_version {self.version})"
        self.made: list[str] = []

    def database(self, name: str) -> str:
        """Create an empty database; return the SQLAlchemy URL the application uses for it."""
        with psycopg.connect(self.admin_dsn, autocommit=True) as c:
            c.execute(f'drop database if exists "{name}"')
            c.execute(f'create database "{name}"')
        self.made.append(name)
        kw = psycopg.conninfo.conninfo_to_dict(self.admin_dsn)
        kw["dbname"] = name
        self.dsns = getattr(self, "dsns", {})
        self.dsns[name] = psycopg.conninfo.make_conninfo(**kw)
        return "postgresql+psycopg://" + _url_tail(kw)

    def dsn(self, name: str) -> str:
        return self.dsns[name]

    def close(self):
        try:
            with psycopg.connect(self.admin_dsn, autocommit=True) as c:
                for n in self.made:
                    c.execute(f'drop database if exists "{n}" with (force)')
        finally:
            if self._cleanup:
                self._cleanup()


def _url_tail(kw: dict) -> str:
    from urllib.parse import quote
    auth = quote(kw.get("user", "")) + (":" + quote(kw["password"]) if kw.get("password") else "")
    return f"{auth}@{kw.get('host', 'localhost')}:{kw.get('port', 5432)}/{kw['dbname']}"


def _find_bin() -> Path | None:
    """Opt-in only: the PostgreSQL tests run when EDL_PG_BIN (or EDL_PG_URL) is set, never by accident."""
    c = os.environ.get("EDL_PG_BIN")
    return Path(c) if c and (Path(c) / "initdb").is_file() else None


def _start_throwaway(bin_dir: Path) -> Cluster:
    root = Path(tempfile.mkdtemp(prefix="edl-pgtest-", dir="/var/tmp" if Path("/var/tmp").is_dir() else None))
    as_root = os.geteuid() == 0
    prefix: list[str] = []
    if as_root:
        shutil.chown(root, "postgres", "postgres")
        root.chmod(0o750)
        prefix = ["su", "postgres", "-s", "/bin/sh", "-c"]

    def run(cmd: str):
        full = prefix + [cmd] if as_root else ["/bin/sh", "-c", cmd]
        r = subprocess.run(full, capture_output=True, text=True, timeout=300)
        assert r.returncode == 0, f"{cmd}\n{r.stdout}\n{r.stderr}"

    data, port = root / "data", free_port()
    run(f"'{bin_dir}/initdb' -D '{data}' -A trust -U edl --no-sync -E UTF8")
    run(f"'{bin_dir}/pg_ctl' -D '{data}' -w -l '{root}/pg.log' "
        f"-o '-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off "
        f"-c max_connections=200' start")

    def cleanup():
        try:
            run(f"'{bin_dir}/pg_ctl' -D '{data}' -m fast -w stop")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    return Cluster(f"host=127.0.0.1 port={port} user=edl dbname=postgres", cleanup)


@pytest.fixture(scope="module")
def cluster():
    url = os.environ.get("EDL_PG_URL")
    if url:
        c = Cluster(url.replace("postgresql+psycopg://", "postgresql://"))
    else:
        b = _find_bin()
        if b is None:
            pytest.skip("PostgreSQL tests are opt-in: set EDL_PG_BIN (a PostgreSQL 16 bin directory) or EDL_PG_URL")
        c = _start_throwaway(b)
    LOG(f"\nPOSTGRESQL server_version {c.version}")
    yield c
    c.close()


# --------------------------------------------------------------------------- the application process
class Http:
    def __init__(self, base: str):
        self.base, self.token = base, ""

    def call(self, method, path, body=None, *, admin=False, timeout=1800):
        headers = {"Content-Type": "application/json"}
        headers.update({"X-API-Key": API_KEY} if admin else {"Authorization": f"Bearer {self.token}"})
        req = urllib.request.Request(self.base + path, method=method, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode(errors="replace")


class App(Http):
    def __init__(self, tree: Path, db_url: str, work: Path, name: str):
        self.tree, self.work = tree, work
        self.port = free_port()
        super().__init__(f"http://127.0.0.1:{self.port}")
        self.rules = work / f"{name}-rules.json"
        self.rules.write_text("{}")
        self.log = open(work / f"{name}-server.log", "ab")
        self.proc: subprocess.Popen | None = None
        self.env = {
            "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(work)),
            "DATABASE_URL": db_url, "API_KEY": API_KEY, "SECRET_KEY": "pg-test-secret-key-0123456789",
            "ENCRYPTION_KEY": "pg-test-encryption-key-0123456789", "ADMIN_PASSWORD": "pw",
            "ADMIN_COOKIE_SECURE": "false", "PANORAMA_MODE": "mock", "MOCK_CATEGORIES_FILE": str(self.rules),
            "CLASSIFICATION_ENABLED": "true", "PYTHONDONTWRITEBYTECODE": "1"}

    def start(self) -> dict:
        self.proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                                      "--port", str(self.port)], cwd=self.tree, env=self.env,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 120
        while time.time() < deadline:
            assert self.proc.poll() is None, f"server exited {self.proc.returncode}; see {self.log.name}"
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=2) as r:
                    return json.load(r)
            except OSError:
                time.sleep(0.3)
        raise AssertionError("server did not become healthy")

    def kill9(self):
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait(timeout=30)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def create_host(self, name="pgtest"):
        code = ("from app import db, hosts\nwith db.SessionLocal() as s:\n"
                f"    _, t = hosts.create_host(s, {name!r}, '127.0.0.1/32', '*')\n    print(t)\n")
        out = subprocess.run([sys.executable, "-c", code], cwd=self.tree, env=self.env, capture_output=True,
                             text=True, check=True)
        self.token = out.stdout.strip().splitlines()[-1]

    def settings(self, **values):
        s, b = self.call("PUT", "/v1/admin/settings", {"values": values, "confirm": True, "clear_secrets": []},
                         admin=True)
        assert s == 200, b

    def feed(self, name) -> list[str]:
        with urllib.request.urlopen(f"{self.base}/edl/{name}", timeout=300) as r:
            return [x for x in r.read().decode().splitlines() if x]

    def wait_until(self, fn, what, timeout=900, every=2.0):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(every)
        raise AssertionError(f"timed out waiting for {what}")

    # ---- sync helpers
    def sync(self, entries, *, lst, source, sync_id, expect=200, **opts):
        s, b = self.call("POST", f"/v1/lists/{lst}/sync", {"source": source, "sync_id": sync_id, "entries": entries,
                                                           **opts})
        assert s == expect, (s, str(b)[:800])
        return b

    def chunked(self, entries, *, lst, source, sync_id, chunk=4000, skip=(), commit=True, expect=200, **opts):
        commit_opts = {k: opts.pop(k) for k in ("max_removals", "dry_run") if k in opts}
        s, sess = self.call("POST", f"/v1/lists/{lst}/sync/sessions",
                            {"source": source, "sync_id": sync_id, **opts})
        assert s == 200, sess
        sid = sess["session_id"]
        parts = [entries[i:i + chunk] for i in range(0, len(entries), chunk)] or [[]]
        for i, part in enumerate(parts):
            if i in skip:
                continue
            s, b = self.call("PUT", f"/v1/lists/{lst}/sync/sessions/{sid}/chunks/{i}", {"entries": part})
            assert s == 200, (i, b)
        if not commit:
            return sid, parts, None
        s, b = self.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                         {"total_chunks": len(parts), "total_entries": len(entries), **commit_opts})
        assert s == expect, (s, str(b)[:800])
        return sid, parts, b


def ents(prefix, n, domain="pg.example.org"):
    return [f"{prefix}{i:06d}.{domain}" for i in range(n)]


class Db:
    def __init__(self, dsn):
        self.dsn = dsn

    def q(self, sql, *params):
        with psycopg.connect(self.dsn, autocommit=True) as c:
            return c.execute(sql, params).fetchall()

    def one(self, sql, *params):
        return self.q(sql, *params)[0][0]

    def fingerprint(self, *tables):
        """Row counts + an order-independent checksum of the given tables."""
        out = {}
        for t in tables:
            out[t] = tuple(self.q(f"select count(*), coalesce(md5(string_agg(x::text, '|' order by x::text)), '') "
                                  f"from {t} x")[0])
        return out


@pytest.fixture(scope="module")
def work():
    d = Path(tempfile.mkdtemp(prefix="edl-pgwork-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def app(cluster, work):
    assert (SERVER_DIR / "app" / "main.py").is_file(), SERVER_DIR
    url = cluster.database("edl_main")
    a = App(SERVER_DIR, url, work, "main")
    health = a.start()
    a.create_host()
    # a deployment expecting bulk work: continuous background processing and no request rate limit in the way
    a.settings(rate_limit_requests=0, max_batch_size=5000, processing_batch_delay_seconds=0,
               processing_interval_seconds=5, max_sync_size=500_000)
    LOG(f"\nSERVER TREE {SERVER_DIR} version {health.get('version')} on PostgreSQL {cluster.version}")
    a.db = Db(cluster.dsn("edl_main"))
    a.health = health
    yield a
    a.stop()


def wait_published(app, lst, n, timeout=900):
    app.wait_until(lambda: len(app.feed(lst)) == n, f"{n:,} entries of {lst!r} to be published", timeout=timeout,
                   every=3)


# =========================================================================== 1. upgrade 2.2.0 -> current
@pytest.mark.skipif(not LEGACY, reason="EDL_LEGACY_ARCHIVE (the v2.2.0 archive) is not set")
def test_01_upgrade_from_2_2_0_keeps_data_ownership_and_resumes_the_backlog(cluster, work):
    url = cluster.database("edl_upgrade")
    db = Db(cluster.dsn("edl_upgrade"))
    old_root = work / "legacy"
    old_root.mkdir()
    with tarfile.open(LEGACY) as tf:
        tf.extractall(old_root, filter="data")
    old_tree = [p for p in old_root.iterdir() if p.is_dir()][0]
    old = App(old_tree, url, work, "upgrade")
    ver_old = old.start()["version"]
    old.create_host()
    old.settings(rate_limit_requests=0)
    mine, other = ents("m", 3000, "up.example.org"), ents("m", 100, "up.example.org")
    old.sync(mine, lst="up", source="legacy", sync_id="old-1")               # 2000 classified inline, 1000 pending
    old.sync(other, lst="up", source="second", sync_id="old-2")              # a second owner of 100 of them
    before_cols = db.one("select count(*) from information_schema.columns where table_name = 'entries' "
                         "and column_name = 'reclass_job_id'")
    n_old, own_old = db.one("select count(*) from entries where list_name = 'up'"), \
        db.one("select count(*) from entry_sources where list_name = 'up'")
    old.stop()
    assert (ver_old, before_cols, n_old, own_old) == (ver_old, 0, 3000, 3100) and ver_old.startswith("2.2"), ver_old

    new = App(SERVER_DIR, url, work, "upgrade")
    new.rules, new.env["MOCK_CATEGORIES_FILE"] = old.rules, str(old.rules)    # seeded into the database at first start
    new.token = old.token
    try:
        ver_new = new.start()["version"]
        assert not ver_new.startswith("2.2")
        assert db.one("select count(*) from information_schema.columns where table_name = 'entries' "
                      "and column_name = 'reclass_job_id'") == 1
        assert {r[0] for r in db.q("select table_name from information_schema.tables where table_name in "
                                   "('sync_sessions','sync_chunks','sync_staged','reclass_jobs')")} == \
            {"sync_sessions", "sync_chunks", "sync_staged", "reclass_jobs"}
        assert db.one("select count(*) from pg_indexes where indexname = 'ix_entries_reclass_job_id'") == 1
        assert (db.one("select count(*) from entries where list_name = 'up'"),
                db.one("select count(*) from entry_sources where list_name = 'up'")) == (3000, 3100)   # nothing lost
        new.settings(rate_limit_requests=0, max_batch_size=5000, processing_batch_delay_seconds=0,
                     processing_interval_seconds=5)
        new.wait_until(lambda: len(new.feed("up")) == 3000, "the 2.2.0 pending backlog to be drained", 300, 2)

        # ownership reconciliation on the upgraded data: 'legacy' keeps 1000, so 2000 ownerships go; the 100
        # entries 'second' also owns survive even where 'legacy' lets go.
        s, rep = new.call("POST", "/v1/lists/up/sync", {"source": "legacy", "sync_id": "new-1", "entries": mine[:1000],
                                                        "delete_missing": True, "dry_run": True})
        assert s == 200 and rep["counts"]["removed"] == 2000
        new.chunked(mine[:1000], lst="up", source="legacy", sync_id="new-1", chunk=400, delete_missing=True)
        assert db.one("select count(*) from entries where list_name = 'up'") == 1000
        assert db.one("select count(*) from entry_sources where list_name = 'up' and source_id = 'second'") == 100
        assert db.one("select count(*) from entries where list_name = 'up'") == len(new.feed("up"))
    finally:
        new.stop()


# =========================================================================== 2-3. 64,000 entries, repeat
def test_02_chunked_sync_of_64000_entries(app):
    big = ents("a", 64000, "big.example.org")
    t0 = time.time()
    sid, parts, rep = app.chunked(big, lst="big", source="bulk", sync_id="b-1", chunk=4000)
    LOG(f"  64,000 entries in {len(parts)} chunks, committed in {time.time() - t0:.0f}s: counts {rep['counts']}")
    assert rep["status"] in ("applied", "applied_with_errors") and rep["counts"]["new"] == 64000
    assert app.db.one("select count(*) from entries where list_name = 'big'") == 64000
    assert app.db.one("select count(distinct value) from entries where list_name = 'big'") == 64000
    assert app.db.one("select count(*) from entry_sources where list_name = 'big' and source_id = 'bulk' "
                      "and host = 'pgtest'") == 64000
    assert app.db.one("select count(*) from sync_staged") == 0            # the staging area was cleaned up
    wait_published(app, "big", 64000)
    assert app.db.one("select count(*) from entries where list_name = 'big' and status = 'active'") == 64000


def test_03_identical_repeat_changes_nothing(app):
    big = ents("a", 64000, "big.example.org")
    before = app.db.fingerprint("entries", "entry_sources")
    feed_before = app.feed("big")
    sid, parts, rep = app.chunked(big, lst="big", source="bulk", sync_id="b-2", chunk=4000)
    assert rep["status"] == "no_change", rep["status"]
    c = rep["counts"]
    assert c["new"] == 0 and c["unchanged"] == 64000 and c["removed"] == 0
    assert app.db.fingerprint("entries", "entry_sources") == before
    assert app.feed("big") == feed_before
    # a repeated sync_id is answered from the stored run
    s, rep2 = app.call("POST", "/v1/lists/big/sync", {"source": "bulk", "sync_id": "b-2",
                                                      "entries": big[:10]})
    assert s == 409                                                       # same id, different content
    s, start = app.call("POST", "/v1/lists/big/sync/sessions", {"source": "bulk", "sync_id": "b-2"})
    assert s == 200 and start["status"] == "already_applied"            # nothing to upload again


# =========================================================================== 4. deletion and ownership
def test_04_deletion_ownership_and_the_removal_limit(app):
    lst = "own"
    a_all, b_all = ents("o", 6000, "own.example.org"), ents("o", 2000, "own.example.org")   # B shares A's first 2000
    app.chunked(a_all, lst=lst, source="alpha", sync_id="a-1", chunk=2000)
    app.chunked(b_all, lst=lst, source="beta", sync_id="b-1", chunk=2000)
    app.sync(["api-added.example.org"], lst="other", source="alpha", sync_id="x-1")        # another list, same source
    wait_published(app, lst, 6000)

    # default: nothing is removed, however much is missing
    rep = app.sync(a_all[:3000], lst=lst, source="alpha", sync_id="a-2")
    assert rep["counts"]["removed"] == 0 and app.db.one("select count(*) from entries where list_name = %s", lst) == 6000

    # dry run: no database change at all
    snap = app.db.fingerprint("entries", "entry_sources", "sync_runs", "sync_sources", "edl_snapshots", "audit_log",
                              "category_cache", "reclass_jobs")
    rep = app.sync(a_all[:3000], lst=lst, source="alpha", sync_id="a-3", delete_missing=True, dry_run=True,
                   max_removals=10)
    assert rep["counts"]["removed"] == 3000 and rep["would_exceed_max_removals"] is True
    assert app.db.fingerprint("entries", "entry_sources", "sync_runs", "sync_sources", "edl_snapshots", "audit_log",
                              "category_cache", "reclass_jobs") == snap

    # the server enforces the limit; nothing is applied
    sid, parts, _ = app.chunked(a_all[:3000], lst=lst, source="alpha", sync_id="a-3", chunk=1500,
                                delete_missing=True, commit=False)
    s, b = app.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                    {"total_chunks": 2, "total_entries": 3000, "max_removals": 10})
    assert s == 409 and b["detail"]["removal_limit_exceeded"] and b["detail"]["would_remove"] == 3000
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 6000
    assert app.db.one("select status from sync_sessions where id = %s", sid) == "receiving"      # retry possible
    s, b = app.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                    {"total_chunks": 2, "total_entries": 3000, "max_removals": 3000})
    assert s == 200 and b["counts"]["removed"] == 3000, b

    # alpha dropped o003000..o005999 (3000 ownerships, 3000 entries); beta's 2000 shared entries are untouched
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 3000
    assert app.db.one("select count(*) from entry_sources where list_name = %s and source_id like %s", lst,
                      "%beta") == 2000
    # now alpha drops the shared ones too: the entries stay because beta still owns them
    rep = app.sync(a_all[2000:3000], lst=lst, source="alpha", sync_id="a-4", delete_missing=True)
    assert rep["counts"]["removed"] == 2000 and rep["counts"]["entries_deleted"] == 0
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 3000
    # other list/source untouched; the feed equals the table
    assert app.db.one("select count(*) from entries where list_name = 'other'") == 1
    assert len(app.feed(lst)) == 3000 and app.db.one("select count(*) from entries where list_name = %s", lst) == 3000


# =========================================================================== 5. duplicates
def test_05_duplicates_inside_and_across_chunks(app):
    base = ents("d", 1000, "dup.example.org")
    variants = [f"HTTP://{e.upper()}/" for e in base[:100]] + [f"https://{e}" for e in base[100:200]]
    entries = base + base + variants + base[:50]                 # 1000 + 1000 + 200 + 50 occurrences
    sid, parts, rep = app.chunked(entries, lst="dup", source="d", sync_id="d-1", chunk=700)
    assert len(parts) == 4 and rep["counts"]["new"] == 1000
    assert rep["counts"]["duplicates_in_request"] == 1250
    assert app.db.one("select count(*) from entries where list_name = 'dup'") == 1000
    assert app.db.one("select count(distinct value) from entries where list_name = 'dup'") == 1000
    assert app.db.one("select count(*) from entry_sources where list_name = 'dup'") == 1000
    # the same content in another order and chunking is an unchanged desired state
    rep = app.chunked(list(reversed(entries)), lst="dup", source="d", sync_id="d-2", chunk=300)[2]
    assert rep["status"] == "no_change" and rep["counts"]["unchanged"] == 1000


# =========================================================================== 6. interruption and restart
def test_06_interrupted_session_survives_a_hard_server_kill_and_resumes(app):
    lst = "intr"
    app.sync(ents("keep", 500, "intr.example.org"), lst=lst, source="s", sync_id="seed")
    entries = ents("i", 30000, "intr.example.org")
    sid, parts, _ = app.chunked(entries, lst=lst, source="s", sync_id="i-1", chunk=3000, skip=(4, 7), commit=False,
                                delete_missing=True)
    # a commit with chunks missing is refused and changes nothing (in particular it deletes nothing)
    s, b = app.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                    {"total_chunks": len(parts), "total_entries": len(entries)})
    assert s == 409 and b["detail"]["nothing_applied"] is True
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 500
    app.kill9()                                                              # the server dies, un-gracefully
    app.start()
    s, st = app.call("GET", f"/v1/lists/{lst}/sync/sessions/{sid}")
    assert s == 200 and st["status"] == "receiving"
    assert app.db.one("select count(*) from sync_chunks where session_id = %s", sid) == 8   # persisted, not just acked
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 500      # still nothing applied
    # re-sending a chunk that already arrived is idempotent; a different body for the same index is refused
    s, b = app.call("PUT", f"/v1/lists/{lst}/sync/sessions/{sid}/chunks/0", {"entries": parts[0]})
    assert s == 200 and b.get("already_received") is True
    s, b = app.call("PUT", f"/v1/lists/{lst}/sync/sessions/{sid}/chunks/0", {"entries": parts[1]})
    assert s == 409
    for i in (4, 7):
        s, b = app.call("PUT", f"/v1/lists/{lst}/sync/sessions/{sid}/chunks/{i}", {"entries": parts[i]})
        assert s == 200, b
    s, rep = app.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                      {"total_chunks": len(parts), "total_entries": len(entries)})
    assert s == 200 and rep["counts"]["new"] == 30000 and rep["counts"]["removed"] == 500, rep["counts"]
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 30000
    # a commit repeated after the success returns the stored result, and a new start sees it as applied
    s, again = app.call("POST", f"/v1/lists/{lst}/sync/sessions/{sid}/commit",
                        {"total_chunks": len(parts), "total_entries": len(entries)})
    assert s == 200 and again["duplicate"] is True and again["run_id"] == rep["run_id"]
    # a session killed during the COMMIT's own work leaves the old state: simulate by an abort after restart
    sid2, parts2, _ = app.chunked(entries[:100], lst=lst, source="s", sync_id="i-2", chunk=50, commit=False,
                                  delete_missing=True)
    app.kill9()
    app.start()
    s, _ = app.call("DELETE", f"/v1/lists/{lst}/sync/sessions/{sid2}")
    assert s == 200
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 30000   # an aborted session removes nothing
    assert app.db.one("select count(*) from sync_staged where session_id = %s", sid2) == 0


# =========================================================================== 7. reclassification persistence
def test_07_reclassification_job_is_persisted_and_finished_after_a_hard_restart(app):
    lst = "recl"
    blocked = [f"a{i:03d}.blockme.test" for i in range(60)]
    fine = [f"b{i:03d}.fine.test" for i in range(240)]
    app.settings(background_processing_enabled=False, sync_classification_budget=30)
    app.rules.write_text(json.dumps({"*.blockme.test": "malware"}))
    app.sync(blocked + fine, lst=lst, source="r", sync_id="r-1")
    st = dict(app.db.q("select status, count(*) from entries where list_name = %s group by status", lst))
    assert st.get("blocked") == 30 and st.get("pending") == 270, st       # 30 inline (all 'a*' sorted first), rest pending

    # Panorama now says everything is clean; request reclassification of all 300 with a small inline budget
    app.rules.write_text("{}")
    os.utime(app.rules, (time.time() + 5, time.time() + 5))
    app.settings(sync_classification_budget=40)
    rep = app.sync(blocked + fine, lst=lst, source="r", sync_id="r-2", reclassify=True)
    rc = rep["reclassification"]
    assert rc["requested"] and rc["in_scope"] == 300 and rc["remaining"] > 0 and rc["status"] != "done", rc
    job = rc["job_id"]
    assert app.db.one("select status from reclass_jobs where id = %s", job) == "running"
    flagged = app.db.one("select count(*) from entries where reclass_job_id = %s", job)
    assert flagged == rc["remaining"] > 0                                  # the work list is in the database

    app.kill9()
    app.start()
    assert app.db.one("select status from reclass_jobs where id = %s", job) == "running"
    assert app.db.one("select count(*) from entries where reclass_job_id = %s", job) == flagged   # survived the kill
    s, b = app.call("GET", f"/v1/lists/{lst}/sync/reclassifications/{job}")
    assert s == 200 and b["status"] == "running" and b["remaining"] == flagged

    app.settings(background_processing_enabled=True, max_batch_size=100, processing_batch_delay_seconds=0,
                 processing_interval_seconds=5)
    app.wait_until(lambda: app.db.one("select status from reclass_jobs where id = %s", job) == "done",
                   "the persisted reclassification job to finish", 300, 2)
    assert app.db.one("select count(*) from entries where reclass_job_id is not null") == 0
    assert dict(app.db.q("select status, count(*) from entries where list_name = %s group by status", lst)) == \
        {"active": 300}                                                    # blocked entries were reconsidered
    assert len(app.feed(lst)) == 300


# =========================================================================== 8. concurrent syncs
def test_08_concurrent_syncs_are_serialised_and_idempotent(app):
    lst = "conc"
    app.settings(rate_limit_requests=0, background_processing_enabled=True)
    shared = ents("shared", 500, "conc.example.org")
    sources = [f"src{i}" for i in range(6)]
    results, errors = {}, []

    def one(src):
        try:
            own = ents(src, 2000, "conc.example.org")
            for attempt in range(40):                                       # 503 = another sync running: retry
                s, b = app.call("POST", f"/v1/lists/{lst}/sync", {"source": src, "sync_id": f"{src}-1",
                                                                 "entries": shared + own})
                if s != 503:
                    break
                time.sleep(1)
            results[src] = (s, b)
        except Exception as e:                                              # noqa: BLE001
            errors.append(repr(e))

    ts = [threading.Thread(target=one, args=(s,)) for s in sources]
    [t.start() for t in ts]
    [t.join(900) for t in ts]
    assert not errors, errors
    assert all(s == 200 for s, _ in results.values()), {k: (v[0], str(v[1])[:200]) for k, v in results.items()}
    assert app.db.one("select count(*) from entries where list_name = %s", lst) == 500 + 6 * 2000
    assert app.db.one("select count(distinct value) from entries where list_name = %s", lst) == 12500
    for src in sources:
        assert app.db.one("select count(*) from entry_sources where list_name = %s and source_id like %s", lst,
                          f"%{src}") == 2500
    assert app.db.one("select count(*) from sync_runs where list_name = %s and status <> 'failed'", lst) == 6

    # the same sync_id sent by 6 clients at once is applied exactly once; the others get the stored result
    out, barrier = [], threading.Barrier(6)

    def same():
        barrier.wait()
        for _ in range(40):
            s, b = app.call("POST", f"/v1/lists/{lst}/sync", {"source": "twin", "sync_id": "twin-1",
                                                             "entries": ents("twin", 300, "conc.example.org")})
            if s != 503:
                break
            time.sleep(1)
        out.append((s, b))

    ts = [threading.Thread(target=same) for _ in range(6)]
    [t.start() for t in ts]
    [t.join(600) for t in ts]
    assert [s for s, _ in out] == [200] * 6, [(s, str(b)[:150]) for s, b in out]
    assert sum(1 for _, b in out if not b.get("duplicate")) == 1
    assert len({b["run_id"] for _, b in out}) == 1
    assert app.db.one("select count(*) from sync_runs where list_name = %s and sync_id = 'twin-1'", lst) == 1

    # racing destructive syncs of one source: neither exceeds the server-enforced limit, the list never ends
    # in a state neither of them asked for
    app.sync(ents("race", 100, "conc.example.org"), lst=lst, source="racer", sync_id="race-0")
    res, barrier = {}, threading.Barrier(2)

    def race(name, keep):
        barrier.wait()
        for _ in range(40):
            s, b = app.call("POST", f"/v1/lists/{lst}/sync", {
                "source": "racer", "sync_id": name, "entries": ents("race", keep, "conc.example.org"),
                "delete_missing": True, "max_removals": 30})
            if s != 503:
                break
            time.sleep(1)
        res[name] = (s, b)

    ts = [threading.Thread(target=race, args=("race-a", 80)), threading.Thread(target=race, args=("race-b", 50))]
    [t.start() for t in ts]
    [t.join(600) for t in ts]
    for name, (s, b) in res.items():
        assert s in (200, 409), (name, s, str(b)[:200])
        if s == 200:
            assert b["counts"]["removed"] <= 30
        else:
            assert b["detail"]["removal_limit_exceeded"] is True
    owned = app.db.one("select count(*) from entry_sources where list_name = %s and source_id like '%%racer'", lst)
    # a then b: 100->80 (20 removed) then 80->50 (30 removed) = 50. b first needs 50 > 30: refused, then a = 80.
    assert owned in (50, 80), owned
    assert any(s == 200 for s, _ in res.values())
