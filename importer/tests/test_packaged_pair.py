"""The PACKAGED pair: a server archive and this importer, tested together as separate processes.

Unlike the other integration tests (which import the server's source tree into the test process), these tests

  * extract the server archive given in EDL_SERVER_ARCHIVE (edl-service.tar.gz) into a scratch directory,
  * start it as a real `uvicorn app.main:app` process with a file database and the mock Panorama,
  * run the importer file that sits next to this tests/ directory (so: the importer as extracted from its own ZIP)
    as a subprocess, over HTTP,

and nothing from either package is imported by the test process. Without EDL_SERVER_ARCHIVE the tests are SKIPPED.

    EDL_SERVER_ARCHIVE=/path/to/edl-service.tar.gz python -m pytest tests/test_packaged_pair.py -v -s

The tests share one server (state flows between them on purpose, each uses its own EDL list); the last one restarts
it. They take several minutes: 64,000- and 100,000-entry imports are real.
"""
import hashlib
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
IMPORTER = HERE.parent / "import_edl.py"
ARCHIVE = os.environ.get("EDL_SERVER_ARCHIVE")
pytestmark = pytest.mark.skipif(not ARCHIVE, reason="EDL_SERVER_ARCHIVE is not set (packaged-pair tests)")

API_KEY = "packaged-test-api-key-0123456789"


def yaml_doc(lists):
    out = ["---", "url:"]
    for name, members in lists.items():
        out += [f"  - name: {name}", "    type: URL List", "    list:", "      member:" if members else "      member: []"]
        out += [f'        - "{m}"' for m in members]
    return "\n".join(out) + "\n"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, root: Path, archive: Path):
        self.root = root
        with tarfile.open(archive) as tf:
            tf.extractall(root / "server", filter="data")
        tops = [p for p in (root / "server").iterdir() if p.is_dir()]
        assert len(tops) == 1 and (tops[0] / "app" / "main.py").is_file(), "unexpected archive layout"
        self.dir = tops[0]
        self.db = root / "edl.db"
        self.rules = root / "mock-rules.json"
        self.rules.write_text("{}")
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None
        self.log = open(root / "server.log", "ab")
        self.token = ""
        self.env = {
            "PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(root)),
            "DATABASE_URL": f"sqlite:///{self.db}", "API_KEY": API_KEY, "SECRET_KEY": "packaged-test-secret-key-123456",
            "ENCRYPTION_KEY": "packaged-test-encryption-key-123456", "ADMIN_PASSWORD": "pw", "ADMIN_COOKIE_SECURE": "false",
            "PANORAMA_MODE": "mock", "MOCK_CATEGORIES_FILE": str(self.rules), "CLASSIFICATION_ENABLED": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def start(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=self.dir, env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited with {self.proc.returncode}; see {self.root / 'server.log'}")
            try:
                with urllib.request.urlopen(self.url + "/healthz", timeout=2) as r:
                    if r.status == 200:
                        return json.load(r)
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("server did not become healthy")

    def kill9(self):
        assert self.proc is not None
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait(timeout=30)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def create_host(self):
        code = ("from app import db, hosts\n"
                "with db.SessionLocal() as s:\n"
                "    _, t = hosts.create_host(s, 'importer', '127.0.0.1/32', '*')\n"
                "    print(t)\n")
        out = subprocess.run([sys.executable, "-c", code], cwd=self.dir, env=self.env, capture_output=True, text=True,
                             check=True)
        self.token = out.stdout.strip().splitlines()[-1]

    # ---- API helpers
    def admin(self, method, path, body=None):
        req = urllib.request.Request(self.url + path, method=method, headers={"X-API-Key": API_KEY,
                                     "Content-Type": "application/json"},
                                     data=json.dumps(body).encode() if body is not None else None)
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    def settings(self, **values):
        self.admin("PUT", "/v1/admin/settings", {"values": values, "confirm": True, "clear_secrets": []})

    def host_get(self, path):
        req = urllib.request.Request(self.url + path, headers={"Authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    def feed(self, name):
        with urllib.request.urlopen(f"{self.url}/edl/{name}", timeout=120) as r:
            return [x for x in r.read().decode().splitlines() if x]

    def sql(self, query, *params):
        con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True, timeout=30)
        try:
            return con.execute(query, params).fetchall()
        finally:
            con.close()

    def statuses(self, lst):
        return dict(self.sql("select status, count(*) from entries where list_name = ? group by status", lst))

    def wait_until(self, fn, what, timeout=420, every=2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = fn()
            if v:
                return v
            time.sleep(every)
        raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    archive = Path(ARCHIVE).resolve()
    assert archive.is_file(), archive
    s = Server(tmp_path_factory.mktemp("packaged"), archive)
    health = s.start()
    s.create_host()
    # a deployment that expects bulk imports: fast, continuous background processing and no rate limit in the way
    s.settings(rate_limit_requests=1_000_000, max_batch_size=5000, processing_batch_delay_seconds=0,
               processing_interval_seconds=5, max_sync_size=500_000)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    isha = hashlib.sha256(IMPORTER.read_bytes()).hexdigest()
    print(f"\nPACKAGED PAIR: server archive {archive.name} sha256 {sha[:16]} (app {health.get('version')}); "
          f"importer {IMPORTER} sha256 {isha[:16]}")
    s.health = health
    yield s
    s.stop()


FAULT = r"""
import os, resource, sys
sys.path.insert(0, {importer_dir!r})
import import_edl as imp
limit = int(os.environ.get("KILL_AFTER_CHUNKS", "0"))
if limit:
    orig, n = imp.Api.put_chunk, {{"c": 0}}
    def put(self, *a, **k):
        r = orig(self, *a, **k)
        n["c"] += 1
        if n["c"] >= limit:
            os._exit(137)          # the process dies right after the server acknowledged this chunk
        return r
    imp.Api.put_chunk = put
try:
    code = imp.main(sys.argv[1:])
finally:
    print("MAXRSS_KB=%d" % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, file=sys.stderr)
raise SystemExit(code)
"""


def run_importer(srv, tmp, lists, *args, kill_after=0, name="in.yaml", timeout=1800, yaml_text=None):
    p = tmp / name
    p.write_text(yaml_text if yaml_text is not None else yaml_doc(lists), encoding="utf-8")
    report = tmp / (name + ".report.json")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(tmp)),
           "KILL_AFTER_CHUNKS": str(kill_after)}
    cmd = [sys.executable, "-c", FAULT.format(importer_dir=str(IMPORTER.parent)), str(p), "--base-url", srv.url,
           "--token", srv.token, "--report-file", str(report), *args]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    r.report = json.loads(report.read_text()) if report.exists() else None
    r.state = (json.loads(Path(str(p) + ".import-state.json").read_text())
               if Path(str(p) + ".import-state.json").exists() else None)
    r.yaml = p
    m = [ln for ln in r.stderr.splitlines() if ln.startswith("MAXRSS_KB=")]
    r.maxrss_mb = int(m[-1].split("=")[1]) / 1024 if m else None
    return r


def ents(prefix, n, domain="bulk.example.org"):
    return [f"{prefix}{i:06d}.{domain}" for i in range(n)]


@pytest.fixture
def tmp(tmp_path):
    return tmp_path


def drained(srv, lst, total):
    return lambda: len(srv.feed(lst)) == total and srv.statuses(lst) == {"active": total}


# ====================================================================================================== 0. the pair
def test_packaged_server_is_the_expected_release_and_has_every_endpoint_the_importer_uses(srv):
    assert srv.health["version"] == "2.3.1", srv.health
    spec = json.load(urllib.request.urlopen(srv.url + "/openapi.json", timeout=30))
    for path in ("/v1/lists/{name}/sync", "/v1/lists/{name}/sync/sessions",
                 "/v1/lists/{name}/sync/sessions/{session_id}",
                 "/v1/lists/{name}/sync/sessions/{session_id}/chunks/{index}",
                 "/v1/lists/{name}/sync/sessions/{session_id}/commit",
                 "/v1/lists/{name}/sync/sessions/{session_id}/invalid",
                 "/v1/lists/{name}/sync/reclassifications/{job_id}"):
        assert path in spec["paths"], path
    for model in ("SyncIn", "SessionStart"):
        assert "reclassify" in spec["components"]["schemas"][model]["properties"]
    for model in ("SyncIn", "CommitIn"):
        assert "max_removals" in spec["components"]["schemas"][model]["properties"]


# ====================================================================================================== 1. 64,000
def test_01_initial_64000_entry_import(srv, tmp):
    r = run_importer(srv, tmp, {"big64": ents("a", 64000)})
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    assert "Entries newly created by the server:   64,000" in r.stdout
    assert "7 chunk(s)" in r.stdout or "chunk(s) of up to 10,000" in r.stdout
    u = r.report["units"][0]
    assert u["occurrences_submitted"] == 64000 and u["chunks"] == 7 and u["server_new"] == 64000
    assert srv.sql("select count(*) from entries where list_name='big64'")[0][0] == 64000
    # uploaded is not published: only the sync classification budget (2000) was classified inside the request
    assert "CLASSIFICATION IS STILL PENDING" in r.stdout
    # the server's background engine now drains the backlog batch after batch without further requests
    srv.wait_until(drained(srv, "big64", 64000), "the engine to classify and publish all 64,000 entries")
    print(f"01: importer peak RSS {r.maxrss_mb:.0f} MB")


# ====================================================================================================== 2. repeat
def test_02_identical_repeat_import_changes_nothing(srv, tmp):
    before = srv.sql("select count(*), min(id), max(id) from entries where list_name='big64'")
    runs = srv.sql("select count(*) from sync_runs")[0][0]
    r = run_importer(srv, tmp, {"big64": ents("a", 64000)})
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    assert "Entries newly created by the server:   0" in r.stdout
    assert srv.sql("select count(*), min(id), max(id) from entries where list_name='big64'") == before
    last = srv.sql("select status from sync_runs order by id desc limit 1")[0][0]
    assert last == "no_change" and srv.sql("select count(*) from sync_runs")[0][0] == runs + 1
    assert len(srv.feed("big64")) == 64000


# ====================================================================================================== 3. duplicates
def test_03_duplicates_reach_the_server_with_no_deduplicate_and_it_prevents_duplicate_rows(srv, tmp):
    base = [f"d{i:04d}.dups.example.org" for i in range(1000)]
    occurrences = []
    for i, b in enumerate(base):
        occurrences += [b, b.upper(), f" {b} ", f"https://{b}:443/", f"{b}/"]     # five spellings, one entry
    paths = [f"p{i:03d}.dups.example.org/x" for i in range(100)]
    occurrences += paths + [p + "/" for p in paths]                                # trailing slash: DIFFERENT entries
    occurrences += [f"q.dups.example.org/p?x={i}#f{i}" for i in range(50)]         # query/fragment: all one entry
    expected_unique = 1000 + 200 + 1
    # (a) importer-side deduplication OFF: every occurrence is submitted, across several upload chunks
    r = run_importer(srv, tmp, {"dups": occurrences}, "--no-deduplicate", "--chunk-size", "700", "--mode", "chunked")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    u = r.report["units"][0]
    assert u["occurrences_submitted"] == len(occurrences) and u["duplicates_removed_by_importer"] is None
    assert "deduplication disabled; none performed" in r.stdout
    assert u["chunks"] == -(-len(occurrences) // 700) and u["chunks"] > 5
    assert u["server_new"] == expected_unique
    assert u["server_duplicates_in_submission"] == len(occurrences) - expected_unique
    rows = srv.sql("select count(*), count(distinct value) from entries where list_name='dups'")[0]
    assert rows == (expected_unique, expected_unique)                               # no duplicate database rows
    feed = srv.feed("dups")
    srv.wait_until(lambda: len(srv.feed("dups")) == expected_unique, "all unique entries published", timeout=120)
    feed = srv.feed("dups")
    assert len(feed) == len(set(feed)) == expected_unique                           # no duplicate EDL lines
    assert "p001.dups.example.org/x" in feed and "p001.dups.example.org/x/" in feed
    assert sum(1 for x in feed if x.startswith("q.dups.example.org/")) == 1
    # (b) importer-side deduplication ON gives the identical result and says what it removed
    r2 = run_importer(srv, tmp, {"dups_on": occurrences}, "--deduplicate")
    assert r2.returncode == 0
    u2 = r2.report["units"][0]
    assert u2["duplicates_removed_by_importer"] == len(occurrences) - expected_unique
    assert u2["occurrences_submitted"] == expected_unique
    srv.wait_until(lambda: len(srv.feed("dups_on")) == expected_unique, "dups_on published", timeout=120)
    assert sorted(srv.feed("dups_on")) == sorted(feed)


# ====================================================================================================== 4 + 5. deletion
def shared_lists():
    s1_all = [f"s1-{i:04d}.share.example.org" for i in range(3000)]
    s2 = [f"s2-{i:04d}.share.example.org" for i in range(1000)] + s1_all[:500]       # s2 also owns 500 of s1's
    return s1_all, s2


def test_04_delete_missing_removes_only_this_sources_entries_and_shows_the_count_first(srv, tmp):
    s1_all, s2 = shared_lists()
    r = run_importer(srv, tmp, {"s1": s1_all, "s2": s2}, "--target-list", "shared", "--chunk-size", "1000")
    assert r.returncode == 0, r.stdout[-3000:]
    srv.wait_until(lambda: len(srv.feed("shared")) == len(set(s1_all) | set(s2)), "initial publication", timeout=180)
    s1_small = s1_all[2000:3000]                                                    # drops 2000, of which 500 are s2's
    r = run_importer(srv, tmp, {"s1": s1_small, "s2": s2}, "--target-list", "shared", "--chunk-size", "600",
                     "--delete-missing", name="shrunk.yaml")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    assert "[s1] --delete-missing: committing will remove 2,000 entries" in r.stdout
    assert "(1,500 deleted outright, 500 kept because another source also owns them)" in r.stdout
    assert r.stdout.index("committing will remove 2,000") < r.stdout.index("Import summary")
    expected = {f"{x}/" for x in s1_small} | {f"{x}/" for x in s2}
    assert set(srv.feed("shared")) == expected                                      # s2's entries all survive
    # nothing at all was removed from the sources that were not part of this call
    assert len(srv.feed("big64")) == 64000


def test_05_without_delete_missing_nothing_is_removed(srv, tmp):
    entries = [f"k{i:04d}.keep.example.org" for i in range(3000)]
    assert run_importer(srv, tmp, {"keep": entries}, "--chunk-size", "1000").returncode == 0
    srv.wait_until(lambda: len(srv.feed("keep")) == 3000, "publication", timeout=180)
    r = run_importer(srv, tmp, {"keep": entries[:1000]}, "--chunk-size", "1000", name="smaller.yaml")
    assert r.returncode == 0, r.stdout[-3000:]
    assert "committing will remove" not in r.stdout                                  # deletion not enabled: no preview
    assert "kept, NOT removed because --delete-missing is not set: 2,000" in r.stdout
    assert len(srv.feed("keep")) == 3000
    # --server-dry-run with --delete-missing shows the count and still deletes nothing
    r = run_importer(srv, tmp, {"keep": entries[:1000]}, "--server-dry-run", "--delete-missing", name="smaller.yaml")
    assert r.returncode == 0 and "Would remove (no longer listed):       2,000" in r.stdout
    assert len(srv.feed("keep")) == 3000
    # the local dry run never contacts the server
    r = run_importer(srv, tmp, {"keep": entries[:1000]}, "--dry-run", "--delete-missing", name="smaller.yaml")
    assert r.returncode == 0 and len(srv.feed("keep")) == 3000
    # and --max-removals refuses before anything is committed
    r = run_importer(srv, tmp, {"keep": entries[:1000]}, "--delete-missing", "--max-removals", "100", "--chunk-size", "500",
                     name="smaller.yaml")
    assert r.returncode == 1 and "--max-removals is 100" in r.stdout + r.stderr and len(srv.feed("keep")) == 3000


# ====================================================================================================== 6. interrupt
def test_06_interrupted_chunk_upload_resumes_without_a_new_session_and_never_applies_early(srv, tmp):
    entries = ents("i", 30000, "intr.example.org")
    r = run_importer(srv, tmp, {"intr": entries}, "--chunk-size", "2000", kill_after=4)
    assert r.returncode == 137, (r.returncode, r.stdout[-1500:], r.stderr[-1500:])      # the importer process died
    assert srv.sql("select count(*) from entries where list_name='intr'")[0][0] == 0   # a partial upload applied nothing
    assert srv.sql("select count(*) from sync_runs where list_name='intr'")[0][0] == 0
    unit = next(iter(r.state["units"].values()))
    sync_id, session = unit["sync_id"], unit["session_id"]
    # The process died right after the server acknowledged chunk 3 and BEFORE the checkpoint recorded it: the server
    # holds 4 chunks, the checkpoint knows 3. (The worst moment to die; resume must cope with it.)
    assert sorted(map(int, unit["uploaded"])) == [0, 1, 2] and unit["status"] == "uploading"
    assert srv.sql("select received_chunks, status from sync_sessions where id=?", session)[0] == (4, "receiving")
    # a plain re-run must not silently start over
    again = run_importer(srv, tmp, {"intr": entries}, "--chunk-size", "2000")
    assert again.returncode == 2 and "unfinished checkpoint" in again.stdout + again.stderr
    r = run_importer(srv, tmp, {"intr": entries}, "--chunk-size", "2000", "--resume")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    u = r.report["units"][0]
    # chunk 3 is sent again to the SAME session and acknowledged as already received; chunks 4..14 are new
    assert u["chunks"] == 15 and u["chunks_sent_this_run"] == 12 and u["chunks_already_on_server"] == 3
    assert r.stdout.count("(already on the server)") == 1 and "uploaded chunk 4/15 (already on the server)" in r.stdout
    assert u["sync_id"] == sync_id
    assert srv.sql("select count(*) from sync_sessions where list_name='intr'")[0][0] == 1       # no second session
    assert srv.sql("select count(*) from entries where list_name='intr'")[0][0] == 30000
    # the checkpoint is kept, marked completed, with the server's confirmation
    final = next(iter(json.loads(Path(str(r.yaml) + ".import-state.json").read_text())["units"].values()))
    assert final["status"] == "completed" and final["sync_id"] == sync_id


# ====================================================================================================== 7. reclassify
def test_07_reclassification_of_blocked_and_pending_entries(srv, tmp):
    blocked = [f"a{i:02d}.blockme.test" for i in range(10)]
    pending = [f"b{i:02d}.fine.test" for i in range(40)]
    srv.rules.write_text(json.dumps({"*.blockme.test": "malware"}))
    srv.settings(background_processing_enabled=False, sync_classification_budget=10)
    # first import: the budget covers 10 lookups (the first ten targets, which are the blocked ones); 40 stay pending
    r = run_importer(srv, tmp, {"recl": blocked + pending})
    assert r.returncode == 0, r.stdout[-3000:]
    assert srv.statuses("recl") == {"blocked": 10, "pending": 40}
    assert srv.feed("recl") == []
    # Panorama's opinion changes, and the budget is lifted. WITHOUT --reclassify the cached answers are preserved:
    srv.rules.write_text("{}")
    os.utime(srv.rules, (time.time() + 5, time.time() + 5))
    srv.settings(sync_classification_budget=2000)
    r = run_importer(srv, tmp, {"recl": blocked + pending})
    assert r.returncode == 0 and "Reclassification" not in r.stdout
    assert srv.statuses("recl") == {"blocked": 10, "pending": 40}                   # existing results preserved
    # WITH --reclassify every existing entry is asked again, blocked and pending alike
    r = run_importer(srv, tmp, {"recl": blocked + pending}, "--reclassify")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    assert "Reclassification (job" in r.stdout and "50 existing entries" in r.stdout
    assert srv.statuses("recl") == {"active": 50}
    assert len(srv.feed("recl")) == 50
    rc = r.report["units"][0]["reclassification"]
    assert rc["status"] == "done" and rc["in_scope"] == 50 and rc["changed_inline"] == 50
    # and reclassification works in the other direction too: Panorama now flags the first ten again
    srv.rules.write_text(json.dumps({"*.blockme.test": "malware"}))
    os.utime(srv.rules, (time.time() + 10, time.time() + 10))
    r = run_importer(srv, tmp, {"recl": blocked + pending}, "--reclassify")
    assert r.returncode == 0
    assert srv.statuses("recl") == {"active": 40, "blocked": 10}
    assert len(srv.feed("recl")) == 40
    srv.settings(background_processing_enabled=True)


# ====================================================================================================== 8. 100,000
def test_08_100000_entry_chunked_import(srv, tmp):
    r = run_importer(srv, tmp, {"huge": ents("h", 100000, "huge.example.org")}, "--chunk-size", "10000", "--mode", "chunked")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    u = r.report["units"][0]
    assert u["chunks"] == 10 and u["chunks_sent_this_run"] == 10 and u["server_new"] == 100000
    assert "Entries newly created by the server:   100,000" in r.stdout
    assert srv.sql("select count(*) from entries where list_name='huge'")[0][0] == 100000
    assert r.maxrss_mb is not None and r.maxrss_mb < 400, r.maxrss_mb                 # bounded importer memory
    print(f"08: importer peak RSS {r.maxrss_mb:.0f} MB for 100,000 entries")
    srv.wait_until(drained(srv, "huge", 100000), "the engine to publish all 100,000 entries", timeout=900, every=5)
    assert len(srv.feed("huge")) == 100000
    # another run of the same file is a no-op
    again = run_importer(srv, tmp, {"huge": ents("h", 100000, "huge.example.org")}, "--chunk-size", "10000")
    assert again.returncode == 0 and "Entries newly created by the server:   0" in again.stdout


# ====================================================================================================== 9. restart
def test_09_server_restart_during_an_incomplete_sync(srv, tmp):
    entries = ents("r", 30000, "restart.example.org")
    r = run_importer(srv, tmp, {"restart": entries}, "--chunk-size", "3000", kill_after=4)
    assert r.returncode == 137
    unit = next(iter(r.state["units"].values()))
    sync_id, session = unit["sync_id"], unit["session_id"]
    assert srv.sql("select count(*) from entries where list_name='restart'")[0][0] == 0
    srv.kill9()                                                                       # the SERVER dies, uncleanly
    srv.start()
    # the staged chunks survived in the database; nothing was applied
    st = srv.host_get(f"/v1/lists/restart/sync/sessions/{session}")
    assert st["status"] == "receiving" and st["received_chunks"] == 4 and st["received_ranges"] == [[0, 3]]
    assert srv.sql("select count(*) from entries where list_name='restart'")[0][0] == 0
    r = run_importer(srv, tmp, {"restart": entries}, "--chunk-size", "3000", "--resume")
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    u = r.report["units"][0]
    assert u["sync_id"] == sync_id and u["chunks"] == 10 and u["chunks_sent_this_run"] == 7   # chunk 3 again, 4..9 new
    assert u["chunks_already_on_server"] == 3 and r.stdout.count("(already on the server)") == 1
    assert srv.sql("select count(*) from sync_sessions where list_name='restart'")[0][0] == 1
    assert srv.sql("select count(*), count(distinct value) from entries where list_name='restart'")[0] == (30000, 30000)
    # earlier data survived the restart too
    assert srv.sql("select count(*) from entries where list_name='big64'")[0][0] == 64000


# ====================================================================================================== older server
LEGACY = os.environ.get("EDL_LEGACY_ARCHIVE")


def host_call(srv, method, path, body):
    req = urllib.request.Request(srv.url + path, method=method, data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {srv.token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_11_the_packaged_server_enforces_max_removals_itself_and_the_importer_passes_it_on(srv, tmp):
    lst, all_ = "lim", ents("z", 200, "limit.example.org")
    st, b = host_call(srv, "POST", f"/v1/lists/{lst}/sync", {"source": "raw", "sync_id": "1", "entries": all_})
    assert st == 200
    # a request the importer's preview never saw: the SERVER refuses, and nothing changes
    st, b = host_call(srv, "POST", f"/v1/lists/{lst}/sync", {"source": "raw", "sync_id": "2", "entries": all_[:50],
                                                            "delete_missing": True, "max_removals": 100})
    assert st == 409 and b["detail"]["removal_limit_exceeded"] and b["detail"]["would_remove"] == 150, b
    assert srv.sql("select count(*) from entry_sources where list_name = 'lim'")[0][0] == 200
    st, b = host_call(srv, "POST", f"/v1/lists/{lst}/sync", {"source": "raw", "sync_id": "2", "entries": all_[:50],
                                                            "delete_missing": True, "max_removals": 150})
    assert st == 200 and b["counts"]["removed"] == 150 and not b.get("duplicate")        # the refused id was reusable
    # through the importer: the limit is part of the request that commits
    entries = ents("w", 3000, "limit2.example.org")
    assert run_importer(srv, tmp, {"lim2": entries}, "--chunk-size", "1000").returncode == 0
    r = run_importer(srv, tmp, {"lim2": entries[:2500]}, "--chunk-size", "1000", "--delete-missing",
                     "--max-removals", "500", name="lim2.yaml")
    assert r.returncode == 0, r.stdout[-2500:] + r.stderr[-1500:]
    assert "committing will remove 500 entries" in r.stdout
    assert srv.sql("select count(*) from entry_sources where list_name = 'lim2'")[0][0] == 2500


@pytest.mark.skipif(not LEGACY, reason="EDL_LEGACY_ARCHIVE (the previously delivered v2.2.0 archive) is not set")
def test_10_against_the_previous_v220_archive_single_mode_works_and_unsupported_features_are_refused(tmp_path):
    s = Server(tmp_path / "legacy", Path(LEGACY).resolve())
    health = s.start()
    try:
        assert health["version"] == "2.2.0", health
        s.create_host()
        entries = ents("L", 3000, "legacy.example.org")
        # default import, single request (the 2.2.0 server has no chunked sessions)
        r = run_importer(s, tmp_path, {"old": entries}, "--mode", "single")
        assert r.returncode == 0, r.stdout[-2500:] + r.stderr[-1500:]
        assert s.sql("select count(*) from entries where list_name='old'")[0][0] == 3000
        # deletion preview + removal use only the 'dry_run' / 'delete_missing' fields the 2.2.0 server defines
        r = run_importer(s, tmp_path, {"old": entries[:2000]}, "--mode", "single", "--delete-missing", name="small.yaml")
        assert r.returncode == 0, r.stdout[-2500:] + r.stderr[-1500:]
        assert "committing will remove 1,000 entries" in r.stdout
        assert s.sql("select count(*) from entries where list_name='old'")[0][0] == 2000
        # features the 2.2.0 server cannot do are refused clearly, before anything is sent
        r = run_importer(s, tmp_path, {"old": entries}, "--reclassify", name="rc.yaml")
        assert r.returncode == 3 and "no 'reclassify' option" in r.stdout + r.stderr
        r = run_importer(s, tmp_path, {"old": entries}, "--mode", "chunked", "--chunk-size", "500", name="ch.yaml")
        assert r.returncode == 1 and "does not offer chunked sync" in r.stdout + r.stderr
        assert s.sql("select count(*) from entries where list_name='old'")[0][0] == 2000
        # a server without max_removals: the importer says so, and its own preview check still protects
        r = run_importer(s, tmp_path, {"old": entries[:1900]}, "--mode", "single", "--delete-missing",
                         "--max-removals", "500", name="lim.yaml")
        assert r.returncode == 0 and "cannot enforce --max-removals itself" in r.stdout + r.stderr, r.stdout[-1500:]
        assert s.sql("select count(*) from entries where list_name='old'")[0][0] == 1900
        r = run_importer(s, tmp_path, {"old": entries[:1000]}, "--mode", "single", "--delete-missing",
                         "--max-removals", "50", name="lim2.yaml")
        assert r.returncode == 1 and s.sql("select count(*) from entries where list_name='old'")[0][0] == 1900
    finally:
        s.stop()
