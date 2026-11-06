"""Importer behaviour against a scripted fake server: failure injection, capability checks, bounded memory."""
import io
import json
import tracemalloc
from contextlib import redirect_stderr

import httpx
import pytest

import import_edl as imp
from conftest import yaml_doc


class FakeServer:
    """Speaks just enough of the v2.2.0 sync API. Stores nothing but counts."""

    def __init__(self, *, sessions=True, openapi=None, max_chunk=25000):
        self.sessions, self.openapi, self.max_chunk = sessions, openapi, max_chunk
        self.next_id = 1
        self.open: dict[int, dict] = {}
        self.log: list[tuple[str, str]] = []
        self.max_entries_in_request = 0
        self.fail = {}                    # (method, path-suffix) -> list of responses to return first
        self.commit_result = None
        self.singles: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.log.append((method, path))
        for key, queue in self.fail.items():
            if key[0] == method and path.endswith(key[1]) and queue:
                item = queue.pop(0)
                if isinstance(item, Exception):
                    raise item
                return item
        if path == "/openapi.json":
            if self.openapi is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"components": {"schemas": self.openapi}})
        body = json.loads(request.content) if request.content else {}
        if path.endswith("/sync") and method == "POST":
            self.singles.append(body)
            self.max_entries_in_request = max(self.max_entries_in_request, len(body["entries"]))
            return httpx.Response(200, json=self._report(len(body["entries"]), body))
        if not self.sessions and "/sync/sessions" in path:
            return httpx.Response(404, json={"detail": "Not Found"})
        if path.endswith("/sync/sessions") and method == "POST":
            sid = self.next_id
            self.next_id += 1
            self.open[sid] = {"chunks": {}, "opts": body}
            return httpx.Response(200, json=self._progress(sid, resumed=False))
        parts = path.split("/")
        if "sessions" in parts:
            sid = int(parts[parts.index("sessions") + 1])
            sess = self.open.get(sid)
            if sess is None:
                return httpx.Response(410, json={"detail": {"errors": ["session expired"]}})
            if method == "GET":
                return httpx.Response(200, json=self._progress(sid))
            if method == "DELETE":
                self.open.pop(sid, None)
                return httpx.Response(200, json={})
            if method == "PUT":
                idx = int(parts[-1])
                n = len(body["entries"])
                self.max_entries_in_request = max(self.max_entries_in_request, n)
                if n > self.max_chunk:
                    return httpx.Response(413, json={"detail": {"errors": ["chunk too large"]}})
                already = idx in sess["chunks"]
                sess["chunks"][idx] = n
                out = self._progress(sid)
                out["already_received"] = already
                return httpx.Response(200, json=out)
            if method == "POST" and path.endswith("/commit"):
                if self.commit_result:
                    return self.commit_result(sess, body)
                if set(sess["chunks"]) != set(range(body["total_chunks"])):
                    return httpx.Response(409, json={"detail": {"errors": ["incomplete"], "nothing_applied": True}})
                self.open.pop(sid)
                return httpx.Response(200, json=self._report(body["total_entries"], sess["opts"], run=sid))
        return httpx.Response(500, json={"detail": "unexpected " + path})

    def _progress(self, sid, resumed=None):
        sess = self.open[sid]
        idx = sorted(sess["chunks"])
        ranges = []
        for i in idx:
            if ranges and i == ranges[-1][1] + 1:
                ranges[-1][1] = i
            else:
                ranges.append([i, i])
        out = {"session_id": sid, "status": "receiving", "received_ranges": ranges, "max_chunk_size": self.max_chunk,
               "recommended_chunk_size": 10000}
        if resumed is not None:
            out["resumed"] = resumed
        return out

    def _report(self, n, opts, run=None):
        return {"status": "applied", "duplicate": False, "run_id": run, "counts": {
            "received": n, "new": n, "unchanged": 0, "removed": 0, "invalid": 0, "pending_classification": 0,
            "duplicates_in_request": 0, "blocked_by_policy": 0, "blocked_by_classification": 0,
            "suppressed_by_shadowing": 0, "published_of_desired": n, "ownership_added": 0, "missing_not_removed": 0},
            "feed": {"entries_before": 0, "entries_after": n, "changed": True}, "invalid": []}


def drive(tmp_path, server, yaml_text, *args, name="in.yaml"):
    p = tmp_path / name
    p.write_text(yaml_text, encoding="utf-8")
    client = httpx.Client(transport=httpx.MockTransport(server.handler))
    lines, sleeps = [], []
    err = io.StringIO()
    with redirect_stderr(err):
        code = imp.main([str(p), "--base-url", "http://fake", "--token", "t", *args],
                        client_factory=lambda token, timeout, verify: client, sleep=sleeps.append,
                        out=lambda *a, **k: lines.append(" ".join(map(str, a))))
    return code, "\n".join(lines + err.getvalue().splitlines()), sleeps, p


def test_older_server_without_sessions_still_serves_small_lists_and_explains_large_ones(tmp_path):
    srv = FakeServer(sessions=False)
    code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(20)]}))
    assert code == 0 and len(srv.singles) == 1                      # auto mode: one request, works on any v2.2.0
    code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(20)]}),
                             "--chunk-size", "5", "--discard-checkpoint")
    assert code == 1 and "does not offer chunked sync" in text and "--mode single" in text


def test_mode_single_sends_one_request_even_for_a_large_list(tmp_path):
    srv = FakeServer()
    code, _, _, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(50)]}),
                          "--mode", "single", "--chunk-size", "10")
    assert code == 0 and len(srv.singles) == 1 and len(srv.singles[0]["entries"]) == 50


def test_request_payload_is_exactly_the_documented_contract(tmp_path):
    srv = FakeServer()
    drive(tmp_path, srv, yaml_doc({"a": ["x.example.com"]}))
    body = srv.singles[0]
    assert set(body) == {"source", "sync_id", "delete_missing", "confirm_empty", "entries", "dry_run", "verbose"}
    assert body["source"] == "yaml-import:a" and body["delete_missing"] is False and body["confirm_empty"] is False
    assert "reclassify" not in body
    srv2 = FakeServer()
    drive(tmp_path, srv2, yaml_doc({"a": ["x.example.com"]}), "--delete-missing", name="d.yaml")
    assert [b["delete_missing"] for b in srv2.singles] == [True, True]          # preview (dry run) + the real sync
    assert [b["dry_run"] for b in srv2.singles] == [True, False]


def test_503_and_network_errors_are_retried_then_succeed(tmp_path):
    srv = FakeServer()
    srv.fail[("PUT", "/chunks/0")] = [httpx.Response(503, json={"detail": "busy"}), httpx.ConnectError("down")]
    code, text, sleeps, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(12)]}),
                                  "--chunk-size", "5")
    assert code == 0 and sleeps == [1.0, 2.0] and "retrying" in text


def test_lost_session_restarts_with_the_same_sync_id_and_reuploads_everything(tmp_path):
    srv = FakeServer()
    srv.fail[("PUT", "/chunks/1")] = [httpx.Response(410, json={"detail": {"errors": ["session expired"]}})]
    code, text, _, p = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(12)]}), "--chunk-size", "5")
    assert code == 0 and "Restarting the upload with the same sync_id" in text
    starts = [1 for m, path in srv.log if m == "POST" and path.endswith("/sync/sessions")]
    assert len(starts) == 2
    assert [json.loads(p.with_name(p.name + ".import-state.json").read_text())["units"]["a|yaml-import:a"]["sync_id"]]


def test_definitive_refusal_abandons_the_session_so_the_next_run_is_not_blocked(tmp_path):
    srv = FakeServer()
    srv.commit_result = lambda sess, body: httpx.Response(422, json={"detail": {"errors": ["2 invalid entries"], "invalid": [
        {"entry": "bad one", "reason": "invalid hostname label"}]}})
    code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": ["good.example.com", "bad one", "x.example.com"]}),
                             "--chunk-size", "2")
    assert code == 1 and "HTTP 422" in text and "rejected (line 8): 'bad one'" in text
    assert srv.open == {}                                               # the staged upload was abandoned
    assert ("DELETE", "/v1/lists/a/sync/sessions/1") in srv.log


def test_incomplete_commit_response_triggers_resend_of_missing_chunks_only(tmp_path):
    srv = FakeServer()
    sent = {"hit": False}

    def commit(sess, body):
        if not sent["hit"]:
            sent["hit"] = True
            sess["chunks"].pop(1)                                       # the server lost chunk 1
            return httpx.Response(409, json={"detail": {"errors": ["incomplete"], "nothing_applied": True}})
        srv.open.pop(1)
        return httpx.Response(200, json=srv._report(body["total_entries"], {}, run=1))
    srv.commit_result = commit
    code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(12)]}), "--chunk-size", "5")
    assert code == 0
    puts = [path.rsplit("/", 1)[-1] for m, path in srv.log if m == "PUT"]
    assert puts == ["0", "1", "2", "1"]


# ---- reclassify ----------------------------------------------------------------------------------------------
def test_reclassify_is_sent_only_when_the_server_schema_defines_it(tmp_path):
    srv = FakeServer(openapi={"SyncIn": {"properties": {"source": {}, "reclassify": {}}}})
    code, _, _, _ = drive(tmp_path, srv, yaml_doc({"a": ["x.example.com"]}), "--reclassify")
    assert code == 0 and srv.singles[0]["reclassify"] is True


def test_reclassify_refused_when_schema_lacks_it_or_is_unreadable(tmp_path):
    for openapi in ({"SyncIn": {"properties": {"source": {}}}}, None):
        srv = FakeServer(openapi=openapi)
        code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": ["x.example.com"]}), "--reclassify", name="r.yaml")
        assert code == imp.EXIT_UNSUPPORTED and srv.singles == [] and "Nothing was sent" in text
        assert not any(path.endswith("/sync") for _, path in srv.log)
        assert not (tmp_path / "r.yaml.import-state.json").exists()      # and no checkpoint was left behind


def test_reclassify_for_chunked_needs_the_session_schema_too(tmp_path):
    srv = FakeServer(openapi={"SyncIn": {"properties": {"reclassify": {}}}, "SessionStart": {"properties": {"source": {}}}})
    code, text, _, _ = drive(tmp_path, srv, yaml_doc({"a": [f"h{i}.example.com" for i in range(12)]}),
                             "--reclassify", "--chunk-size", "5")
    assert code == imp.EXIT_UNSUPPORTED and "SessionStart" in text


# ---- scale and memory ------------------------------------------------------------------------------------------
@pytest.mark.slow
def test_100k_entries_use_bounded_memory_and_bounded_requests(tmp_path):
    n = 100_000
    p = tmp_path / "big.yaml"
    with p.open("w") as f:
        f.write("---\nurl:\n  - name: huge\n    type: URL List\n    list:\n      member:\n")
        for i in range(n):
            f.write(f'        - "h{i}.site{i // 4}.example.net"\n')
    srv = FakeServer()
    client = httpx.Client(transport=httpx.MockTransport(srv.handler))
    lines = []
    tracemalloc.start()
    code = imp.main([str(p), "--base-url", "http://fake", "--token", "t", "--chunk-size", "5000"],
                    client_factory=lambda t, to, v: client, sleep=lambda s: None, out=lambda *a, **k: lines.append(" ".join(map(str, a))))
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert code == 0
    assert srv.max_entries_in_request == 5000                        # no request carries more than one chunk
    assert len([1 for m, path in srv.log if m == "PUT"]) == 20
    mb = peak / 1024 / 1024
    print(f"\n100,000-entry import: peak traced memory {mb:.0f} MB")
    assert mb < 150, f"peak {mb:.0f} MB"
    # the request bodies are not retained: after the run only the parsed YAML (freed with main's frame) remains
    assert current / 1024 / 1024 < 40
