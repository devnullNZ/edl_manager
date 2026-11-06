"""Importer 2.1.1: --max-removals is also handed to the server, which enforces it inside the commit."""
import pytest

import import_edl as imp
from conftest import yaml_doc
from test_integration import members, run_ok


def source_of(runner):
    return runner.db("select distinct source_id from entry_sources where kind = 'sync'")[0][0]


def grow_before_real_commit(runner, extra=30):
    """Between the importer's preview and its real commit another run grows the source (a stale preview)."""
    done = []

    def hook(rec):
        j = rec["json"] or {}
        real_commit = rec["method"] == "POST" and rec["path"].endswith("/commit") and not j.get("dry_run")
        real_single = rec["method"] == "POST" and rec["path"].endswith("/sync") and not j.get("dry_run") \
            and j.get("delete_missing")
        if (real_commit or real_single) and not done:
            done.append(1)
            owned = [r[0] for r in runner.db("select e.value from entries e join entry_sources s on s.entry_id = e.id "
                                             "where s.kind = 'sync'")]
            r = runner.server.post("/v1/lists/a/sync", json={
                "source": source_of(runner), "sync_id": "grown", "entries": owned + [f"late{i}.example.com" for i in range(extra)]})
            assert r.status_code == 200, r.text
    runner.spy.before = hook
    return done


@pytest.mark.parametrize("chunk", ["5", "10000"])
def test_limit_is_sent_to_the_server(runner, chunk):
    p = runner.write_yaml(yaml_doc({"a": members(10)}))
    run_ok(runner, p, "--chunk-size", chunk)
    runner.write_yaml(yaml_doc({"a": members(8)}))
    n = len(runner.spy.log)
    run_ok(runner, p, "--delete-missing", "--max-removals", "4", "--chunk-size", chunk)
    sent = [x["json"] for x in runner.spy.log[n:] if x["method"] == "POST" and x["json"]
            and (x["path"].endswith("/commit") or x["path"].endswith("/sync"))]
    assert sent and all(j.get("max_removals") == 4 for j in sent)       # the preview and the real call


def test_limit_is_not_sent_without_delete_missing_or_without_a_limit(runner):
    p = runner.write_yaml(yaml_doc({"a": members(10)}))
    run_ok(runner, p, "--max-removals", "4")
    run_ok(runner, p, "--delete-missing", "--discard-checkpoint")
    assert not any("max_removals" in (x["json"] or {}) for x in runner.spy.log)


def test_stale_preview_chunked_server_refuses_session_kept_and_resume_works(runner):
    p = runner.write_yaml(yaml_doc({"a": members(20)}))
    run_ok(runner, p, "--chunk-size", "5")
    runner.write_yaml(yaml_doc({"a": members(7)}))                       # preview: 13 removals, accepted (limit 13)
    done = grow_before_real_commit(runner)
    assert runner.run(p, "--delete-missing", "--max-removals", "13", "--chunk-size", "5") == imp.EXIT_FAILED
    assert done and "would now remove 43" in runner.text and "Nothing was removed" in runner.text
    assert len(runner.feed("a")) == 50                                   # the list is exactly as the other run left it
    assert runner.db("select count(*) from sync_sessions where status = 'receiving'")[0][0] == 1   # staged upload kept
    runner.spy.before = None
    n = len(runner.spy.log)
    run_ok(runner, p, "--delete-missing", "--max-removals", "43", "--chunk-size", "5", "--resume")
    assert len(runner.feed("a")) == 7
    assert [x for x in runner.spy.log[n:] if x["method"] == "PUT"] == []


def test_stale_preview_single_request_server_refuses_and_the_sync_id_is_reusable(runner):
    p = runner.write_yaml(yaml_doc({"a": members(10)}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": members(5)}))
    done = grow_before_real_commit(runner)
    assert runner.run(p, "--delete-missing", "--max-removals", "5") == imp.EXIT_FAILED
    assert done and "would now remove 35" in runner.text
    assert len(runner.feed("a")) == 40
    runner.spy.before = None
    run_ok(runner, p, "--delete-missing", "--max-removals", "35", "--resume")
    assert len(runner.feed("a")) == 5


def test_server_without_the_field_is_told_plainly_and_nothing_is_sent(runner, monkeypatch):
    p = runner.write_yaml(yaml_doc({"a": members(10)}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": members(8)}))
    real = imp.Api.schema_properties
    monkeypatch.setattr(imp.Api, "schema_properties",
                        lambda self, model: (real(self, model) or set()) - {"max_removals"})
    n = len(runner.spy.log)
    run_ok(runner, p, "--delete-missing", "--max-removals", "4")
    assert "cannot enforce --max-removals itself" in runner.text
    assert not any("max_removals" in (x["json"] or {}) for x in runner.spy.log[n:])
    # the importer's own preview check still applies
    runner.write_yaml(yaml_doc({"a": members(2)}))
    assert runner.run(p, "--delete-missing", "--max-removals", "1", "--discard-checkpoint") == imp.EXIT_FAILED
    assert len(runner.feed("a")) == 8
