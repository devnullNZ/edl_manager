"""Importer 2.1: deletion is opt-in and previewed, --reclassify uses the real server option, early rejection reports."""
import json
from pathlib import Path

import pytest

import import_edl as imp
from conftest import ADMIN, Killed, yaml_doc
from test_integration import THREE, members, run_ok

SMALLER = {**THREE, "threat-feeds": ["evil1.example.com"]}          # drops evil2 + shared from threat-feeds


def settings(runner, **values):
    r = runner.server.put("/v1/admin/settings", headers=ADMIN, json={"values": values, "confirm": True,
                                                                       "clear_secrets": []})
    assert r.status_code == 200, r.text


def sync_calls(runner, since=0):
    return [(x["method"], x["path"], x["json"]) for x in runner.spy.log[since:] if "/sync" in x["path"]]


# ======================================================================== deletion is opt-in
@pytest.mark.parametrize("chunk", ["10000", "2"])
def test_default_never_removes_entries(runner, chunk):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p, "--chunk-size", chunk)
    runner.write_yaml(yaml_doc(SMALLER))
    n = len(runner.spy.log)
    run_ok(runner, p, "--chunk-size", chunk)
    assert runner.feed("threat-feeds") == ["evil1.example.com/", "evil2.example.com/", "shared.example.com/"]
    assert "kept, NOT removed because --delete-missing is not set: 2" in runner.text
    sent = [j for _, path, j in sync_calls(runner, n) if j and "delete_missing" in j]
    assert sent and all(j["delete_missing"] is False for j in sent)
    assert not any(j.get("dry_run") for j in sent)                  # no removal preview when nothing can be removed


def test_no_delete_missing_is_a_compatibility_alias_for_the_default(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc(SMALLER))
    run_ok(runner, p, "--no-delete-missing")
    assert len(runner.feed("threat-feeds")) == 3


@pytest.mark.parametrize("chunk", ["10000", "2"])
def test_delete_missing_removes_only_after_showing_how_many(runner, chunk):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p, "--chunk-size", chunk)
    runner.write_yaml(yaml_doc(SMALLER))
    n = len(runner.spy.log)
    run_ok(runner, p, "--delete-missing", "--chunk-size", chunk)
    assert runner.feed("threat-feeds") == ["evil1.example.com/"]
    assert runner.feed("malware-domains") == ["m1.example.net/", "m2.example.net/", "shared.example.com/"]
    text = runner.text
    assert "[threat-feeds] --delete-missing: committing will remove 2 entries" in text
    # ordering: the preview (a server dry run) happens BEFORE the request that changes anything
    log = runner.spy.log[n:]
    is_apply = lambda c: bool(c["json"]) and c["json"].get("dry_run") is False and (  # noqa: E731
        c["path"].endswith("/commit") or c["path"].endswith("/sync")) and "threat-feeds" in c["path"]
    is_preview = lambda c: bool(c["json"]) and c["json"].get("dry_run") is True and "threat-feeds" in c["path"]  # noqa: E731
    first_apply = next(i for i, c in enumerate(log) if is_apply(c))
    assert any(is_preview(c) for c in log[:first_apply])


def test_the_preview_never_changes_anything(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc(SMALLER))
    before = {k: runner.feed(k) for k in THREE}
    runs = runner.db("select count(*) from sync_runs")[0][0]
    run_ok(runner, p, "--server-dry-run", "--delete-missing")
    assert {k: runner.feed(k) for k in THREE} == before
    assert runner.db("select count(*) from sync_runs")[0][0] == runs
    assert "Would remove (no longer listed):       2" in runner.text
    assert runner.run(p, "--dry-run", "--delete-missing") == 0       # local dry run: the server is not contacted
    assert {k: runner.feed(k) for k in THREE} == before


def test_max_removals_stops_before_committing_and_resume_continues(runner):
    p = runner.write_yaml(yaml_doc({"a": members(20)}))
    run_ok(runner, p, "--chunk-size", "5")
    runner.write_yaml(yaml_doc({"a": members(7)}))                      # 13 would go; 7 > chunk size -> chunked
    assert runner.run(p, "--delete-missing", "--max-removals", "3", "--chunk-size", "5") == imp.EXIT_FAILED
    assert "would remove 13 entries" in runner.text and "--max-removals is 3" in runner.text
    assert len(runner.feed("a")) == 20                                  # nothing removed
    open_sessions = runner.db("select count(*) from sync_sessions where status = 'receiving'")[0][0]
    assert open_sessions == 1                                           # the staged upload is kept ...
    n = len(runner.spy.log)
    run_ok(runner, p, "--delete-missing", "--max-removals", "13", "--chunk-size", "5", "--resume")
    assert len(runner.feed("a")) == 7
    puts = [x for x in runner.spy.log[n:] if x["method"] == "PUT"]
    assert puts == []                                                   # ... so nothing was uploaded again


def test_max_removals_in_single_request_mode(runner):
    p = runner.write_yaml(yaml_doc({"a": members(10)}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": members(2)}))
    assert runner.run(p, "--delete-missing", "--max-removals", "5") == imp.EXIT_FAILED
    assert len(runner.feed("a")) == 10
    run_ok(runner, p, "--delete-missing", "--max-removals", "8", "--discard-checkpoint")
    assert len(runner.feed("a")) == 2


def test_empty_desired_state_still_needs_confirm_empty_and_deletion(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com"]}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": []}))
    assert runner.run(p, "--delete-missing") == imp.EXIT_FAILED and "--confirm-empty" in runner.text
    assert runner.feed("a") == ["x.example.com/"]
    run_ok(runner, p, "--delete-missing", "--confirm-empty", "--discard-checkpoint")
    assert runner.feed("a") == []
    runner.write_yaml(yaml_doc({"a": []}))
    run_ok(runner, p, "--confirm-empty")                                # without deletion an empty list is a no-op
    assert "nothing is removed by default" in runner.text


def test_discarding_a_checkpoint_abandons_its_open_upload_session(runner):
    p = runner.write_yaml(yaml_doc({"a": members(12)}))
    def die(rec):
        if rec["method"] == "PUT" and rec["path"].endswith("/chunks/1"):
            raise Killed
    runner.spy.before = die
    with pytest.raises(Killed):
        runner.run(p, "--chunk-size", "5")
    runner.spy.before = None
    assert runner.db("select count(*) from sync_sessions where status = 'receiving'")[0][0] == 1
    run_ok(runner, p, "--chunk-size", "5", "--discard-checkpoint")
    assert runner.db("select count(*) from sync_sessions where status = 'receiving'")[0][0] == 0
    assert len(runner.feed("a")) == 12


# ======================================================================== reclassify against the real server
def test_reclassify_off_keeps_the_cached_classification(runner):
    p = runner.write_yaml(yaml_doc({"a": ["bad1.example.com", "ok.example.com"]}))
    run_ok(runner, p)
    runner.server.fake.lookup = lambda t: f"{t} search-engines (Base db)"
    n = len(runner.server.fake.calls)
    run_ok(runner, p)
    assert len(runner.server.fake.calls) == n and runner.feed("a") == ["ok.example.com/"]


def test_reclassify_reconsiders_blocked_entries_and_refreshes_the_cache(runner):
    p = runner.write_yaml(yaml_doc({"a": ["bad1.example.com", "ok.example.com"]}))
    run_ok(runner, p)
    assert runner.feed("a") == ["ok.example.com/"]
    runner.server.fake.lookup = lambda t: (runner.server.fake.calls.append(t) or f"{t} search-engines (Base db)")
    n = len(runner.server.fake.calls)
    run_ok(runner, p, "--reclassify")
    assert sorted(runner.server.fake.calls[n:]) == ["bad1.example.com", "ok.example.com"]
    assert runner.feed("a") == ["bad1.example.com/", "ok.example.com/"]
    assert "Reclassification (job" in runner.text and "2 existing entries" in runner.text and "(1 changed)" in runner.text
    sent = [j for _, path, j in sync_calls(runner) if j and j.get("reclassify")]
    assert sent and all(j["reclassify"] is True for j in sent)
    assert runner.state(p)["units"]["a|yaml-import:a"]["report"]["reclassification"]["status"] == "done"
    # the fingerprint covers --reclassify: a resume without it is refused
    assert runner.run(p, "--resume") == imp.EXIT_USAGE


@pytest.mark.parametrize("chunk", ["10000", "3"])
def test_reclassify_in_both_upload_modes_and_a_failed_lookup_approves_nothing(runner, chunk):
    p = runner.write_yaml(yaml_doc({"a": ["bad1.example.com", "bad2.example.com", "ok.example.com"]}))
    run_ok(runner, p, "--chunk-size", chunk)
    pe = __import__("app.panorama", fromlist=["x"]).PanoramaError

    def down(t):
        raise pe("timeout")
    runner.server.fake.lookup = down
    run_ok(runner, p, "--reclassify", "--chunk-size", chunk)
    assert runner.feed("a") == ["ok.example.com/"]                      # blocked stay blocked, approved stays approved
    assert "RECLASSIFICATION OF [a] IS STILL RUNNING ON THE SERVER" in runner.text
    assert runner.db("select count(*) from entries where reclass_job_id is not null")[0][0] == 3
    runner.server.fake.lookup = lambda t: f"{t} search-engines (Base db)"
    runner.server.engine.tick(force=True)                                # the server's engine works the job off
    assert runner.feed("a") == ["bad1.example.com/", "bad2.example.com/", "ok.example.com/"]
    assert runner.db("select count(*) from entries where reclass_job_id is not null")[0][0] == 0


def test_reclassify_respects_the_budget_and_the_five_request_limit(runner):
    import threading
    import time
    settings(runner, sync_classification_budget=4)
    ents = members(30)
    p = runner.write_yaml(yaml_doc({"a": ents}))
    settings(runner, sync_classification_budget=2000)
    run_ok(runner, p)
    settings(runner, sync_classification_budget=4)
    lock, state = threading.Lock(), {"now": 0, "max": 0}

    def slow(t):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.005)
        with lock:
            state["now"] -= 1
        return f"{t} malware (Cloud db)"
    runner.server.fake.lookup = slow
    run_ok(runner, p, "--reclassify")
    assert "4 re-checked now" in runner.text and "26 queued for the server" in runner.text
    assert len(runner.feed("a")) == 26                                  # not yet reclassified: still published
    settings(runner, sync_classification_budget=2000, max_batch_size=10, processing_batch_delay_seconds=0)
    res = runner.server.engine.tick(force=True, drain=True)
    assert res["drain"]["batches"] >= 3 and runner.feed("a") == [] and state["max"] <= 5


def test_reclassify_dry_run_reports_scope_and_changes_nothing(runner):
    p = runner.write_yaml(yaml_doc({"a": ["bad1.example.com", "ok.example.com"]}))
    run_ok(runner, p)
    n = len(runner.server.fake.calls)
    run_ok(runner, p, "--server-dry-run", "--reclassify")
    assert len(runner.server.fake.calls) == n and "would ask Panorama again about 2 existing entries" in runner.text
    assert runner.db("select count(*) from reclass_jobs")[0][0] == 0


# ======================================================================== rejected entries
def test_rejected_entries_are_reported_per_chunk_with_exact_yaml_lines(runner):
    good = members(6)
    yml = yaml_doc({"a": good[:3] + ["bad host one!"] + good[3:] + ["bad host two!"]})
    p = runner.write_yaml(yml)
    lines = {i + 1: t for i, t in enumerate(yml.splitlines())}
    run_ok(runner, p, "--chunk-size", "4")                              # default: no deletion -> valid entries applied
    assert "rejected by the server" in runner.text                      # announced while uploading
    for bad in ("bad host one!", "bad host two!"):
        line = next(n for n, t in lines.items() if bad in t)
        assert f"rejected (line {line}): {bad!r}" in runner.text
    assert len(runner.feed("a")) == 6


def test_more_than_a_hundred_rejected_entries_are_all_listed(runner):
    bad = [f"bad host {i}!" for i in range(130)]
    p = runner.write_yaml(yaml_doc({"a": members(5) + bad}))
    report = Path(runner.tmp) / "rep.json"
    run_ok(runner, p, "--chunk-size", "50", "--report-file", str(report))
    unit = json.loads(report.read_text())["units"][0]
    assert unit["server_invalid"] == 130 and len(unit["invalid"]) == 130
    assert all(i["yaml_line"] for i in unit["invalid"])


def test_invalid_entries_with_delete_missing_still_refuse_and_remove_nothing(runner):
    p = runner.write_yaml(yaml_doc({"a": members(5)}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": members(2) + ["bad host!"]}))
    assert runner.run(p, "--delete-missing", "--chunk-size", "2") == imp.EXIT_FAILED
    assert len(runner.feed("a")) == 5 and "bad host!" in runner.text
