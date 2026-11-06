"""The importer against the real EDL Publisher application (in-process, fake Panorama)."""
import json
from pathlib import Path

import httpx
import pytest

import import_edl as imp
from conftest import ADMIN, Killed, yaml_doc

THREE = {"threat-feeds": ["evil1.example.com", "evil2.example.com", "shared.example.com"],
         "malware-domains": ["m1.example.net", "m2.example.net", "shared.example.com"],
         "corporate-blocklist": ["corp.example.org/login", "corp.example.org/admin/"]}


def run_ok(r, p, *a, **k):
    code = r.run(p, *a, **k)
    assert code == 0, r.text
    return code


# 1. initial import of several lists ----------------------------------------------------------------------
def test_initial_import_of_multiple_yaml_lists(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    assert runner.feed("threat-feeds") == ["evil1.example.com/", "evil2.example.com/", "shared.example.com/"]
    assert runner.feed("malware-domains") == ["m1.example.net/", "m2.example.net/", "shared.example.com/"]
    assert runner.feed("corporate-blocklist") == ["corp.example.org/admin/", "corp.example.org/login"]
    sources = {(s["list"], s["source"]) for s in runner.server.get("/v1/admin/sync/sources", headers=ADMIN).json()["sources"]}
    assert sources == {("threat-feeds", "yaml-import:threat-feeds"), ("malware-domains", "yaml-import:malware-domains"),
                       ("corporate-blocklist", "yaml-import:corporate-blocklist")}
    st = runner.state(p)
    assert all(u["status"] == "completed" and u["sync_id"] for u in st["units"].values())
    assert len({u["sync_id"] for u in st["units"].values()}) == 3          # a sync_id per list
    assert "Entries newly created by the server:   3" in runner.text


# 2. identical repeat import --------------------------------------------------------------------------------
def test_identical_repeat_import_changes_nothing_and_uses_new_sync_ids(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    first_ids = {k: u["sync_id"] for k, u in runner.state(p)["units"].items()}
    before = {n: runner.feed(n) for n in THREE}
    panorama = len(runner.server.fake.calls)
    run_ok(runner, p)                                                    # no --resume: a NEW operation
    second = runner.state(p)["units"]
    assert all(second[k]["sync_id"] != first_ids[k] for k in first_ids)
    assert {n: runner.feed(n) for n in THREE} == before
    assert len(runner.server.fake.calls) == panorama                     # no Panorama requests at all
    assert all(u["report"]["status"] == "no_change" for u in second.values())
    assert "Entries newly created by the server:   0" in runner.text


def test_resume_of_a_completed_checkpoint_sends_nothing(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    n = len(runner.spy.log)
    run_ok(runner, p, "--resume")
    assert len(runner.spy.log) == n and "already completed" in runner.text


# 3 + 4. removal from one source; entries owned by another source are preserved --------------------------------
def test_removal_from_one_source_leaves_other_sources_alone(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    smaller = {**THREE, "threat-feeds": ["evil1.example.com"]}           # drops evil2 and shared
    runner.write_yaml(yaml_doc(smaller))
    run_ok(runner, p, "--delete-missing")
    assert runner.feed("threat-feeds") == ["evil1.example.com/"]
    assert runner.feed("malware-domains") == ["m1.example.net/", "m2.example.net/", "shared.example.com/"]
    assert "Removed (no longer listed):            2" in runner.text


def test_shared_destination_keeps_entries_another_source_or_a_manual_entry_owns(runner):
    runner.server.post("/v1/lists/default/entries", json={"urls": ["manual.example.com"], "source": "hand"})
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com", "only-a.example.com"], "b": ["x.example.com", "only-b.example.com"]}))
    run_ok(runner, p, "--target-list", "default", "--delete-missing")
    assert runner.feed("default") == ["manual.example.com/", "only-a.example.com/", "only-b.example.com/", "x.example.com/"]
    runner.write_yaml(yaml_doc({"a": ["only-a.example.com"], "b": ["x.example.com", "only-b.example.com"]}))
    run_ok(runner, p, "--target-list", "default", "--delete-missing")
    # a dropped x, but b still lists it; the manual entry belongs to nobody in the YAML
    assert runner.feed("default") == ["manual.example.com/", "only-a.example.com/", "only-b.example.com/", "x.example.com/"]
    runner.write_yaml(yaml_doc({"a": ["only-a.example.com"], "b": ["only-b.example.com"]}))
    run_ok(runner, p, "--target-list", "default", "--delete-missing")
    assert runner.feed("default") == ["manual.example.com/", "only-a.example.com/", "only-b.example.com/"]


def test_a_source_that_is_not_in_the_yaml_any_more_is_not_touched(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"threat-feeds": ["evil1.example.com"]}))
    run_ok(runner, p)
    assert runner.feed("malware-domains") == ["m1.example.net/", "m2.example.net/", "shared.example.com/"]


# 5. interrupted upload and resume ---------------------------------------------------------------------------------
def members(n, tag="h"):
    return [f"{tag}{i:03d}.example.com" for i in range(n)]


def test_interrupted_upload_resumes_without_a_new_session_and_never_finalises_early(runner):
    p = runner.write_yaml(yaml_doc({"big": members(25)}))
    puts = []

    def die_after_two(rec):
        if rec["method"] == "PUT":
            puts.append(rec)
            if len(puts) == 3:
                raise Killed
    runner.spy.before = die_after_two
    with pytest.raises(Killed):
        runner.run(p, "--chunk-size", "5")
    runner.spy.before = None
    assert runner.spy.calls("POST", "/commit") == []                      # never asked the server to finalise
    assert runner.db("select count(*) from entries")[0][0] == 0           # nothing applied
    st = runner.state(p)["units"]["big|yaml-import:big"]
    sync_id, session = st["sync_id"], st["session_id"]
    assert sorted(st["uploaded"]) == ["0", "1"] and st["status"] == "uploading"

    # a plain re-run must not silently start over
    assert runner.run(p, "--chunk-size", "5") == imp.EXIT_USAGE
    assert "unfinished checkpoint" in runner.text

    runner.spy.log.clear()
    run_ok(runner, p, "--chunk-size", "5", "--resume")
    sent = [r["path"].rsplit("/", 1)[-1] for r in runner.spy.calls("PUT")]
    assert sent == ["2", "3", "4"]                                         # only the missing chunks
    assert runner.spy.session_starts() == []                                # no new session was created
    st2 = runner.state(p)["units"]["big|yaml-import:big"]
    assert st2["sync_id"] == sync_id and st2["session_id"] == session and st2["status"] == "completed"
    assert runner.feed("big") == sorted(f"{m}/" for m in members(25))
    assert runner.db("select count(*) from sync_sessions")[0][0] == 1


def test_crash_after_the_server_applied_but_before_the_checkpoint(runner):
    p = runner.write_yaml(yaml_doc({"big": members(12)}))

    def die_after_commit(rec, resp):
        if rec["path"].endswith("/commit"):
            raise Killed
    runner.spy.after = die_after_commit
    with pytest.raises(Killed):
        runner.run(p, "--chunk-size", "5")
    runner.spy.after = None
    assert runner.feed("big") == sorted(f"{m}/" for m in members(12))     # the server did apply it
    assert runner.state(p)["units"]["big|yaml-import:big"]["status"] == "committing"
    run_ok(runner, p, "--chunk-size", "5", "--resume")
    assert runner.state(p)["units"]["big|yaml-import:big"]["status"] == "completed"
    assert runner.db("select count(*) from sync_runs where status != 'failed'")[0][0] == 1   # applied exactly once
    assert runner.db("select count(*) from sync_sessions")[0][0] == 1


def test_resume_refuses_a_changed_input_or_option(runner):
    p = runner.write_yaml(yaml_doc({"big": members(12)}))
    runner.spy.before = lambda rec: (_ for _ in ()).throw(Killed) if rec["method"] == "PUT" else None
    with pytest.raises(Killed):
        runner.run(p, "--chunk-size", "5")
    runner.spy.before = None
    assert runner.run(p, "--chunk-size", "5", "--resume", "--no-deduplicate") == imp.EXIT_USAGE
    assert "deduplicate" in runner.text
    runner.write_yaml(yaml_doc({"big": members(13)}))
    assert runner.run(p, "--chunk-size", "5", "--resume") == imp.EXIT_USAGE
    assert "input_sha256" in runner.text
    # --discard-checkpoint abandons it and starts a new operation; the open session of the old one is still there
    assert runner.run(p, "--chunk-size", "5", "--discard-checkpoint") in (0, 1)


# 6. retrying an already uploaded chunk ------------------------------------------------------------------------------
def test_a_chunk_whose_reply_was_lost_is_retried_in_the_same_session(runner):
    p = runner.write_yaml(yaml_doc({"big": members(15)}))
    state = {"done": False}

    def lose_reply(rec, resp):
        if rec["method"] == "PUT" and rec["path"].endswith("/chunks/1") and not state["done"]:
            state["done"] = True
            raise httpx.ReadTimeout("reply lost")
    runner.spy.after = lose_reply
    run_ok(runner, p, "--chunk-size", "5")
    puts = [r["path"].rsplit("/", 1)[-1] for r in runner.spy.calls("PUT")]
    assert puts == ["0", "1", "1", "2"]                                    # chunk 1 sent twice, nothing else
    assert len(runner.spy.session_starts()) == 1
    assert "(already on the server)" in runner.text
    assert runner.db("select count(*) from sync_sessions")[0][0] == 1
    assert runner.feed("big") == sorted(f"{m}/" for m in members(15))


def test_429_is_retried_with_backoff(runner):
    p = runner.write_yaml(yaml_doc({"big": members(10)}))
    seen = {"n": 0}
    original = runner.spy.inner.request

    def flaky(method, url, **kw):
        if method == "PUT" and seen["n"] < 2:
            seen["n"] += 1
            return httpx.Response(429, headers={"Retry-After": "7"}, json={"detail": "slow down"})
        return original(method, url, **kw)
    runner.spy.inner.request = flaky
    try:
        run_ok(runner, p, "--chunk-size", "5")
    finally:
        runner.spy.inner.request = original
    assert runner.sleeps[:2] == [7.0, 7.0]


def test_expired_session_restarts_with_the_same_sync_id_and_applies_nothing_meanwhile(runner):
    p = runner.write_yaml(yaml_doc({"big": members(10)}))
    state = {"killed": False}

    def expire(rec, resp):
        if rec["method"] == "PUT" and rec["path"].endswith("/chunks/0") and not state["killed"]:
            state["killed"] = True
            with runner.server.factory() as s:
                s.execute(__import__("sqlalchemy").text("update sync_sessions set status = 'expired'"))
                s.commit()
    runner.spy.after = expire
    run_ok(runner, p, "--chunk-size", "5")
    assert "Restarting the upload with the same sync_id" in runner.text
    assert runner.feed("big") == sorted(f"{m}/" for m in members(10))


# 7. empty desired state ---------------------------------------------------------------------------------------------
def test_empty_desired_state_requires_confirmation(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com", "y.example.com"], "b": ["z.example.com"]}))
    run_ok(runner, p, "--target-list", "default")
    runner.write_yaml(yaml_doc({"a": [], "b": ["z.example.com"]}))
    n = len(runner.spy.log)
    assert runner.run(p, "--target-list", "default", "--delete-missing") == imp.EXIT_FAILED
    assert "no members" in runner.text and "--confirm-empty" in runner.text
    assert runner.feed("default") == ["x.example.com/", "y.example.com/", "z.example.com/"]   # untouched
    assert not any(r["json"] and r["json"].get("source") == "yaml-import:a"
                   for r in runner.spy.log[n:])                           # nothing was even sent for the empty list
    # b completed; the checkpoint remembers that. --resume with the confirmation now applies the empty list.
    run_ok(runner, p, "--target-list", "default", "--delete-missing", "--resume", "--confirm-empty")
    assert runner.feed("default") == ["z.example.com/"]                   # b's entry is not a's to remove


def test_empty_list_with_no_delete_missing_is_a_no_op(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com"]}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": []}))
    n = len(runner.spy.log)
    run_ok(runner, p, "--no-delete-missing")
    assert len(runner.spy.log) == n and runner.feed("a") == ["x.example.com/"]


def test_a_file_with_no_lists_is_refused(runner):
    p = runner.write_yaml("---\nurl: []\n")
    assert runner.run(p) == imp.EXIT_USAGE and "no URL lists" in runner.text


def test_no_delete_missing_only_adds(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com", "y.example.com"]}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": ["x.example.com", "w.example.com"]}))
    run_ok(runner, p, "--no-delete-missing")
    assert runner.feed("a") == ["w.example.com/", "x.example.com/", "y.example.com/"]


# 8. dry runs ---------------------------------------------------------------------------------------------------------
def test_local_dry_run_never_contacts_the_server(runner):
    p = runner.write_yaml(yaml_doc(THREE))
    assert runner.run(p, "--dry-run") == 0
    assert runner.spy.log == [] and not Path(str(p) + ".import-state.json").exists()
    assert "the server was not contacted" in runner.text


@pytest.mark.parametrize("chunk", ["10000", "5"])
def test_server_dry_run_changes_nothing_and_keeps_no_checkpoint(runner, chunk):
    p = runner.write_yaml(yaml_doc({"a": members(12), "b": ["q.example.com"]}))
    run_ok(runner, p)
    runner.write_yaml(yaml_doc({"a": members(11) + ["new.example.com"], "b": ["q.example.com"]}))
    before = runner.feed("a")
    n_runs = runner.db("select count(*) from sync_runs")[0][0]
    import os
    os.remove(str(p) + ".import-state.json")
    run_ok(runner, p, "--server-dry-run", "--delete-missing", "--chunk-size", chunk)
    assert runner.feed("a") == before
    assert runner.db("select count(*) from sync_runs")[0][0] == n_runs
    assert not Path(str(p) + ".import-state.json").exists()
    assert runner.db("select count(*) from sync_sessions where status = 'receiving'")[0][0] == 0   # session abandoned
    assert "Server dry run" in runner.text and "Entries newly created by the server:   1" in runner.text
    assert "Would remove (no longer listed):       1" in runner.text         # a dry run says "would"


# 9. reclassification -------------------------------------------------------------------------------------------------
def test_reclassify_is_refused_when_the_server_sync_api_cannot_do_it(runner, monkeypatch):
    # a v2.2.0 server: its request schemas have no 'reclassify' property
    real = imp.Api.schema_properties
    monkeypatch.setattr(imp.Api, "schema_properties", lambda self, m: (real(self, m) or set()) - {"reclassify"})
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com"]}))
    run_ok(runner, p)
    n = len(runner.spy.log)
    assert runner.run(p, "--reclassify") == imp.EXIT_UNSUPPORTED
    assert "no 'reclassify' option" in runner.text and "Nothing was sent" in runner.text
    sent = [r for r in runner.spy.log[n:] if "/sync" in r["path"]]
    assert sent == []                                                       # nothing was sent
    assert runner.db("select count(*) from sync_runs")[0][0] == 1


def test_reclassify_off_preserves_existing_classification(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com", "bad1.example.com"]}))
    run_ok(runner, p)
    runner.server.fake.lookup = lambda t: f"{t} malware (Cloud db)"         # Panorama now disagrees about everything
    run_ok(runner, p)
    assert runner.feed("a") == ["x.example.com/"]                           # x stays published, bad1 stays blocked


# 10. path slashes, query and fragment -------------------------------------------------------------------------------------
def test_path_trailing_slash_distinction_reaches_the_server_intact(runner):
    p = runner.write_yaml(yaml_doc({"a": ["a.example.com/x", "a.example.com/x/", "a.example.com", "a.example.com/"]}))
    run_ok(runner, p)
    assert runner.feed("a") == ["a.example.com/", "a.example.com/x", "a.example.com/x/"]
    assert "Duplicates removed by the importer:    1" in runner.text        # only the domain-root pair collapses


def test_query_and_fragment_normalisation_matches_the_server(runner):
    variants = ["a.example.com/x?utm=1", "a.example.com/x#top", "https://a.example.com/x?q#f", "a.example.com/x",
                "b.example.com?x=1", "b.example.com#f", "b.example.com/"]
    p = runner.write_yaml(yaml_doc({"a": variants}))
    run_ok(runner, p, "--no-deduplicate")                                   # let the SERVER do the collapsing
    assert runner.feed("a") == ["a.example.com/x", "b.example.com/"]


def test_local_key_equals_the_servers_canonical_form(server):
    from app.normalize import normalize
    corpus = ["example.com", "Example.COM/", "https://u:p@Example.com:8443/Path/", "*.example.com", "a.com/x", "a.com/x/",
              "a.com/x//", "a.com//x", "a.com/x?y=1#z", "a.com/x/?y", "a.com#f", "a.com?q", "HTTP://A.com/a/b/",
              "a.com/%20x", "sub.a.com./", "a.com:80/x/"]
    for raw in corpus:
        assert imp.canonical_key(raw) == normalize(raw), raw


# 11. client-side deduplication ---------------------------------------------------------------------------------------------
def submitted(spy):
    """Every entry string that was sent in an upload request, in order."""
    out = []
    for r in spy.log:
        if r["method"] in ("PUT", "POST") and r["json"] and "entries" in r["json"]:
            out.extend(r["json"]["entries"])
    return out


DUPES = ["dup.example.com", "DUP.example.com", " dup.example.com ", "https://dup.example.com/", "dup.example.com/",
         "other.example.com", "dup.example.com"]


def test_dedupe_on_sends_each_url_once(runner):
    p = runner.write_yaml(yaml_doc({"a": DUPES}))
    run_ok(runner, p)
    assert submitted(runner.spy) == ["dup.example.com", "other.example.com"]
    assert "Duplicates removed by the importer:    5" in runner.text
    assert "Importer-side deduplication: ENABLED" in runner.text


def test_dedupe_off_sends_every_occurrence_and_the_server_deduplicates(runner):
    p = runner.write_yaml(yaml_doc({"a": DUPES}))
    run_ok(runner, p, "--no-deduplicate")
    sent = submitted(runner.spy)
    assert len(sent) == 7                                                   # all occurrences reach the server
    assert sorted(sent) == sorted(DUPES) and " dup.example.com " in sent    # untouched, whitespace and case included
    assert runner.feed("a") == ["dup.example.com/", "other.example.com/"]   # one published entry each
    assert runner.db("select count(*) from entries")[0][0] == 2             # one database record each
    assert runner.db("select count(*) from entry_sources")[0][0] == 2
    assert "Importer-side deduplication: DISABLED" in runner.text
    assert "Duplicates removed by the importer:    0 (deduplication disabled; none performed)" in runner.text
    assert "URL occurrences read from YAML:        7" in runner.text
    assert "URL occurrences submitted to server:   7" in runner.text
    assert "Duplicates identified by the server:   5" in runner.text
    assert "Entries newly created by the server:   2" in runner.text


def test_dedupe_off_duplicates_within_one_batch_in_single_request_mode(runner):
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com"] * 4 + ["y.example.com"]}))
    run_ok(runner, p, "--no-deduplicate")
    assert len(runner.spy.calls("POST", "/sync")) == 1 and len(submitted(runner.spy)) == 5
    assert runner.feed("a") == ["x.example.com/", "y.example.com/"]


def test_dedupe_off_duplicates_spanning_two_upload_batches(runner):
    items = ["dup.example.com", "a1.example.com", "a2.example.com", "a3.example.com", "dup.example.com",
             "a4.example.com", "a5.example.com", "DUP.example.com/"]
    p = runner.write_yaml(yaml_doc({"a": items}))
    run_ok(runner, p, "--no-deduplicate", "--chunk-size", "3")
    chunks = [r["json"]["entries"] for r in runner.spy.calls("PUT")]
    assert chunks == [items[0:3], items[3:6], items[6:8]]                  # not de-duplicated across batches
    assert sum(c.count("dup.example.com") for c in chunks) == 2 and "DUP.example.com/" in chunks[2]
    assert runner.feed("a") == sorted(f"{x}/" for x in {"dup.example.com", "a1.example.com", "a2.example.com",
                                                        "a3.example.com", "a4.example.com", "a5.example.com"})
    assert runner.db("select count(*) from entries where value = 'dup.example.com/'")[0][0] == 1
    assert "Duplicates identified by the server:   2" in runner.text


def test_dedupe_off_checkpoint_resume_keeps_batches_identical(runner):
    items = ["d.example.com", "e.example.com", "d.example.com", "f.example.com", "d.example.com", "g.example.com"]
    p = runner.write_yaml(yaml_doc({"a": items}))
    runner.spy.before = lambda rec: (_ for _ in ()).throw(Killed) if rec["method"] == "PUT" and rec["path"].endswith("/chunks/1") else None
    with pytest.raises(Killed):
        runner.run(p, "--no-deduplicate", "--chunk-size", "2")
    runner.spy.before = None
    first = [r["json"]["entries"] for r in runner.spy.calls("PUT") if r.get("status") == 200]
    runner.spy.log.clear()
    run_ok(runner, p, "--no-deduplicate", "--chunk-size", "2", "--resume")
    rest = [r["json"]["entries"] for r in runner.spy.calls("PUT")]
    assert first + rest == [items[0:2], items[2:4], items[4:6]]            # exactly the original batches
    assert runner.feed("a") == ["d.example.com/", "e.example.com/", "f.example.com/", "g.example.com/"]


def test_duplicates_across_different_yaml_lists(runner):
    p = runner.write_yaml(yaml_doc({"one": ["same.example.com", "same.example.com"], "two": ["same.example.com"]}))
    run_ok(runner, p, "--no-deduplicate")
    assert runner.feed("one") == runner.feed("two") == ["same.example.com/"]
    p2 = runner.write_yaml(yaml_doc({"one": ["same.example.com"], "two": ["same.example.com"]}), "b.yaml")
    run_ok(runner, p2, "--target-list", "merged")
    assert runner.feed("merged") == ["same.example.com/"]
    assert runner.db("select count(*) from entry_sources where list_name = 'merged'")[0][0] == 2   # two sources own it
    assert "Canonical entries shared across lists: 1" in runner.text


def test_domain_roots_with_and_without_trailing_slash(runner):
    p = runner.write_yaml(yaml_doc({"a": ["r.example.com", "r.example.com/", "https://r.example.com", "*.r.example.com", "*.r.example.com/"]}))
    run_ok(runner, p, "--no-deduplicate")
    assert runner.db("select value from entries order by value") == [("*.r.example.com/",), ("r.example.com/",)]


def test_invalid_entries_are_reported_with_their_yaml_line(runner):
    p = runner.write_yaml("---\nurl:\n  - name: a\n    list:\n      member:\n        - ok.example.com\n"
                          "        - 'bad host!'\n        - fine.example.com\n")
    assert runner.run(p, "--delete-missing") == imp.EXIT_FAILED
    assert "line 7" in runner.text and "bad host!" in runner.text and "422" in runner.text
    assert runner.db("select count(*) from entries")[0][0] == 0             # a refused sync removes/adds nothing
    run_ok(runner, p, "--no-delete-missing", "--discard-checkpoint")
    assert "rejected (line 7)" in runner.text and runner.feed("a") == ["fine.example.com/", "ok.example.com/"]


def test_pending_classification_is_called_out(runner):
    runner.server.fake.lookup = lambda t: (_ for _ in ()).throw(__import__("app.panorama", fromlist=["x"]).PanoramaError("down"))
    p = runner.write_yaml(yaml_doc({"a": ["x.example.com", "y.example.com"]}))
    run_ok(runner, p)
    assert "CLASSIFICATION IS STILL PENDING for 2 entries" in runner.text
    assert runner.feed("a") == []


def test_upload_finished_but_classification_budget_leaves_entries_pending(runner):
    r = runner.server.put("/v1/admin/settings", headers=ADMIN, json={
        "values": {"sync_classification_budget": 5}, "confirm": True, "clear_secrets": []})
    assert r.status_code == 200, r.text
    p = runner.write_yaml(yaml_doc({"a": members(20)}))
    run_ok(runner, p)
    assert "CLASSIFICATION IS STILL PENDING for 15 entries" in runner.text
    assert "Pending classification:                15" in runner.text
    assert len(runner.feed("a")) == 5                                       # only the classified ones are published
    assert runner.state(p)["units"]["a|yaml-import:a"]["status"] == "completed"   # the upload IS complete


def test_report_file(runner, tmp_path):
    p = runner.write_yaml(yaml_doc({"a": DUPES}))
    rep = tmp_path / "r.json"
    run_ok(runner, p, "--no-deduplicate", "--report-file", str(rep))
    u = json.loads(rep.read_text())["units"][0]
    assert u["yaml_occurrences_read"] == 7 and u["occurrences_submitted"] == 7 and u["duplicates_removed_by_importer"] is None
    assert u["server_new"] == 2 and u["server_duplicates_in_submission"] == 5


# 12. scale ------------------------------------------------------------------------------------------------------------------
@pytest.mark.slow
def test_100k_entries_in_one_list_against_the_real_server(runner):
    n = 100_000
    # a fresh server classifies at most `sync_classification_budget` (default 2000) new entries per sync and
    # leaves the rest pending for the background engine; this test needs them all classified in the sync
    r = runner.server.put("/v1/admin/settings", headers=ADMIN, json={
        "values": {"sync_classification_budget": 1_000_000}, "confirm": True, "clear_secrets": []})
    assert r.status_code == 200, r.text
    p = runner.write_yaml(yaml_doc({"huge": [f"h{i}.site{i // 4}.example.net" for i in range(n)]}))
    run_ok(runner, p)                                                       # auto mode -> 10 chunks of 10,000
    assert len(runner.spy.calls("PUT")) == 10 and max(len(r["json"]["entries"]) for r in runner.spy.calls("PUT")) == 10000
    assert runner.db("select count(*) from entries where list_name='huge'")[0][0] == n
    assert len(runner.feed("huge")) == n
    run_ok(runner, p)                                                       # identical repeat
    assert "Entries newly created by the server:   0" in runner.text and "Removed (no longer listed):            0" in runner.text
