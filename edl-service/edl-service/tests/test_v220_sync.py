"""v2.2.0: POST /v1/lists/{name}/sync (source-based reconciliation)."""
import re
import threading
from contextlib import contextmanager

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker

from app import hosts, migrations, service
from app import sync as sync_mod
from app.db import AuditLog, EdlSnapshot, Entry, EntrySource, SyncRun, SyncSource
from app.engine import processing_engine as eng
from conftest import KEY, apex_policy, bearer, feed, post, put_settings, sync

WATCHED = re.compile(r"^\s*(INSERT INTO|UPDATE|DELETE FROM)\s+(entries|entry_sources|edl_snapshots|category_cache)\b", re.I)
# every table a sync could touch (host bookkeeping such as last_used_at is done by authentication, not by sync)
ANY_WRITE = re.compile(r"^\s*(INSERT INTO|UPDATE|DELETE FROM)\s+(entries|entry_sources|edl_snapshots|category_cache|"
                       r"sync_runs|sync_sources|audit_log|app_settings)\b", re.I)


@contextmanager
def writes(client, pattern=WATCHED):
    seen: list[str] = []

    def hook(conn, cursor, statement, params, context, executemany):
        m = pattern.match(statement)
        if m:
            seen.append(m.group(0).split()[-1] if m.lastindex else statement[:40])
    event.listen(client.engine, "before_cursor_execute", hook)
    try:
        yield seen
    finally:
        event.remove(client.engine, "before_cursor_execute", hook)


def stored(client, list_name="default"):
    with client.factory() as s:
        return {e.value: e for e in s.scalars(select(Entry).where(Entry.list_name == list_name))}


def owners(client, value, list_name="default"):
    with client.factory() as s:
        e = s.scalars(select(Entry).where(Entry.list_name == list_name, Entry.value == value)).one()
        return sorted((o.kind, o.host, o.source_id) for o in s.scalars(select(EntrySource).where(EntrySource.entry_id == e.id)))


def second_host(client, name="other", lists="*"):
    with client.factory() as s:
        _, token = hosts.create_host(s, name, "10.0.0.0/24", lists)
    return token


def feed_lines(client, name="default"):
    return feed(client, name).text.splitlines()


# =========================================================================== basics
class TestReconcile:
    def test_new_entries_are_created_classified_and_published(self, client):
        r = sync(client, ["example.com", "https://www.example.org/a/", "bad.example.net"])
        c = r["counts"]
        assert (c["total_desired"], c["new"], c["unchanged"], c["removed"], c["blocked_by_classification"]) == (3, 3, 0, 0, 1)
        assert r["status"] == "applied" and r["duplicate"] is False and r["dry_run"] is False
        assert feed_lines(client) == ["example.com/", "www.example.org/a/"]
        assert owners(client, "example.com/") == [("sync", "ticketing", "yaml-import")]
        assert stored(client)["example.com/"].source == "ticketing:yaml-import"

    def test_report_has_every_required_count(self, client):
        r = sync(client, ["example.com"])
        for k in ("total_desired", "existing", "new", "unchanged", "removed", "blocked_by_policy", "pending_classification",
                  "approved_by_apex_classification", "suppressed_by_shadowing", "requiring_reclassification", "invalid",
                  "processing_errors"):
            assert k in r["counts"], k
        assert r["entries"][0]["entry"] == "example.com/" and r["entries"][0]["action"] == "added"
        assert r["feed"] == {"entries_before": 0, "entries_after": 1, "added": 1, "removed": 0, "changed": True,
                             "truncated_by_maximum": 0}

    def test_unchanged_new_and_removed(self, client):
        sync(client, ["a.example.com", "b.example.com"], sync_id="1")
        r = sync(client, ["b.example.com", "c.example.com"], sync_id="2", delete_missing=True)
        c = r["counts"]
        assert (c["new"], c["unchanged"], c["removed"], c["entries_deleted"], c["existing"]) == (1, 1, 1, 1, 1)
        assert feed_lines(client) == ["b.example.com/", "c.example.com/"]
        assert {e["action"] for e in r["entries"]} == {"added", "removed"}

    def test_missing_entries_are_kept_without_delete_missing(self, client):
        sync(client, ["a.example.com", "b.example.com"], sync_id="1")
        r = sync(client, ["b.example.com"], sync_id="2")
        assert r["counts"]["removed"] == 0 and r["counts"]["missing_not_removed"] == 1
        assert feed_lines(client) == ["a.example.com/", "b.example.com/"]

    def test_input_forms_are_normalised_and_duplicates_counted(self, client):
        r = sync(client, ["example.com", "https://EXAMPLE.com/", "http://example.com"])
        assert r["counts"]["received"] == 3 and r["counts"]["duplicates_in_request"] == 2 and r["counts"]["new"] == 1

    def test_yaml_list_name_is_tracked_and_updated(self, client):
        sync(client, [{"url": "a.example.com", "yaml_list": "blocklist-1"}, "b.example.com"], sync_id="1")
        with client.factory() as s:
            rows = {e.value: o.yaml_list for o, e in s.execute(select(EntrySource, Entry).join(Entry, Entry.id == EntrySource.entry_id))}
        assert rows == {"a.example.com/": "blocklist-1", "b.example.com/": None}
        r = sync(client, [{"url": "a.example.com", "yaml_list": "blocklist-2"}, "b.example.com"], sync_id="2")
        assert r["counts"]["yaml_list_changed"] == 1 and r["counts"]["unchanged"] == 1
        item = {e["value"]: e for e in client.get("/v1/lists/default/entries", headers=KEY).json()["entries"]}
        assert item["a.example.com/"]["owners"][0]["yaml_list"] == "blocklist-2"
        assert item["a.example.com/"]["owners"][0]["last_sync_id"] == "2"

    def test_other_lists_are_untouched(self, client):
        post(client, ["x.example.com"], list_name="other")
        sync(client, ["a.example.com"], delete_missing=True)
        assert feed_lines(client, "other") == ["x.example.com/"]


# =========================================================================== idempotency
class TestIdempotency:
    def test_repeated_identical_sync_writes_nothing_and_asks_panorama_nothing(self, client):
        apex_policy(client)
        body = ["example.com", "*.example.com", "www.example.com", "bad.example.net", "p.example.org/x/"]
        sync(client, body, sync_id="1", delete_missing=True)
        snap = client.factory().get(EdlSnapshot, "default")
        before = (snap.etag, snap.generated_at, snap.body)
        calls = len(client.fake.calls)
        with writes(client) as seen:
            r = sync(client, body, sync_id="2", delete_missing=True)
        assert seen == [] and len(client.fake.calls) == calls
        assert r["status"] == "no_change" and r["counts"]["unchanged"] == 5 and r["feed"]["changed"] is False
        snap = client.factory().get(EdlSnapshot, "default")
        assert (snap.etag, snap.generated_at, snap.body) == before

    def test_same_sync_id_returns_the_stored_result_without_processing(self, client):
        r1 = sync(client, ["a.example.com"], sync_id="same")
        calls = len(client.fake.calls)
        with writes(client, ANY_WRITE) as seen:
            r2 = sync(client, ["a.example.com"], sync_id="same")
        assert seen == [] and len(client.fake.calls) == calls
        assert r2["duplicate"] is True and r2["run_id"] == r1["run_id"] and r2["counts"] == r1["counts"]
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(SyncRun)) == 1

    def test_same_sync_id_with_different_content_is_a_conflict(self, client):
        sync(client, ["a.example.com"], sync_id="x")
        r = client.post("/v1/lists/default/sync", json={"source": "yaml-import", "sync_id": "x",
                                                        "entries": ["b.example.com"]}, headers=bearer(client.token))
        assert r.status_code == 409 and "different content" in r.text
        assert feed_lines(client) == ["a.example.com/"]

    def test_a_sync_id_is_scoped_to_list_and_source(self, client):
        sync(client, ["a.example.com"], sync_id="x")
        r = sync(client, ["a.example.com"], sync_id="x", source="another-source")
        assert r["duplicate"] is False
        r = sync(client, ["a.example.com"], sync_id="x", list_name="other")
        assert r["duplicate"] is False

    def test_a_response_lost_in_transit_is_recovered_by_retrying(self, client):
        sync(client, ["a.example.com", "b.example.com"], sync_id="1", delete_missing=True)
        first = sync(client, ["a.example.com"], sync_id="2", delete_missing=True)   # client never saw this reply
        retry = sync(client, ["a.example.com"], sync_id="2", delete_missing=True)
        assert retry["duplicate"] is True and retry["counts"]["removed"] == first["counts"]["removed"] == 1
        assert feed_lines(client) == ["a.example.com/"]

    def test_a_sync_that_failed_can_be_retried_with_the_same_id(self, client, monkeypatch):
        real = sync_mod._write
        monkeypatch.setattr(sync_mod, "_write", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full")))
        sync(client, ["a.example.com"], sync_id="retry", expect=500)
        monkeypatch.setattr(sync_mod, "_write", real)
        r = sync(client, ["a.example.com"], sync_id="retry")
        assert r["status"] == "applied" and r["duplicate"] is False and feed_lines(client) == ["a.example.com/"]


# =========================================================================== ownership and safety
class TestOwnership:
    def test_two_sources_share_an_entry_and_removal_from_one_keeps_it(self, client):
        sync(client, ["shared.example.com", "only-a.example.com"], source="A", sync_id="a1")
        r = sync(client, ["shared.example.com", "only-b.example.com"], source="B", sync_id="b1")
        assert r["counts"]["ownership_added"] == 1 and r["counts"]["new"] == 1
        assert owners(client, "shared.example.com/") == [("sync", "ticketing", "A"), ("sync", "ticketing", "B")]
        r = sync(client, [], source="A", sync_id="a2", delete_missing=True, confirm_empty=True)
        assert r["counts"]["removed"] == 2 and r["counts"]["entries_deleted"] == 1 and r["counts"]["kept_other_owners"] == 1
        assert feed_lines(client) == ["only-b.example.com/", "shared.example.com/"]
        sync(client, ["only-b.example.com"], source="B", sync_id="b2", delete_missing=True)
        assert feed_lines(client) == ["only-b.example.com/"]

    def test_another_hosts_entries_are_never_removed(self, client):
        other = second_host(client)
        sync(client, ["theirs.example.com"], sync_id="o1", token=other)
        sync(client, ["mine.example.com"], sync_id="m1")
        r = sync(client, ["mine2.example.com"], sync_id="m2", delete_missing=True)
        assert r["counts"]["removed"] == 1                                      # only 'mine'
        assert feed_lines(client) == ["mine2.example.com/", "theirs.example.com/"]

    def test_same_source_name_on_a_different_host_is_a_different_source(self, client):
        other = second_host(client)
        sync(client, ["a.example.com"], source="shared-name", sync_id="1", token=other)
        sync(client, ["b.example.com"], source="shared-name", sync_id="1", delete_missing=True)
        assert feed_lines(client) == ["a.example.com/", "b.example.com/"]

    def test_manually_submitted_entries_are_never_removed_by_sync(self, client):
        post(client, ["manual.example.com"])                                     # legacy endpoint, same host
        r = sync(client, ["manual.example.com", "synced.example.com"], delete_missing=True)
        assert r["counts"]["ownership_added"] == 1
        assert owners(client, "manual.example.com/") == [("api", "ticketing", ""), ("sync", "ticketing", "yaml-import")]
        sync(client, ["synced.example.com"], sync_id="2", delete_missing=True)    # drops its claim on 'manual'
        assert feed_lines(client) == ["manual.example.com/", "synced.example.com/"]
        assert owners(client, "manual.example.com/") == [("api", "ticketing", "")]

    def test_entries_without_any_owner_are_untouchable(self, client):
        with client.factory() as s:
            s.add(Entry(list_name="default", value="orphan.example.com/", status="active"))
            s.commit()
        sync(client, ["a.example.com"], delete_missing=True)
        sync(client, [], sync_id="2", delete_missing=True, confirm_empty=True)
        assert "orphan.example.com/" in feed_lines(client)
        with client.factory() as s:
            assert s.scalars(select(Entry).where(Entry.value == "orphan.example.com/")).first() is not None

    def test_legacy_submission_records_an_owner_and_second_submitter_is_added(self, client):
        post(client, ["a.example.com"], source="batch-1")
        assert owners(client, "a.example.com/") == [("api", "ticketing", "batch-1")]
        other = second_host(client)
        client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=bearer(other))
        assert owners(client, "a.example.com/") == [("api", "other", ""), ("api", "ticketing", "batch-1")]

    def test_deleting_through_the_management_api_removes_owners_too(self, client):
        sync(client, ["a.example.com"])
        client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=KEY)
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(EntrySource)) == 0
        r = sync(client, ["a.example.com"], sync_id="2", delete_missing=True)    # the importer's desired state wins again
        assert r["counts"]["new"] == 1


class TestSafety:
    def test_empty_desired_state_needs_explicit_confirmation(self, client):
        sync(client, ["a.example.com"], sync_id="1")
        r = sync(client, [], sync_id="2", delete_missing=True, expect=422)
        assert "confirm_empty" in r["detail"]["errors"][0]
        assert feed_lines(client) == ["a.example.com/"]
        r = sync(client, [], sync_id="3", delete_missing=True, confirm_empty=True)
        assert r["counts"]["removed"] == 1 and feed_lines(client) == []

    def test_empty_without_delete_missing_is_a_harmless_noop(self, client):
        sync(client, ["a.example.com"], sync_id="1")
        r = sync(client, [], sync_id="2")
        assert r["status"] == "no_change" and feed_lines(client) == ["a.example.com/"]

    def test_invalid_entries_block_removal(self, client):
        sync(client, ["a.example.com", "b.example.com"], sync_id="1")
        r = sync(client, ["a.example.com", "not a url!", "*.com"], sync_id="2", delete_missing=True, expect=422)
        assert "nothing is removed" in r["detail"]["errors"][0] and len(r["detail"]["invalid"]) == 2
        assert feed_lines(client) == ["a.example.com/", "b.example.com/"]

    def test_invalid_entries_without_delete_missing_are_reported_and_valid_ones_applied(self, client):
        r = sync(client, ["a.example.com", "not a url!", "*.com"], sync_id="1")
        assert r["counts"]["invalid"] == 2 and r["counts"]["new"] == 1
        assert {i["entry"] for i in r["invalid"]} == {"not a url!", "*.com"}
        assert "public suffix" in [i for i in r["invalid"] if i["entry"] == "*.com"][0]["reason"]
        assert feed_lines(client) == ["a.example.com/"]

    def test_overlong_entry_is_invalid_not_truncated(self, client):
        r = sync(client, ["a.example.com", "x.example.com/" + "p" * 2100], sync_id="1")
        assert r["counts"]["invalid"] == 1 and "2048" in r["invalid"][0]["reason"]

    def test_rejections_are_recorded(self, client):
        sync(client, [], sync_id="2", delete_missing=True, expect=422)
        with client.factory() as s:
            run = s.scalars(select(SyncRun)).one()
            assert run.status == "failed" and "confirm_empty" in run.error
            assert s.scalars(select(AuditLog).where(AuditLog.action == "sync-rejected")).one().target == "default"
            assert s.scalars(select(SyncSource)).one().last_status == "failed"

    def test_removals_are_deferred_while_classification_is_failing(self, client):
        put_settings(client, {"retry_delay_seconds": 0})
        sync(client, ["a.example.com", "b.example.com"], sync_id="1")
        client.fake.fail_next = 10_000
        r = sync(client, ["a.example.com", "c.example.com"], sync_id="2", delete_missing=True)
        assert r["removals_deferred"] is True and r["counts"]["removed"] == 0 and r["counts"]["processing_errors"] == 1
        assert "NOT applied" in r["warning"]
        assert feed_lines(client) == ["a.example.com/", "b.example.com/"]     # b kept; c pending, not published
        assert stored(client)["c.example.com/"].status == "pending"
        client.fake.fail_next = 0
        r = sync(client, ["a.example.com", "c.example.com"], sync_id="3", delete_missing=True)
        assert r["counts"]["removed"] == 1 and "b.example.com/" not in stored(client)

    def test_a_panorama_outage_is_never_approval(self, client):
        apex_policy(client)
        client.fake.fail_next = 10_000
        r = sync(client, ["a.example.com", "*.example.org"], sync_id="1")
        assert r["counts"]["pending_classification"] == 2 and feed_lines(client) == []
        assert {e.status for e in stored(client).values()} == {"pending"}

    def test_failure_while_writing_changes_nothing(self, client, monkeypatch):
        sync(client, ["a.example.com"], sync_id="1")
        before_feed = feed(client).text
        real = service.rebuild_snapshot

        def boom(db, list_name, *, commit=True):
            if not commit:
                raise RuntimeError("snapshot failure")
            return real(db, list_name, commit=commit)
        monkeypatch.setattr(service, "rebuild_snapshot", boom)
        sync(client, ["a.example.com", "b.example.com", "c.example.com"], sync_id="2", delete_missing=True, expect=500)
        monkeypatch.setattr(service, "rebuild_snapshot", real)
        assert set(stored(client)) == {"a.example.com/"}                         # rolled back as a whole
        assert feed(client).text == before_feed
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(EntrySource)) == 1
            failed = s.scalars(select(SyncRun).where(SyncRun.status == "failed")).one()
            assert failed.sync_id == "2" and s.scalars(select(AuditLog).where(AuditLog.action == "sync-failed")).one()
            assert s.scalars(select(SyncRun).where(SyncRun.status != "failed")).one().sync_id == "1"

    def test_failure_while_planning_changes_nothing(self, client, monkeypatch):
        monkeypatch.setattr(sync_mod, "build_plan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db gone")))
        sync(client, ["a.example.com"], expect=500)
        assert stored(client) == {} and feed(client).text == ""


# =========================================================================== dry run
class TestDryRun:
    def test_dry_run_changes_nothing_at_all(self, client):
        apex_policy(client)
        sync(client, ["keep.example.com", "gone.example.com"], sync_id="1")
        calls = len(client.fake.calls)
        with writes(client, ANY_WRITE) as seen:
            r = sync(client, ["keep.example.com", "new.example.com", "*.example.org", "bad.example.net"],
                     sync_id="dry", delete_missing=True, dry_run=True)
        assert seen == [] and len(client.fake.calls) == calls                    # no writes, no Panorama requests
        assert r["dry_run"] is True and r["status"] == "dry_run" and r["run_id"] is None
        assert feed_lines(client) == ["gone.example.com/", "keep.example.com/"]
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(SyncRun)) == 1      # only the real sync is recorded

    def test_dry_run_reports_what_a_real_run_then_does(self, client):
        apex_policy(client)
        sync(client, ["keep.example.com", "gone.example.com", "www.example.org"], sync_id="1")
        body = dict(entries=["keep.example.com", "*.example.org", "www.example.org", "new.example.net"], delete_missing=True)
        client.post("/v1/lists/default/sync", json={"source": "yaml-import", "sync_id": "x", "dry_run": True,
                                                   **body, "entries": body["entries"]}, headers=bearer(client.token))
        # prime the cache so the dry run can project the wildcard and the new entry
        service_calls = len(client.fake.calls)
        dry = sync(client, body["entries"], sync_id="d", delete_missing=True, dry_run=True)
        assert len(client.fake.calls) == service_calls
        assert dry["classification_needed"]["requires_live"] == 2
        real = sync(client, body["entries"], sync_id="r", delete_missing=True)
        keys = ("total_desired", "existing", "new", "unchanged", "removed")
        assert {k: dry["counts"][k] for k in keys} == {k: real["counts"][k] for k in keys}
        assert real["counts"]["suppressed_by_shadowing"] == 1
        assert feed_lines(client) == ["*.example.org/", "keep.example.com/", "new.example.net/"]

    def test_dry_run_uses_cached_classifications_and_projects_the_final_state(self, client):
        apex_policy(client)
        post(client, ["warm.example.com", "example.org"])                          # primes the cache for these targets
        calls = len(client.fake.calls)
        r = sync(client, ["warm.example.com", "*.example.org", "www.example.org"], dry_run=True)
        assert len(client.fake.calls) == calls
        assert r["classification_needed"] == {"cached": 1, "requires_live": 1, "not_required": 0, "left_to_engine": 0}
        by = {e["entry"]: e for e in r["entries"]}
        assert by["*.example.org/"]["status"] == "active" and by["*.example.org/"]["classification"]["source"] == "cached"
        assert by["www.example.org/"]["status"] == "pending" and by["www.example.org/"]["classification"]["source"] == "requires_live"
        assert r["feed"]["entries_after"] == 3 and r["feed"]["changed"] is True

    def test_dry_run_shows_suppression_and_removals_without_applying(self, client):
        apex_policy(client)
        sync(client, ["a.example.com", "gone.example.com", "example.org"], sync_id="1")
        post(client, ["example.net"])
        r = sync(client, ["a.example.com", "example.org"], delete_missing=True, dry_run=True, sync_id="d")
        assert r["counts"]["removed"] == 1 and {e["action"] for e in r["entries"]} == {"would_remove"}
        assert "gone.example.com/" in feed_lines(client)

    def test_dry_run_with_invalid_entries_and_delete_missing_is_still_refused_but_unrecorded(self, client):
        r = sync(client, ["bad entry!"], dry_run=True, delete_missing=True, expect=422)
        assert r["detail"]["invalid"]
        with client.factory() as s:
            assert s.scalar(select(func.count()).select_from(SyncRun)) == 0
            assert s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action.like("sync%"))) == 0


# =========================================================================== wildcards and shadowing via sync
class TestSyncWildcards:
    def test_exclude_policy_blocks_wildcards_without_asking_panorama(self, client):
        r = sync(client, ["*.example.com", "www.example.com"])
        assert r["counts"]["blocked_by_policy"] == 1 and client.fake.calls == ["www.example.com"]
        assert feed_lines(client) == ["www.example.com/"]

    def test_apex_policy_approves_classifies_the_apex_and_suppresses(self, client):
        apex_policy(client)
        r = sync(client, ["*.example.com", "www.example.com", "mail.example.com", "example.com"])
        c = r["counts"]
        assert (c["approved_by_apex_classification"], c["suppressed_by_shadowing"]) == (1, 2)
        assert feed_lines(client) == ["*.example.com/", "example.com/"]
        by = {e["entry"]: e for e in r["entries"]}
        assert by["www.example.com/"]["suppressed_by"] == "*.example.com/" and by["www.example.com/"]["published"] is False
        assert "*.example.com" not in " ".join(client.fake.calls)

    def test_wildcard_is_not_published_until_approved(self, client):
        apex_policy(client)
        client.fake.fail_next = 10_000
        sync(client, ["*.example.com", "www.example.com"])
        assert stored(client)["*.example.com/"].status == "pending"
        assert stored(client)["www.example.com/"].suppressed_by is None      # a pending wildcard suppresses nothing
        assert feed_lines(client) == []                                       # and nothing unclassified is published
        client.fake.fail_next = 0
        eng.tick(force=True)
        assert feed_lines(client) == ["*.example.com/"]

    def test_removing_the_wildcard_from_the_source_restores_subdomains(self, client):
        apex_policy(client)
        sync(client, ["*.example.com", "www.example.com"], sync_id="1", delete_missing=True)
        assert feed_lines(client) == ["*.example.com/"]
        sync(client, ["www.example.com"], sync_id="2", delete_missing=True)
        assert feed_lines(client) == ["www.example.com/"] and stored(client)["www.example.com/"].suppressed_by is None

    def test_wildcard_with_no_cache_entry_and_classification_disabled_stays_pending(self, client):
        apex_policy(client)
        put_settings(client, {"classification_enabled": False}, confirm=True)
        r = sync(client, ["*.example.com", "plain.example.org"])
        assert r["counts"]["pending_classification"] == 1 and feed_lines(client) == ["plain.example.org/"]

    def test_policy_change_is_picked_up_by_the_next_sync(self, client):
        sync(client, ["*.example.com", "www.example.com"], sync_id="1", delete_missing=True)
        assert feed_lines(client) == ["www.example.com/"]
        apex_policy(client)
        eng.tick(force=True)
        r = sync(client, ["*.example.com", "www.example.com"], sync_id="2", delete_missing=True)
        assert r["status"] == "no_change" and r["counts"]["suppressed_by_shadowing"] == 1
        assert feed_lines(client) == ["*.example.com/"]


# =========================================================================== bounded work
class TestBudget:
    def test_live_lookups_are_bounded_and_the_rest_is_queued_pending(self, client):
        put_settings(client, {"sync_classification_budget": 2})
        r = sync(client, [f"h{i}.example.com" for i in range(5)])
        assert r["counts"]["live_lookups"] == 2 and r["counts"]["queued_for_background"] == 3
        assert len(client.fake.calls) == 2 and len(feed_lines(client)) == 2
        assert sorted(e.status for e in stored(client).values()) == ["active", "active", "pending", "pending", "pending"]
        put_settings(client, {"sync_classification_budget": 2000})
        eng.tick(force=True)
        assert len(feed_lines(client)) == 5                                     # the background engine finished the job

    def test_budget_zero_never_contacts_panorama(self, client):
        put_settings(client, {"sync_classification_budget": 0})
        sync(client, ["a.example.com"])
        assert client.fake.calls == [] and feed_lines(client) == []

    def test_identical_apex_domains_count_once_against_the_budget(self, client):
        apex_policy(client)
        put_settings(client, {"sync_classification_budget": 1})
        r = sync(client, ["*.example.com", "*.example.com/a", "*.example.com/b", "example.com"])
        assert r["counts"]["live_lookups"] == 1 and r["counts"]["queued_for_background"] == 0

    def test_size_limit(self, client):
        put_settings(client, {"max_sync_size": 3})
        sync(client, ["a.example.com", "b.example.com", "c.example.com", "d.example.com"], expect=413)
        sync(client, ["a.example.com", "b.example.com", "c.example.com"])


# =========================================================================== request validation and auth
class TestRequest:
    def test_sync_id_and_source_validation(self, client):
        for body in ({"source": "s", "sync_id": "bad id with spaces", "entries": []},
                     {"source": "s", "sync_id": "", "entries": []},
                     {"source": "", "sync_id": "x", "entries": []},
                     {"source": "s", "sync_id": "x"},
                     {"source": "s", "sync_id": "x", "entries": "a.example.com"}):
            r = client.post("/v1/lists/default/sync", json=body, headers=bearer(client.token))
            assert r.status_code == 422, body

    def test_host_plus_source_length_is_limited_like_other_submissions(self, client):
        long_host = second_host(client, "h" * 64)
        r = client.post("/v1/lists/default/sync", json={"source": "s" * 100, "sync_id": "x", "entries": ["a.example.com"]},
                        headers=bearer(long_host))
        assert r.status_code == 422 and "128" in r.text
        assert stored(client) == {}

    def test_requires_a_host_token(self, client):
        body = {"source": "s", "sync_id": "x", "entries": ["a.example.com"]}
        assert client.post("/v1/lists/default/sync", json=body).status_code == 401
        assert client.post("/v1/lists/default/sync", json=body, headers=KEY).status_code == 401   # management key is not a host token
        assert client.post("/v1/lists/default/sync", json=body, headers=bearer("nope")).status_code == 401
        assert stored(client) == {}

    def test_list_permission_is_enforced(self, client):
        limited = second_host(client, "limited", lists="allowed")
        body = {"source": "s", "sync_id": "x", "entries": ["a.example.com"]}
        assert client.post("/v1/lists/denied/sync", json=body, headers=bearer(limited)).status_code == 403
        assert client.post("/v1/lists/allowed/sync", json=body, headers=bearer(limited)).status_code == 200

    def test_ip_restriction_applies(self, client):
        from fastapi.testclient import TestClient
        outside = TestClient(client.main.app, client=("192.0.2.9", 1))
        r = outside.post("/v1/lists/default/sync", json={"source": "s", "sync_id": "x", "entries": []},
                         headers=bearer(client.token))
        assert r.status_code in (401, 403)

    def test_bad_list_name(self, client):
        r = client.post("/v1/lists/bad name!/sync", json={"source": "s", "sync_id": "x", "entries": []},
                        headers=bearer(client.token))
        assert r.status_code in (404, 422)

    def test_audit_trail_records_the_sync(self, client):
        sync(client, ["a.example.com", "b.example.com"], sync_id="aud-1")
        rows = client.get("/v1/admin/audit?kind=api", headers=KEY).json()["records"]
        rec = [r for r in rows if r["action"] == "sync"][0]
        assert rec["actor"] == "host:ticketing" and rec["target"] == "default"
        assert "source=yaml-import" in rec["detail"] and "sync_id=aud-1" in rec["detail"] and "new=2" in rec["detail"]
        assert rec["ip"] == "10.0.0.5"

    def test_sync_does_not_leak_secrets(self, client):
        r = sync(client, ["a.example.com"])
        blob = str(r) + client.get("/v1/admin/sync/runs/1", headers=KEY).text + client.get("/v1/admin/sync/sources", headers=KEY).text
        assert client.token not in blob and "token_hash" not in blob


# =========================================================================== concurrency
class TestConcurrency:
    @pytest.fixture
    def file_db(self, tmp_path, client):
        """A real file-backed database: the shared in-memory connection of the test client is not thread safe."""
        from sqlalchemy import create_engine
        eng_ = create_engine(f"sqlite:///{tmp_path / 'c.db'}", connect_args={"check_same_thread": False, "timeout": 30})
        migrations.run_migrations(eng_)
        return sessionmaker(eng_, expire_on_commit=False), eng_

    def run_threads(self, fns):
        errors, out = [], [None] * len(fns)

        def wrap(i, fn):
            try:
                out[i] = fn()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        ts = [threading.Thread(target=wrap, args=(i, f)) for i, f in enumerate(fns)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        return out, errors

    def req(self, sync_id, entries, **kw):
        return sync_mod.SyncIn(source="src", sync_id=sync_id, entries=entries, **kw)

    def test_concurrent_syncs_of_one_list_are_serialised_and_consistent(self, client, file_db):
        factory, _ = file_db
        import time
        orig = client.fake.lookup
        client.fake.lookup = lambda t: (time.sleep(0.05), orig(t))[1]

        def go(sync_id, entries):
            def run():
                with factory() as db:
                    return sync_mod.run_sync(db, list_name="L", host="h", req=self.req(sync_id, entries, delete_missing=True))
            return run
        out, errors = self.run_threads([go("1", ["a.example.com", "b.example.com"]), go("2", ["b.example.com", "c.example.com"]),
                                        go("3", ["c.example.com", "d.example.com"])])
        assert errors == []
        with factory() as db:
            values = sorted(db.scalars(select(Entry.value)))
            runs = sorted(db.scalars(select(SyncRun.sync_id)))
            owned = sorted(db.scalars(select(Entry.value).join(EntrySource, EntrySource.entry_id == Entry.id)))
        assert runs == ["1", "2", "3"]
        assert values == owned and len(values) == len(set(values))                       # no orphans, no duplicates
        assert values in (["a.example.com/", "b.example.com/"], ["b.example.com/", "c.example.com/"],
                          ["c.example.com/", "d.example.com/"])                          # exactly one request's final state

    def test_concurrent_identical_sync_id_is_applied_once(self, client, file_db):
        factory, _ = file_db

        def run():
            with factory() as db:
                return sync_mod.run_sync(db, list_name="L", host="h", req=self.req("same", ["a.example.com"]))
        out, errors = self.run_threads([run, run, run])
        assert errors == []
        assert sorted(o["duplicate"] for o in out) == [False, True, True]
        assert {o["run_id"] for o in out} == {out[0]["run_id"]}
        with factory() as db:
            assert db.scalar(select(func.count()).select_from(SyncRun)) == 1

    def test_sync_and_legacy_submission_race_safely(self, client, file_db):
        factory, _ = file_db

        def do_sync():
            with factory() as db:
                return sync_mod.run_sync(db, list_name="L", host="h", req=self.req("1", [f"s{i}.example.com" for i in range(30)]))

        def do_post():
            with factory() as db:
                return service.add_urls(db, "L", [f"s{i}.example.com" for i in range(0, 30, 2)] + ["p.example.com"], "h2:manual")
        out, errors = self.run_threads([do_sync, do_post])
        assert errors == []
        with factory() as db:
            assert db.scalar(select(func.count()).select_from(Entry)) == 31
            assert db.scalar(select(func.count()).select_from(Entry).where(~Entry.id.in_(select(EntrySource.entry_id)))) == 0
