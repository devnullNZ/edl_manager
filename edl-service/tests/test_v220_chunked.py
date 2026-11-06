"""v2.2.0 (section 8): chunked, resumable synchronisation."""
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import service
from app.db import Entry, EntrySource, SyncChunk, SyncRun, SyncSession, SyncStaged, utcnow
from conftest import KEY, bearer, chunked, feed, post, put_settings, sync

H = lambda c: bearer(c.token)  # noqa: E731


def hosts_of(c, names):
    with c.factory() as s:
        return sorted(s.scalars(select(Entry.value).where(Entry.list_name == "default")))


def names(n, tag="a"):
    return [f"{tag}{i:04d}.example.org" for i in range(n)]


def test_chunked_sync_applies_only_at_commit(client):
    ents = names(10)
    sess, _ = chunked(client, ents, chunk=3, commit=False)
    assert hosts_of(client, None) == []                      # staged, not applied
    assert feed(client).text == ""
    r = client.post(f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit", headers=H(client),
                    json={"total_chunks": 4, "total_entries": 10})
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["new"] == 10 and r.json()["session"]["chunks"] == 4
    assert feed(client).text.splitlines() == sorted(f"{e}/" for e in ents)
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(SyncStaged)) == 0     # staging cleaned up


def test_result_equals_single_request_sync(client):
    ents = names(25) + ["*.wild.example.org", "x.wild.example.org"]
    chunked(client, ents, chunk=4, sync_id="c1", source="a")
    first = feed(client).text
    from app.db import SyncRun
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(Entry)) == 27
    # same content through the one-request endpoint, as a different source: nothing new, identical feed
    r = sync(client, ents, source="b", sync_id="s1")
    assert r["counts"]["new"] == 0 and feed(client).text == first


def test_incomplete_sync_is_refused_and_removes_nothing(client):
    sync(client, names(6), source="imp", sync_id="base")
    before = feed(client).text
    sess, out = chunked(client, names(2), chunk=1, delete_missing=True, skip=(1,), commit=True)
    assert out.status_code == 409
    body = out.json()["detail"]
    assert body["nothing_applied"] is True and any("missing" in e for e in body["errors"])
    assert feed(client).text == before and len(hosts_of(client, None)) == 6      # nothing removed


def test_wrong_totals_are_refused(client):
    sess, _ = chunked(client, names(5), chunk=2, commit=False)
    url = f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit"
    assert client.post(url, headers=H(client), json={"total_chunks": 3, "total_entries": 6}).status_code == 409
    assert client.post(url, headers=H(client), json={"total_chunks": 4, "total_entries": 5}).status_code == 409   # chunk 3 missing
    assert client.post(url, headers=H(client), json={"total_chunks": 2, "total_entries": 5}).status_code == 409   # extra chunk
    assert hosts_of(client, None) == []
    assert client.post(url, headers=H(client), json={"total_chunks": 3, "total_entries": 5}).status_code == 200


def test_resume_after_interruption(client):
    ents = names(9)
    first, _ = chunked(client, ents, chunk=3, skip=(1,), commit=False)
    # the importer restarts: same source and sync_id returns the same session and says what is missing
    r = client.post("/v1/lists/default/sync/sessions", headers=H(client), json={"source": "imp", "sync_id": "c1"})
    j = r.json()
    assert j["resumed"] is True and j["session_id"] == first["session_id"]
    assert j["received_ranges"] == [[0, 0], [2, 2]] and j["missing_below_highest"] == [1]
    ok = client.put(f"/v1/lists/default/sync/sessions/{j['session_id']}/chunks/1", headers=H(client),
                    json={"entries": ents[3:6]})
    assert ok.status_code == 200 and ok.json()["missing_below_highest"] == []
    c = client.post(f"/v1/lists/default/sync/sessions/{j['session_id']}/commit", headers=H(client),
                    json={"total_chunks": 3, "total_entries": 9})
    assert c.status_code == 200 and c.json()["counts"]["new"] == 9


def test_resume_survives_a_restart(client):
    ents = names(6)
    sess, _ = chunked(client, ents, chunk=3, skip=(1,), commit=False)
    client.main.init_app(client.engine, client.factory)          # the application starts again
    r = client.post("/v1/lists/default/sync/sessions", headers=H(client), json={"source": "imp", "sync_id": "c1"})
    assert r.json()["resumed"] and r.json()["received_chunks"] == 1


def test_repeated_chunk_is_idempotent_and_changed_chunk_refused(client):
    sess, _ = chunked(client, names(4), chunk=2, commit=False)
    url = f"/v1/lists/default/sync/sessions/{sess['session_id']}/chunks/0"
    again = client.put(url, headers=H(client), json={"entries": names(4)[:2]})
    assert again.status_code == 200 and again.json()["already_received"] is True
    assert again.json()["received_entries"] == 4
    other = client.put(url, headers=H(client), json={"entries": ["different.example.org"]})
    assert other.status_code == 409


def test_commit_is_idempotent_and_sync_id_cannot_be_reused_for_other_content(client):
    sess, first = chunked(client, names(5), chunk=2)
    assert first.status_code == 200 and first.json()["duplicate"] is False
    again = client.post(f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit", headers=H(client),
                        json={"total_chunks": 3, "total_entries": 5})
    assert again.status_code == 200 and again.json()["duplicate"] is True
    assert again.json()["run_id"] == first.json()["run_id"]
    # starting again with the applied sync_id says so instead of asking for the data again
    st = client.post("/v1/lists/default/sync/sessions", headers=H(client), json={"source": "imp", "sync_id": "c1"})
    assert st.json()["status"] == "already_applied"
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(SyncRun).where(SyncRun.status != "failed")) == 1
    # a chunk to a committed session is refused
    put = client.put(f"/v1/lists/default/sync/sessions/{sess['session_id']}/chunks/9", headers=H(client),
                     json={"entries": ["z.example.org"]})
    assert put.status_code == 409


def test_delete_missing_only_after_commit_and_only_for_the_source(client):
    post(client, ["manual.example.org"])
    sync(client, names(6), source="imp", sync_id="base")
    chunked(client, names(3), chunk=2, sync_id="full", delete_missing=True)
    assert [v for v in hosts_of(client, None)] == sorted(["manual.example.org/"] + [f"{n}/" for n in names(3)])


def test_invalid_entries_across_chunks_block_removal(client):
    sync(client, names(4), source="imp", sync_id="base")
    sess, out = chunked(client, names(2) + ["not a url !!", "a b"], chunk=2, sync_id="bad", delete_missing=True)
    assert out.status_code == 422 and len(hosts_of(client, None)) == 4


def test_empty_desired_state_needs_confirmation(client):
    sync(client, names(3), source="imp", sync_id="base")
    sess, _ = chunked(client, [], sync_id="e1", delete_missing=True, commit=False)
    url = f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit"
    assert client.post(url, headers=H(client), json={"total_chunks": 0, "total_entries": 0}).status_code == 422
    assert len(hosts_of(client, None)) == 3
    client.delete(f"/v1/lists/default/sync/sessions/{sess['session_id']}", headers=H(client))
    _, out = chunked(client, [], sync_id="e2", delete_missing=True, confirm_empty=True)
    assert out.status_code == 200 and hosts_of(client, None) == []


def test_one_open_session_per_source_and_abort_discards(client):
    s1, _ = chunked(client, names(4), chunk=2, commit=False)
    second = client.post("/v1/lists/default/sync/sessions", headers=H(client), json={"source": "imp", "sync_id": "other"})
    assert second.status_code == 409 and second.json()["detail"]["session_id"] == s1["session_id"]
    ab = client.delete(f"/v1/lists/default/sync/sessions/{s1['session_id']}", headers=H(client))
    assert ab.status_code == 200 and ab.json()["status"] == "aborted"
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(SyncStaged)) == 0
    assert hosts_of(client, None) == []
    assert client.post("/v1/lists/default/sync/sessions", headers=H(client),
                       json={"source": "imp", "sync_id": "other"}).status_code == 200


def test_other_sources_are_independent(client):
    chunked(client, names(3), chunk=2, source="a", sync_id="1", commit=False)
    chunked(client, names(3, "b"), chunk=2, source="b", sync_id="1")
    assert len(hosts_of(client, None)) == 3


def test_idle_session_expires_and_never_changes_the_list(client):
    sync(client, names(3), source="imp", sync_id="base")
    sess, _ = chunked(client, names(1), chunk=1, sync_id="idle", delete_missing=True, commit=False)
    with client.factory() as s:
        row = s.get(SyncSession, sess["session_id"])
        row.updated_at = utcnow() - timedelta(days=3)
        s.commit()
    from app import sync_sessions
    with client.factory() as s:
        assert sync_sessions.expire_stale(s) == 1
    r = client.post(f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit", headers=H(client),
                    json={"total_chunks": 1, "total_entries": 1})
    assert r.status_code == 410
    assert len(hosts_of(client, None)) == 3
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(SyncStaged)) == 0


def test_limits(client):
    put_settings(client, {"sync_max_chunk_size": 100, "max_sync_size": 150}, confirm=True)
    sess, _ = chunked(client, [], commit=False)
    base = f"/v1/lists/default/sync/sessions/{sess['session_id']}/chunks"
    assert client.put(f"{base}/0", headers=H(client), json={"entries": names(101)}).status_code == 413
    assert client.put(f"{base}/0", headers=H(client), json={"entries": names(100)}).status_code == 200
    assert client.put(f"{base}/1", headers=H(client), json={"entries": names(60, "z")}).status_code == 413
    assert client.put(f"{base}/-1", headers=H(client), json={"entries": ["a.example.org"]}).status_code == 422


def test_sessions_are_private_to_their_host_and_need_auth(client):
    sess, _ = chunked(client, names(2), commit=False)
    url = f"/v1/lists/default/sync/sessions/{sess['session_id']}"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=bearer("wrong")).status_code == 401
    assert client.get(url.replace("default", "other"), headers=H(client)).status_code == 404
    assert client.get(url, headers=H(client)).status_code == 200


def test_dry_run_commit_keeps_the_session_open(client):
    sess, out = chunked(client, names(4), chunk=2, dry_run=True)
    assert out.status_code == 200 and out.json()["dry_run"] is True
    assert hosts_of(client, None) == []
    url = f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit"
    real = client.post(url, headers=H(client), json={"total_chunks": 2, "total_entries": 4})
    assert real.status_code == 200 and real.json()["counts"]["new"] == 4


def test_repeat_sync_is_idempotent_and_makes_no_panorama_requests(client):
    ents = names(12)
    chunked(client, ents, chunk=5, sync_id="r1")
    n = len(client.fake.calls) if hasattr(client.fake, "calls") else None
    _, out = chunked(client, ents, chunk=5, sync_id="r2")
    j = out.json()
    assert j["counts"]["new"] == 0 and j["counts"]["unchanged"] == 12 and j["status"] == "no_change"
    if n is not None:
        assert len(client.fake.calls) == n


def test_duplicates_across_chunks_are_counted_once(client):
    _, out = chunked(client, ["a.example.org", "b.example.org", "a.example.org", "A.EXAMPLE.ORG"], chunk=2)
    j = out.json()
    assert j["counts"]["new"] == 2 and j["counts"]["duplicates_in_request"] == 2


def test_concurrent_commits_for_one_list_do_not_corrupt_it(client):
    import threading
    a, _ = chunked(client, names(30), chunk=10, source="a", sync_id="1", commit=False)
    b, _ = chunked(client, names(30, "b") + names(10), chunk=10, source="b", sync_id="1", commit=False)
    res = {}

    def go(tag, sess, total):
        res[tag] = client.post(f"/v1/lists/default/sync/sessions/{sess['session_id']}/commit", headers=H(client),
                               json={"total_chunks": total[0], "total_entries": total[1]}).status_code
    ts = [threading.Thread(target=go, args=("a", a, (3, 30))), threading.Thread(target=go, args=("b", b, (4, 40)))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert res == {"a": 200, "b": 200}
    assert len(feed(client).text.splitlines()) == 60
    with client.factory() as s:
        assert s.scalar(select(func.count()).select_from(Entry)) == 60
        # the 30 shared values are owned by both sources, stored once
        assert s.scalar(select(func.count()).select_from(EntrySource)) == 70
