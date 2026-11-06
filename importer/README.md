# EDL Publisher YAML importer 2.1.1

Synchronises Palo Alto-style YAML URL lists into **EDL Publisher 2.3.1** using the source-based sync API
(`POST /v1/lists/{list}/sync` and chunked upload sessions). It replaces the old append-only importer that used
`POST /v1/lists/{list}/entries`.

Each YAML list is one **source**. The importer sends that source's desired state and the server works out what to
add, keep and (only if you ask) remove. A source can only ever remove entries **it** owns: entries owned by other
sources, and entries added by hand or through the old `/entries` endpoint, are never removed by it.

> **Server compatibility.** Importer 2.1.1 is built for **EDL Publisher 2.3.1**, which has the chunked-sync
> endpoints, the `reclassify` option and the server-enforced `max_removals`. Against 2.3.0 everything works except
> that `--max-removals` is checked by the importer alone (it says so). Against the older v2.2.0 archive it still works for lists up to that
> server's *Maximum sync size* with `--mode single`; chunked mode and `--reclassify` are refused with a clear
> message (see *Server API requirements*).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # httpx, PyYAML (Python 3.10+)
export EDL_BASE_URL="https://edl.example.net"
export EDL_HOST_TOKEN="edl_your-host-token"   # the per-host token, not the management API_KEY
```

## YAML shape

```yaml
---
url:
  - name: threat-feeds
    description: sample list
    type: URL List
    list:
      member:
        - "*.example.com"
        - example.com
```

Several `url` blocks and `---` documents are supported. Whitespace in a list name becomes `_`; two names that
become the same are refused. Members are sent exactly as written.

## Usage

```bash
# 1. look first: parse and report only, the server is not contacted
python import_edl.py urls.yaml --dry-run

# 2. ask the server what it WOULD do; nothing changes and no checkpoint is kept
python import_edl.py urls.yaml --server-dry-run --delete-missing

# 3. synchronise: add and update only (entries that left the YAML are KEPT)
python import_edl.py urls.yaml

# 4. also remove entries this source owns that are no longer listed
python import_edl.py urls.yaml --delete-missing
python import_edl.py urls.yaml --delete-missing --max-removals 500    # refuse if more than 500 would go

# interrupted? continue exactly where it stopped
python import_edl.py urls.yaml --resume

# ask Panorama again about entries that already exist
python import_edl.py urls.yaml --reclassify

# more examples
python import_edl.py urls.yaml --chunk-size 5000          # smaller upload chunks
python import_edl.py urls.yaml --target-list default      # every YAML list into one EDL, still one source each
python import_edl.py urls.yaml --no-deduplicate           # send every occurrence; the server deduplicates
python import_edl.py urls.yaml --report-file report.json  # machine-readable result
python import_edl.py urls.yaml --mode single              # servers without chunked sync (lists up to 'Maximum sync size')
```

### Options

| Option | Meaning |
|---|---|
| `--base-url`, `--token` | Server and host token (or `EDL_BASE_URL`, `EDL_HOST_TOKEN`). |
| `--source-prefix` (alias `--source`) | Source ids are `<prefix>:<YAML list name>`, default `yaml-import`. **Keep it stable**: it is the identity ownership is tracked under. |
| `--target-list NAME` | Put every YAML list into one EDL list. Each YAML list still has its own source, so lists never remove each other's entries. |
| `--mode auto\|single\|chunked` | `auto` (default): one request for lists up to `--chunk-size` entries, chunked sessions above that. |
| `--chunk-size N` | Entries per upload chunk (default 10000). The server's limit is *Largest accepted chunk* (default 25000). |
| `--delete-missing` | **Off by default.** Remove entries this source owns that are no longer in the YAML list. Before committing, the number to be removed is shown (from a server dry run). `--no-delete-missing` is accepted as an alias of the default. |
| `--max-removals N` | With `--delete-missing`: refuse to commit if more than N entries would be removed from a list. Checked against the preview **and** sent to the server (`max_removals`), which re-checks it inside the commit transaction against the list as it is at that moment, so a list that changed since the preview cannot be deleted from beyond N. A server without the field is told so and only the preview check applies. |
| `--confirm-empty` | Allow an empty YAML list to remove everything its source owns (only meaningful with `--delete-missing`). |
| `--deduplicate` / `--no-deduplicate` | Importer-side deduplication, **on by default**. Off: every occurrence is sent. |
| `--reclassify` | Ask the server to re-classify the entries of the desired state that already exist. See *Reclassification*. |
| `--resume` / `--discard-checkpoint` | Continue an unfinished import / abandon it (and its open upload session) and start a new one. |
| `--state-file` | Checkpoint path (default `<yaml file>.import-state.json`). |
| `--timeout`, `--commit-timeout`, `--max-retries` | HTTP timeouts and retries. The commit classifies and applies, so it gets its own, longer timeout (default 900 s). |
| `--report-file` | JSON report, including every rejected entry with its YAML line. |
| `--dry-run` / `--server-dry-run` | Local-only report / server-side "what would change" (nothing applied). Neither ever deletes anything. |

Exit codes: `0` success; `1` a list did not complete (or the server refused it); `2` usage, YAML or checkpoint
problem; `3` the server lacks a requested capability (`--reclassify` on a server without it).

## How a synchronisation works

For every YAML list (one source each) the importer:

1. generates a `sync_id` and **saves it in the checkpoint before sending anything**;
2. uploads the entries in YAML order, in chunks (or in one request for small lists);
3. **with `--delete-missing`**: asks the server for a dry run of exactly this desired state and prints how many
   entries the commit will remove (and how many are kept because another source also owns them). With
   `--max-removals` it stops here, before anything is committed, if the number is too high (and the server enforces
   the same limit again at commit; if the list changed in between it refuses with 409 and the staged upload is kept,
   so `--resume` with a higher `--max-removals` re-commits without re-uploading);
4. only after **every** chunk was acknowledged, commits, stating the total chunks and entries;
5. the server verifies completeness, validates, classifies and applies everything in one transaction.

Until step 5 nothing about the list changes, so an interrupted or partial upload can never remove (or add)
anything. The server refuses a commit whose chunk count or entry count does not match (HTTP 409,
`nothing_applied`), and the importer never treats a partly uploaded file as a complete desired state.

### Deletion

By default **nothing is ever removed**: entries that left the YAML stay on the server and are counted in the
summary (`kept, NOT removed because --delete-missing is not set`). With `--delete-missing` the server removes the
ownership of this source for entries no longer listed, and deletes an entry only when no other source owns it. A
server dry run (`--server-dry-run`) and the local `--dry-run` never delete anything. Removing an entire list's
content needs `--delete-missing` **and** `--confirm-empty` for an empty YAML list.

### Checkpoint, resume and recovery

* One checkpoint per run (`<yaml>.import-state.json`) holds, per list: `sync_id`, session id, chunk size, a
  SHA-256 per uploaded chunk, the removal preview, status. It is rewritten atomically after every acknowledged chunk.
* `--resume` reuses the same `sync_id` and session, skips chunks the server already holds, and uploads the rest.
  A chunk whose reply was lost is simply sent again to the **same** session: the server acknowledges an identical
  chunk and refuses a different one. No new session is created for a retry.
* If the importer dies after the server applied the sync but before the checkpoint recorded it, `--resume` asks
  the server, which answers that the `sync_id` was already applied. It is not applied twice.
* If the server lost the session (expired), nothing was applied; the importer restarts the upload with the
  **same** `sync_id`. A server **restart** loses nothing: sessions are stored in the database.
* Resume is bound to the YAML file hash, server, `--target-list`, `--source-prefix`, `--chunk-size`, `--mode`,
  `--deduplicate`/`--no-deduplicate`, `--delete-missing` and `--reclassify`. Anything else changing is refused (a
  resumed import never changes the contents of batches already sent). `--max-removals` and `--confirm-empty` may be
  changed on resume (they are safety decisions, not content).
* Without `--resume`: an **unfinished** checkpoint is never overwritten silently (use `--resume` or
  `--discard-checkpoint`, which also abandons its open upload session on the server); a **completed** one is
  replaced and the new run gets new `sync_id`s.
* The checkpoint is kept after success, marked completed, as the record of what the server confirmed.
* Source ids do not depend on the file name. The default checkpoint *path* does, so after renaming the YAML file
  pass `--state-file` to resume.

### Large imports

100,000 URLs per list is the tested size (10 chunks of 10,000). A request never carries more than one chunk.
The importer's own memory is dominated by the parsed YAML: a 100,000-entry list peaks at about **41 MB** (traced
Python allocations, libyaml parser), independent of the chunk count.

The upload is acknowledged chunk by chunk (`uploaded chunk 3/10 ... 30.0%`). The commit is one long request
(validation, classification, apply); the importer says so and waits up to `--commit-timeout`.

**Uploaded does not mean published.** A server classifies at most *Sync classification budget* new entries
(default 2000) per sync; the rest are stored as *pending* and classified by the server's background engine, which
keeps taking batches until the backlog is gone (Panorama allows at most 5 concurrent requests, so it takes time).
Pending entries are not published. The summary says so explicitly (`UPLOAD COMPLETE, BUT CLASSIFICATION IS STILL
PENDING for N entries`). Repeating the import later is safe.

### Safety rules

* **Empty desired state:** a YAML list with no members is not synchronised unless `--delete-missing --confirm-empty`
  are given; with `--delete-missing` but no confirmation nothing is sent for that list and the run exits `1`. A file
  with no lists at all is refused.
* **Invalid entries:** the server validates every chunk as it arrives and the importer reports
  `N entries rejected by the server` per chunk. With `--delete-missing`, any invalid entry makes the server refuse
  the whole sync (HTTP 422, nothing added or removed). Without it the valid entries are applied and the rejected ones
  are listed with their YAML line (all of them, not only the first 100; `--report-file` has them too).
* A definitive refusal abandons the staged upload so the next run is not blocked by it.
* A list that disappears from the YAML entirely is **not** touched (the importer keeps no remote inventory). To empty
  a source, keep its block in the YAML with no members and use `--delete-missing --confirm-empty`.

## Deduplication

`--deduplicate` (default): duplicates are removed before sending. Two entries are duplicates when the server would
store them as one: scheme, credentials, port, query and fragment are ignored, case is ignored, a domain root is
`host/` however written, and **a path keeps its trailing slash**, so `a.com/x` and `a.com/x/` are different.

`--no-deduplicate`: every occurrence in the YAML is sent, byte for byte as written (only blank members are
skipped and counted), including duplicates inside one chunk and across chunks. The server canonicalises,
deduplicates and handles ownership; the importer never claims to have deduplicated.

Reported per list: occurrences read; unique URLs (computed locally either way); duplicates removed by the importer;
occurrences submitted; entries newly created by the server; already present and unchanged; duplicates identified by
the server (`duplicates_in_request`: repeated occurrences within the submission); rejected by validation; removed;
blocked by policy / by classification; pending classification; suppressed by a wildcard; published.

## Reclassification (`--reclassify`)

Without the option, existing valid classifications are preserved: an identical sync sends nothing to Panorama.

With `--reclassify` the importer sends `"reclassify": true` (the field exists on the server's `SyncIn` and
`SessionStart` models, which the importer checks in `/openapi.json` first; a server without it gets exit code `3`
and nothing is sent). The server then, for the entries of this desired state that already exist:

* asks Panorama again (the classification cache is refreshed), at most 5 requests at a time (the server's limit; the
  importer never talks to Panorama);
* reconsiders previously blocked and pending entries, and can block previously approved ones;
* never approves anything after a timeout, error or inconclusive answer: a failed lookup leaves the entry exactly as
  it was and it is retried;
* recomputes wildcard suppression and the published feed;
* does the first *Sync classification budget* lookups inside the request and queues the rest as a persisted job that
  its background engine finishes, surviving restarts.

The summary shows `Reclassification (job N): X existing entries, Y re-checked now (Z changed), Q queued for the
server, F failed and will be retried; R remaining -> running|done`. If a job is still running the importer says so
(`RECLASSIFICATION OF [list] IS STILL RUNNING ON THE SERVER`) and prints the status URL
`GET /v1/lists/<list>/sync/reclassifications/<job_id>` (host token). The importer does not wait for the job.
`--server-dry-run --reclassify` reports the scope and the number of lookups needed without contacting Panorama.

## Server API requirements (EDL Publisher 2.3.1)

All calls use `Authorization: Bearer <host token>`; the host must be allowed for every destination list and the
importer's source address.

| Call | Used for | Fields the importer sends / needs back |
|---|---|---|
| `POST /v1/lists/{list}/sync` | Lists up to `--chunk-size` (and `--mode single`); also the removal preview (`dry_run: true`) | Body: `source`, `sync_id`, `entries` (strings), `delete_missing`, `confirm_empty`, `dry_run`, `verbose`, `reclassify` only with `--reclassify`, and `max_removals` only with `--delete-missing --max-removals` (and only if the server schema defines it). Needs `status`, `counts.*`, `feed`, `invalid`, `reclassification`. HTTP 413 above *Maximum sync size*; 422 invalid/empty without confirm; 409 `sync_id` reused with different content. |
| `POST /v1/lists/{list}/sync/sessions` | Start or resume a chunked sync | Body: `source`, `sync_id`, `delete_missing`, `confirm_empty`, `reclassify`. Needs `session_id`, `received_ranges`, `max_chunk_size`, `resumed`; or `status: "already_applied"`. One open session per host+source (409 otherwise). |
| `GET .../sessions/{id}` | Progress on resume; `received_invalid` | `status`, `received_ranges`, `received_invalid`. 404/410 = session gone. |
| `PUT .../sessions/{id}/chunks/{index}` | Stage one chunk | Body `{"entries": [...]}`. Idempotent per index (same content → `already_received`; different → 409). 413 above *Largest accepted chunk*. Reply has `invalid_in_chunk`. |
| `GET .../sessions/{id}/invalid?offset=&limit=` | Every rejected entry with `chunk` and `position` | Paged, up to 1000 per page. |
| `POST .../sessions/{id}/commit` | Verify, classify, apply; with `dry_run: true` the removal preview (session stays open) | Body: `total_chunks`, `total_entries`, `dry_run`, and `max_removals` as above. 409 + `nothing_applied` if incomplete; 409 + `removal_limit_exceeded` if the limit would be exceeded (session stays open); otherwise the sync report. |
| `DELETE .../sessions/{id}` | Abandon after a refusal / server dry run / `--discard-checkpoint` | — |
| `GET /openapi.json` | For `--reclassify` and `--max-removals` | `SyncIn` / `SessionStart` must define `reclassify`; `SyncIn` / `CommitIn` `max_removals`. |

Server settings that matter: *Maximum sync size* (default 250,000), *Largest accepted chunk* (25,000), *Rate limit*
(default 120 requests/minute per host - an inbound limit on this application, not a Panorama limit: a 100,000-entry
list in 10,000-entry chunks is about 14 requests, but very small chunks hit HTTP 429, which the importer retries
honouring `Retry-After`), *Sync classification budget* (2000),
*Delay between batches* and *Maximum batch size* (background engine speed).

The importer never sends a field the server's models do not define. Against the **v2.2.0** archive (single-request
sync only, no `reclassify`, no `/invalid`, `received_invalid` or `invalid_in_chunk`) it works with `--mode single`
for lists within that server's *Maximum sync size*; the removal preview uses the same `dry_run` field.

## Remaining limits

* A list that disappears from the YAML is not touched (see above); the checkpoint name depends on the file name.
* Memory is linear in the parsed YAML (PyYAML builds the document tree) but request payloads are one chunk.
* Large reclassifications and first imports are finished by the server's background engine at Panorama speed (at most
  5 concurrent requests); the importer reports it but does not wait.
* The default rate limit (120 requests/minute/host) applies to the importer like any other host. Classification time
  is not bounded by it; see the server README, *Panorama concurrency*, for estimates (not measurements).

## Changes in 2.1.1

* `--max-removals` is also sent to the server, which enforces it inside the commit transaction (stale previews and
  concurrent runs cannot exceed it). Refusals keep the staged upload so `--resume` can re-commit.

## Changes from importer 2.0

* **`--delete-missing` is now required to remove anything** (2.0 removed by default). `--no-delete-missing` remains
  as an alias of the default, so old scripts are safe; scripts that relied on removal must add `--delete-missing`.
* With `--delete-missing` the number to be removed is displayed before committing; `--max-removals` is new.
* `--reclassify` is implemented (server `reclassify` option, 2.3.0 and later) and reports the server's reclassification job.
* Every rejected entry is listed with its YAML line (not only the first 100); chunk uploads report rejects as they happen.
* `--discard-checkpoint` abandons the old run's open upload session.

### Changes from importer 1.x

* Uses `/sync`, not `/entries`. One source per YAML list (`yaml-import:<name>`). With `--target-list`, lists are no
  longer merged and deduplicated against each other: each keeps its own ownership.
* Checkpoint format changed (old checkpoints are refused); `--source` is now `--source-prefix` (old name accepted).
* Members are sent as written, not stripped; blank members are skipped and counted.
* `canonical_key` keeps path trailing slashes, as the server does; the 401/403 message shows the response;
  `parse_yaml` annotation corrected.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest                                     # unit + protocol tests (+ integration if the server source is found)
EDL_SERVER_SRC=/path/to/edl-service python -m pytest # integration tests against the server SOURCE TREE, in process
```

* `tests/test_unit.py`, `tests/test_protocol.py`: no server needed (scripted fake server: failure injection,
  capability checks, the 100,000-entry memory bound).
* `tests/test_integration.py`, `tests/test_v21_deletion_reclassify.py`: the importer against the actual EDL
  Publisher application **source tree**, in process, in-memory database, fake Panorama.
* `tests/test_packaged_pair.py`: the **packaged** pair. It extracts a server archive, starts it as a real
  `uvicorn` process with a file database and mock Panorama, and runs *this* importer (as extracted from its own ZIP)
  through the nine acceptance scenarios (64,000-entry import, identical repeat, `--no-deduplicate`,
  `--delete-missing` and not, interrupted upload and resume, reclassification of blocked and pending entries,
  100,000-entry chunked import, server restart during an incomplete sync):

  ```bash
  EDL_SERVER_ARCHIVE=/path/to/edl-service.tar.gz python -m pytest tests/test_packaged_pair.py -v
  ```

  Without `EDL_SERVER_ARCHIVE` these tests are skipped, not passed. Set `EDL_LEGACY_ARCHIVE` to the previously
  delivered v2.2.0 archive to also run the older-server check (single mode works; `--reclassify` and chunked mode are
  refused with a clear message).
