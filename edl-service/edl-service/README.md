# EDL Publisher — release 2.2.0

**Version 2.2.0** (extends 2.1.1; nothing was removed): wildcard entries can be approved by classifying their
apex domain (`apex-classification`, labelled *Classify Apex Domain*); importers can reconcile a whole data set
with `POST /v1/lists/{name}/sync` (idempotent, multi-source ownership, dry run); approved wildcards suppress the
subdomain entries they cover without deleting them; domain roots are stored and published with a trailing slash
(`example.com/`); and the admin interface shows wildcard outcomes, sync history and entry details. See
*Release notes 2.2.0* and *Upgrading from v2.1.1*.

Earlier: 2.1.1 enforced wildcard exclusion independently of Panorama, rejected over-long URLs/sources with 422 and
bounded the rate-limiter memory.

FastAPI + Postgres service that accepts URLs from approved hosts, de-duplicates them, drops
entries shadowed by a wildcard, excludes anything Panorama categorises as high risk, and
publishes a Palo Alto External Dynamic List (type: URL List). Everything operational is
managed from an admin Settings interface, with a matching admin API.

## Run

    cp .env.example .env     # set POSTGRES_PASSWORD, API_KEY, SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
    docker compose up -d --build

Put TLS in front (e.g. Caddy). If you reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy
address, otherwise every request appears to come from the proxy and host IP checks and rate
limits cannot work.

### Initial configuration

1. Open `https://<host>/admin` and sign in with `ADMIN_USER` / `ADMIN_PASSWORD`.
2. **Panorama Integration**: enter host, port, API key; press **Test connection**. The status
   indicator (top of the sidebar and on the page) shows connected / failed / not configured.
   No Panorama yet? Choose mode `mock` (see below).
3. **URL Classification**: review the high-risk categories (the available list is editable
   to match your Panorama) and the failure / unknown-category behaviour.
4. **EDL Configuration**: name, optional extra endpoint, entry limit, empty-list behaviour.
5. **Allowed hosts** (sidebar): add each submitting system; copy its token (shown once).
6. On PAN-OS: Objects > External Dynamic Lists > *URL List*, source
   `https://<host>/edl/<name>` (or your extra endpoint).

## Admin Settings interface (`/admin/settings`)

Six sections, each saved independently (Save / Cancel), with inline validation, success and
error notices, and a confirmation step for changes that could disrupt firewalls (disabling
publishing, lowering the entry limit, switching off classification, fail-open, changing the
EDL name/endpoint, changing high-risk categories, turning off host authentication ...).

| Section | Settings |
|---|---|
| General | app name, description, timezone, log level, audit logging, audit retention |
| Panorama Integration | mode (live/mock), host, port (443), API key (encrypted, masked, replace/clear), verify TLS, connection timeout, retry count, target, URL lookup command, Test connection |
| URL Classification | enable, cache TTL, failure behaviour (fail-open/closed), available + high-risk categories, reclassification interval, unknown-category behaviour (publish/exclude), **wildcard policy** (*Exclude* / *Classify Apex Domain*; stored values `exclude` / `apex-classification`) |
| EDL Configuration | enable publishing, name, description, additional endpoint (conflict-checked), max entries, empty behaviour (publish-empty / keep-previous / return-error), optional feed basic auth |
| Processing | enable background processing, interval, batch size, concurrency (1-5, default 5), HTTP timeout, retries, retry delay, **sync classification budget**; "Run now" / "Reclassify now" |
| Security and API | host authentication, IP restrictions, token expiry, max submission size, **max sync size**, rate limit, audit API submissions |

Three pages under **Lists** in the sidebar (v2.2.0): **Entries** (search; ownership, classification method/target/categories/time, suppression and the suppressing wildcard, last sync), **Wildcards** (policy, per-wildcard outcome, *Recheck wildcard classifications* button) and **Sync** (each source's last sync time, id, status and counts of added / removed / unchanged / blocked / suppressed / pending / errors, plus previous reports with per-entry detail). None of them shows host tokens or encrypted secrets.

Behaviour notes:

- Settings live in the database (`app_settings`, key/value with type, description, default),
  are cached in memory and the cache is refreshed on every change, no restart needed.
- **Precedence**: database > nothing else. Environment variables only *seed* settings that
  are missing when the app starts; they never overwrite saved values (so upgrades are safe).
- Secrets (Panorama API key, feed password) are encrypted with `ENCRYPTION_KEY`, shown as
  `********`, never logged, never returned by the API, and never written to the audit log.
- Bootstrap values (`DATABASE_URL`, `API_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY`, `ADMIN_*`)
  are environment-only; the page cannot edit its own credentials.
- Changing a Panorama connection setting clears the classification cache; changing
  classification / EDL settings rebuilds the feed; changing high-risk categories re-evaluates
  stored entries.
- **The feed is served from the last good snapshot.** If a rebuild fails, the previous list
  keeps being served. Feed format is plain text, one entry per line.
- With publishing disabled the feed answers `503`, which PAN-OS treats as "keep the list I
  already have".

## Admin API (`/v1/admin`, header `X-API-Key`)

The existing convention is `/v1`, so the admin API is `/v1/admin` rather than `/api/v1/admin`.
Host tokens are **not** accepted here.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/admin/settings` | all sections with values, defaults, descriptions (secrets masked) |
| PUT | `/v1/admin/settings` | update any settings: `{"values": {...}, "clear_secrets": [], "confirm": false}` |
| GET / PUT | `/v1/admin/settings/{section}` | one section (`general`, `panorama`, `classification`, `edl`, `processing`, `security`) |
| POST | `/v1/admin/panorama/test-connection` | test saved settings, or unsaved overrides `{"host","port","api_key","verify_tls","connect_timeout","mode"}`; 200 ok / 502 failed |
| GET | `/v1/admin/audit?kind=admin\|api&limit=&offset=` | audit records |
| GET | `/v1/admin/edl` | per list: published vs currently eligible entries, retained / failed-rebuild state |
| GET | `/v1/admin/wildcards?list=&limit=&offset=` | stored wildcards with apex target, result, categories, time, status and how many entries each suppresses; the active policy |
| POST | `/v1/admin/wildcards/recheck` | re-classify wildcards: `{"list": null, "refresh": true}` (apex domains de-duplicated, at most 5 requests in flight, nothing deleted) |
| GET | `/v1/admin/sync/sources` | each importer (list, host, source) and its latest sync outcome and counts |
| GET | `/v1/admin/sync/runs?list=&source=&limit=&offset=` | sync history |
| GET | `/v1/admin/sync/runs/{id}` | one stored sync report, with per-entry detail (capped) |
| GET | `/v1/admin/entries?list=&status=&q=&suppressed=&wildcard=` | entries with owners, classification and suppression details |
| POST | `/v1/admin/entries/enabled` | `{"list","values":[...],"enabled":false}`: keep an entry but never publish it |

`PUT` returns `422 {"detail":{"errors":[...]}}` for invalid values and `409` with
`requires_confirmation` for disruptive changes; repeat with `"confirm": true` to apply.

    curl -X PUT -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
      -d '{"values":{"max_batch_size":50}}' https://edl.example.net/v1/admin/settings/processing

## Allowed hosts and authentication

Each host has addresses (IPv4/IPv6/CIDR; `0.0.0.0/0` refused), a token (shown once, stored as
a SHA-256 hash, regenerable), permitted lists, an optional expiry, and an enabled switch.
A POST is accepted only with the host's bearer token **and** (if IP restrictions are on) from
one of its addresses. Per-host rate limiting returns `429` with `Retry-After`; oversize
submissions return `413`.

## API

Populate a list (per-host credentials):

    curl -H "Authorization: Bearer $HOST_TOKEN" -H 'Content-Type: application/json' \
      -d '{"urls":["example.com","*.example.com","1.example.com"],"source":"ticket-123"}' \
      https://edl.example.net/v1/lists/default/entries

Per-URL status: `added`, `duplicate`, `blocked`, `pending`, `invalid` (plus `published` /
`shadowed_by`). Errors: `401` bad/expired token, `403` wrong address or list, `413`, `429`.

Reconcile a whole data set from one source (see *Source sync* below):

    curl -H "Authorization: Bearer $HOST_TOKEN" -H 'Content-Type: application/json' \
      -d '{"source":"yaml-import","sync_id":"2026-11-06-001","delete_missing":true,"dry_run":false,
           "entries":["example.com","*.example.com",{"url":"tools.example.net/login","yaml_list":"tools"}]}' \
      https://edl.example.net/v1/lists/default/sync

Management calls (`X-API-Key`): `GET/DELETE /v1/lists/{name}/entries`,
`POST /v1/lists/{name}/recheck`. Feed: `GET /edl/{name}` (ETag / 304 supported). Health:
`GET /healthz`. `GET /v1/lists/{name}/entries` now also returns `enabled`, `suppressed_by`, `classification`
(method, target, result, categories, status, reason, time) and `owners` for each entry (`shadowed_by` is kept).

## Behaviour

- **Normalisation** (server side, authoritative, applied before validation, de-duplication, storage,
  classification, shadowing, sync comparison and feed generation): lowercased; scheme, credentials, port,
  query and fragment removed; domain roots end in a slash (see *URL normalisation*). Only a leading `*.`
  wildcard is accepted, and it must not target a public suffix (see *Public Suffix List* below).
- **De-duplication** on the normalised value, per list.
- **Shadowing / suppression**: an *approved* wildcard suppresses the entries it covers (see *Wildcard
  suppression*); `example.com/` and `*.example.com/` never shadow each other.
- **Classification**: entries are looked up on Panorama, cached for the TTL, and compared with
  the high-risk set. Wildcards are governed by the wildcard policy (see *Wildcard entries*). Statuses: `active`, `blocked`, `pending`
  (fail-closed, held back), `unverified` (fail-open, published, re-checked later). A re-check
  that cannot reach Panorama **never demotes** an entry that was classified earlier: its status
  is kept and a warning is logged, so an outage cannot empty the feed.
- **Background processing** retries pending/unverified entries in batches, runs scheduled
  reclassification, and purges old audit records. With it disabled, nothing runs
  automatically; the "Run now" buttons still work.

## Database migrations

No Alembic. At startup `migrations.run_migrations` runs `create_all` (adds missing tables) and
applies additive `ALTER TABLE ... ADD COLUMN` steps: `allowed_hosts.expires_at` (v2.0.0),
`edl_snapshots.retained`, `edl_snapshots.note` (v2.1.0) and, in v2.2.0, `entries.enabled`, `entries.suppressed_by`,
`entries.class_method`, `entries.class_target`, `entries.class_result`, `entries.class_categories`,
`entries.class_status`, all nullable. v2.2.0 also creates the tables `entry_sources`, `sync_sources` and `sync_runs`
and runs one idempotent data upgrade in a single transaction (see *Upgrading from v2.1.1*). Existing data and existing settings are
preserved; only missing settings are seeded. Secrets stored by v1 (encrypted with a key derived
from `SECRET_KEY`) are still readable and are re-encrypted with `ENCRYPTION_KEY` on first start.
Back up the database before upgrading anyway.

## Environment variables

Required: `API_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY` (at least 16 characters), `ADMIN_PASSWORD`, `DATABASE_URL`
(set by compose). Optional: `ADMIN_USER`, `ADMIN_COOKIE_SECURE`, `FORWARDED_ALLOW_IPS`, `ENCRYPTION_KEY_PREVIOUS` (rotation only).
First-start seed values for editable settings are listed in `.env.example`
(old names such as `BLOCKED_CATEGORIES` and `CATEGORY_CHECK_ENABLED` still work as seeds).

### Docker secrets

Any of `API_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY`, `ENCRYPTION_KEY_PREVIOUS`, `ADMIN_PASSWORD`, `DATABASE_URL`,
`PANORAMA_API_KEY`, `EDL_PASSWORD` may be given as `<NAME>_FILE=/run/secrets/<file>`:

    services:
      app:
        environment:
          ENCRYPTION_KEY_FILE: /run/secrets/edl_encryption_key
        secrets: [edl_encryption_key]
    secrets:
      edl_encryption_key:
        file: ./secrets/encryption_key

## Public Suffix List

Wildcards are validated against the [Public Suffix List](https://publicsuffix.org) using the
maintained `publicsuffixlist` package, which ships a dated snapshot (nothing is downloaded at
runtime). A wildcard whose base is itself a public suffix is rejected with status `invalid`:

| Rejected | Accepted |
|---|---|
| `*.com`, `*.net`, `*.co.uk`, `*.com.au`, `*.github.io`, `*.internal` | `*.example.com`, `*.example.com.au`, `*.sub.example.com` |

Both the ICANN and the private sections of the list count (a wildcard over `github.io` or
`blogspot.com` would cover thousands of unrelated owners), and unlisted top-level names are
treated as suffixes, as the PSL specifies. Non-wildcard entries are not restricted. The list is
refreshed by upgrading the package (`pip install -U publicsuffixlist` / rebuild the image);
`app.psl.version()` reports the snapshot in use.

Shadowing is unchanged: `1.example.com` and `*.sub.example.com` are shadowed by
`*.example.com`; `example.com` is not; `a.example.com` and `b.example.com` do not shadow each
other. Entries already stored by an older version that wildcard a public suffix (e.g. `*.com`)
are kept in the database but set to `blocked` at startup, so they are never published and cannot
shadow other entries.

## Wildcard entries and classification: limitations

Panorama categorises **individual URLs**. It cannot answer "is everything under
`*.example.com` safe?". The category of `example.com` says nothing reliable about
`a.example.com`, `mail.example.com`, or a subdomain created tomorrow. The app therefore never
treats an apex classification as proof about subdomains.

Setting *URL Classification > Wildcard entries* (`wildcard_classification_policy`):

| Policy (UI label) | Stored value | Behaviour |
|---|---|---|
| **Exclude** (**default for new installs**) | `exclude` | Wildcard entries are kept but never published. They are stored as `blocked` with the reason "wildcard excluded by policy" (classification status `excluded`); no Panorama lookup is made for them. |
| **Classify Apex Domain** | `apex-classification` | The wildcard is reduced to its apex (`*.example.com/` -> `example.com`, `*.sub.example.com/` -> `sub.example.com`), which is submitted to Panorama. **The literal wildcard is never submitted.** Clean and not high-risk -> approved (published, and it then suppresses the subdomains it covers). High-risk category -> blocked. Panorama unavailable, timing out, returning an unparseable answer or an *unknown* category -> **pending** (not published) whatever the failure and unknown-category settings say: an inconclusive result is never approval. |

An existing installation keeps the policy it has stored; only a missing setting is seeded with `exclude`.

**Apex classification is an explicit policy decision, not evidence.** Classifying `example.com` does **not**
prove that every subdomain is safe: Panorama categorises individual URLs, and `example.com` can be clean
while `a.example.com` hosts malware, or while a subdomain created tomorrow does. Choose *Classify Apex
Domain* only if you accept that risk; every place that shows such a wildcard says its subdomains are not
verified. A wildcard approved on its apex also suppresses (see below) a subdomain entry that was individually
blocked, so the individually blocked subdomain disappears from the feed only because the wildcard already
covers it - it is **not** being protected by that block. Keep that in mind before approving a wildcard whose
subdomains you have reason to distrust.

**Metadata stored on every classified entry** (admin *Entries* page, `GET /v1/lists/{name}/entries`,
`GET /v1/admin/entries`): the original entry (for a wildcard, the wildcard itself), `class_target` (what was
actually submitted - the apex), `class_method` (`url` or `wildcard_apex`), `class_result`
(`clean` / `blocked` / `unknown` / `error` / `excluded` / `not_classified`), `class_categories`, `class_status`
(`approved` / `blocked` / `pending` / `excluded` / `unverified`), the reason (`detail`) and the time of the last
attempt (`checked_at`). Wildcards stored by v2.1.1 have no metadata until they are next classified (run
*Recheck wildcard classifications*).

**Efficiency.** Identical apex domains are looked up once (a thousand `*.example.com/...` entries cost one
request), cached answers are reused for the cache TTL (including answers cached for the same host by an
ordinary `example.com/` entry), and every lookup goes through the process-wide limit of 5 concurrent
Panorama requests.

**Changing the policy** takes effect immediately for stored entries and requires confirmation. Nothing is
deleted: `exclude` -> `apex-classification` releases excluded wildcards to *pending* and the background engine
classifies their apex domains; `apex-classification` -> `exclude` re-statuses published and pending wildcards to
`blocked`/`excluded` and the subdomains they suppressed return to the feed. Wildcards blocked on a high-risk
apex stay blocked until the next recheck. *Wildcards > Recheck wildcard classifications* (or
`POST /v1/admin/wildcards/recheck`) re-evaluates every wildcard, including blocked ones, ignoring the cache. If
Panorama is unreachable during a recheck, wildcards that were already classified keep their status.

**Wildcards and Panorama availability.** Under `apex-classification`, a wildcard needs a successful apex
classification to be published. With classification **disabled**, a wildcard stays *pending* (a warning is
shown on the Overview page); v2.1.1 published it. With policy `exclude` a wildcard is never published, with
classification enabled or not.

## Wildcard suppression

Matching is on whole domain labels: for each entry the matcher looks up its own label suffixes
(`a.b.example.com/` -> `*.b.example.com/`, `*.example.com/`, ...) in the set of approved wildcards, so it is
exact and costs O(entries x labels) - no pairwise comparison, which matters at 60,000 entries.

| Approved wildcard | Suppresses | Does not suppress |
|---|---|---|
| `*.example.com/` | `www.example.com/`, `mail.example.com/`, `a.b.example.com/`, `www.example.com/anything` | `example.com/`, `example.com.au/`, `example.com.evil.net/`, `notexample.com/` |
| `*.sub.example.com/` | `www.sub.example.com/` | `www.example.com/`, `sub.example.com/` |
| `*.example.com/login` | `a.example.com/login` | `a.example.com/other`, `a.example.com/login/` |

- Only **approved** wildcards suppress. A pending, failed, excluded, blocked or disabled wildcard does not.
- Suppression is within one list.
- A suppressed row is **never deleted**. It keeps its owners and records the wildcard in `suppressed_by`
  (shown in the admin UI and API). When the wildcard is removed, blocked, disabled or goes back to pending, the
  row is released automatically and published again **subject to its own classification**.

## URL normalisation

| Input | Canonical value |
|---|---|
| `example.com`, `https://example.com`, `http://example.com`, `example.com/` | `example.com/` |
| `www.example.com` | `www.example.com/` |
| `*.example.com` | `*.example.com/` |
| `example.com/login` | `example.com/login` |
| `example.com/login/` | `example.com/login/` |
| `https://Example.com/login?next=/x#top` | `example.com/login` |

Domain roots always get the slash; path-specific entries are **not** given one, and an existing trailing slash
on a path is kept, so `example.com/login` and `example.com/login/` are different entries (they are not treated
as identical automatically). Query strings and fragments are still stripped, as before, so
`example.com/a?x=1` and `example.com/a` are the same entry. Panorama is asked about the host
(`example.com`) or the path (`example.com/login/`), never about the slash-only form of a root.

## Source sync (`POST /v1/lists/{name}/sync`)

The importer describes the **desired state** of one *source*; the server computes the changes. A source is the
pair (authenticated host, `source` string); ownership, removals and history are per source.

    {"source": "yaml-import", "sync_id": "2026-11-06-001", "delete_missing": true, "dry_run": false,
     "entries": ["example.com", {"url": "*.example.com", "yaml_list": "partners"}]}

| Field | Meaning |
|---|---|
| `source` | 1-100 characters; `host:source` must fit 128 characters. |
| `sync_id` | 1-128 characters `[A-Za-z0-9._:@/+=-]`, unique per run. A repeated, already-applied `sync_id` returns the stored report (`"duplicate": true`) and does nothing; the same id with different content is `409`. |
| `entries` | strings, or `{"url", "yaml_list"}` (the importer's list name, tracked per entry). At most `max_sync_size`. |
| `delete_missing` | remove entries this source owns that are no longer listed. Default `false`: nothing is ever removed. |
| `confirm_empty` | required, with `delete_missing`, when `entries` is empty. |
| `dry_run` | validate and report; **no** database, feed, audit or Panorama activity. |
| `verbose` | include unchanged entries in the per-entry detail. |

Authentication is the host's bearer token plus its list permission and IP restriction, exactly as for
`/entries` (the management API key is not accepted). Pipeline: authenticate -> authorise list -> validate and
normalise -> identify owned entries -> compute add / remove / unchanged -> find entries needing
(re)classification -> classify (cache first, bounded live lookups) -> apex classification of wildcards ->
suppression -> one transaction that writes entries and ownership, recomputes suppression, replaces the feed
snapshot, records the run and the audit trail -> report. A failure at any stage rolls the whole thing back;
the database and the published feed are exactly as before.

**Safety rules (enforced, tested):**

- Only entries owned by *this host and source* are ever removed, and only with `delete_missing=true`. Entries
  of other sources or hosts and entries from `POST .../entries` (owners of kind `api`) are never removed by a
  sync; a sync adds itself as an additional owner, and an entry is deleted only when its **last** owner lets go.
- `delete_missing` with any **invalid** entry in the request is refused (`422`, nothing changed): a damaged
  import never deletes. Without `delete_missing`, invalid entries are reported and the valid ones applied.
- An empty `entries` with `delete_missing` needs `confirm_empty=true`.
- If classification **fails** during a run (Panorama errors), removals are *deferred*: new entries are stored
  as `pending` (never published), the report says `removals_deferred`, and repeating the sync once Panorama is
  back applies them.
- A Panorama outage, timeout or inconclusive answer is never approval. Unclassified wildcards are never
  published when the policy requires classification.
- Classification budget: one request makes at most `sync_classification_budget` (default 2000) distinct live
  Panorama lookups, for entries **new** to the list. The rest are stored `pending` and the background engine
  classifies them (reported as `queued_for_background`), so a first import of tens of thousands of entries
  cannot hold a request open for hours. Existing pending entries are only completed from the cache by a sync;
  retrying them is the engine's job, which is also why repeating an identical sync sends nothing to Panorama.
- Syncs of one list (and legacy submissions to it) are serialised by a per-list lock.

**Idempotency.** Repeating an identical sync with a new `sync_id` changes no entry, ownership or snapshot row,
sends nothing to Panorama and does not regenerate the feed (status `no_change`); only the run record,
source status and audit record are written. The per-entry `last_seen_at` / `last_sync_id` on an ownership row
are updated when that row is created or changed, not on every confirming sync; the source-level last sync is in
`sync_sources`.

**Report** (also stored, see the *Sync* page): `counts` with `total_desired`, `existing`, `new`, `unchanged`,
`ownership_added`, `yaml_list_changed`, `removed`, `entries_deleted`, `kept_other_owners`, `missing_not_removed`,
`blocked_by_policy`, `blocked_by_classification`, `pending_classification`, `queued_for_background`,
`approved_by_apex_classification`, `suppressed_by_shadowing`, `requiring_reclassification`, `invalid`,
`processing_errors`, `live_lookups`, `published_of_desired`; `feed` (entries before / after, added, removed);
`entries` (per entry: action, status, published, suppressed_by, reason, classification and its source - capped
at 2000, with `entries_truncated`); `invalid`; `warning`. HTTP: `200`, `401/403`, `409` (sync_id reuse with
different content, or a conflicting concurrent change - retry), `413`, `422`, `429`, `500` (rolled back,
retry with the same `sync_id`), `503` (another sync of the list is still running).

**Dry run.** `dry_run=true` computes additions, removals, duplicates, suppression, classification changes and
the proposed effective feed (`feed.entries_after` ...) without writing. It never contacts Panorama: each entry
that needs classification is reported as `cached` (projected from the cache), `requires_live` (would be
looked up; projected as pending) or `not_required`; `classification_needed` totals them.

**Rollback** is a sync of the previous desired state with a new `sync_id`
(`delete_missing=true`): the importer's data set is the source of truth, so keep it in version control.
Entries removed in error are recreated and re-classified (from the cache when still fresh).

Example workflow:

    # 1. preview
    curl ... -d '{"source":"yaml-import","sync_id":"2026-11-06-001","entries":[...],"delete_missing":true,"dry_run":true}'
    # 2. apply (same body, dry_run false; the same sync_id is fine for the real run)
    curl ... -d '{"source":"yaml-import","sync_id":"2026-11-06-001","entries":[...],"delete_missing":true}'
    # 3. a lost response? repeat step 2 verbatim: you get the stored report, nothing is applied twice
    # 4. roll back: send the previous entries with sync_id "2026-11-06-002-rollback"

## Stored entries versus the effective published EDL

The database stores **source entries** (everything every source and `POST .../entries` asked for, with ownership,
classification and suppression). The feed firewalls fetch contains only the **effective** entries: validated,
approved (`active`, or `unverified` under fail-open), `enabled`, **not suppressed** by an approved wildcard,
within `edl_max_entries` (oldest kept), de-duplicated and sorted, one per line, with canonical slashes. Identical
data always produces identical bytes and the same ETag; the stored snapshot is only replaced when the effective
output changes (`Last-Modified` and ETag do not move otherwise).

## Panorama concurrency

Palo Alto Networks recommends limiting concurrent XML API requests to about five. *Maximum
concurrent requests* defaults to **5** and cannot be set higher (the API and UI reject larger
values; an older stored or environment value above 5 is clamped to 5 on upgrade). The limit is
enforced inside the Panorama client, process-wide, so it holds across API submissions, background
processing, rechecks and connection tests running at the same time. Lower values (1-4) work too.

## Panorama response parsing

Lookup replies are parsed, not text-searched: the XML envelope must be a well-formed
`<response>` with `status="success"` and a `<result>`; API errors, malformed XML, DTD/entity
declarations and unexpected structures raise an error and the entry is treated as a failed
lookup (held back or kept as-is per the failure policy), never as "no categories". Categories are
taken only from lines of the form `<queried url> <category> [<category> ...] (<database>)` that
begin with the URL actually asked about, lower-cased and compared exactly, so a hostname such as
`malware.example.com`, or an error message that mentions a category, cannot create a match.
Structured `<category>`/`<member>` elements are accepted too.

The lookup command stays configurable (*URL lookup command*, default `<test><url>{url}</url></test>`).
**The default and the response format have not been verified against a real Panorama/PAN-OS**; the
parser is tested against representative replies and mocked HTTP only. Test on your own Panorama
(Panorama page > Test connection, then submit a known URL) before relying on it.

## Encryption key (`ENCRYPTION_KEY`)

Secrets saved in the admin interface (Panorama API key, feed password) are encrypted with a key
derived from `ENCRYPTION_KEY` (Fernet, SHA-256 of the value).

- **It must be identical on every start.** Keep it in a Docker secret or your password manager and
  **back it up separately from the database backup**: a database backup is useless for secrets
  without it.
- It must be at least 16 characters. The app refuses to start, with instructions, if it is missing or
  too short. Generate one: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- A secret that cannot be decrypted is **never overwritten, re-encrypted or removed**. It is treated
  as unset, logged by name only, shown as "unreadable" in the API/UI, flagged on every admin page and
  by `/healthz` (`"secrets": "unreadable"`). Environment values do not silently stand in for it.
- Secrets never appear in logs, API responses, the audit log or HTML, in encrypted or decrypted form.

Check status at any time: `docker compose exec app python -m app.keytool status`.

### Lost key: recovery

If the key is truly lost the secrets cannot be recovered (by design). Procedure:

1. Set a **new** `ENCRYPTION_KEY` and restart. The app starts; unreadable secrets are flagged.
2. Re-enter the Panorama API key (Panorama page) and any feed password (EDL page). Entering a value is
   the only action that replaces an unreadable secret; the audit log records the settings change
   (never the value).
3. Verify with `python -m app.keytool status` and `/healthz`. Take a fresh backup of the new key.

If you only *suspect* the wrong key was loaded, restore the original and restart: nothing was changed,
so everything works again.

### Key rotation

Rotation keeps existing credentials usable throughout:

1. Generate the new key. Set `ENCRYPTION_KEY=<new>` and `ENCRYPTION_KEY_PREVIOUS=<old>` (or the
   `_FILE` variants). Restart.
2. On startup every secret readable with the previous key is re-encrypted with the new one.
   Until then secrets stay readable (the previous key is tried automatically).
3. Verify: `docker compose exec app python -m app.keytool status` shows `current-key` for every secret
   (if any show `older-key`, run `python -m app.keytool reencrypt`). The admin pages show a notice
   while `ENCRYPTION_KEY_PREVIOUS` is set.
4. Remove `ENCRYPTION_KEY_PREVIOUS`, restart, and back up the new key.

Do **not** just replace `ENCRYPTION_KEY`: that makes existing secrets unreadable until the old key is
supplied as `ENCRYPTION_KEY_PREVIOUS`. (Secrets stored by v1, encrypted from `SECRET_KEY`, are also
still readable and are migrated the same way.)

## EDL snapshots and empty-list behaviour

Feeds are served from the **last good snapshot** (table `edl_snapshots`), not computed per request.
A snapshot is built completely in memory and then replaced in a single database transaction; if
anything fails (including a failed commit), the previous snapshot is untouched and keeps being served,
and the failure is shown to administrators. Rebuilds are serialised. A Panorama outage during
processing cannot shrink the list (see *Behaviour*).

When no eligible entries remain (*EDL > Empty list behaviour*):

| Setting | Feed |
|---|---|
| `publish-empty` (default) | HTTP 200 with an empty body. Firewalls empty their list. |
| `keep-previous` | The previous non-empty list keeps being served. **This is flagged**: the snapshot is marked "retained" with a note, a warning appears on the Overview and EDL pages, and `GET /v1/admin/edl` reports `retained: true`. It clears automatically when valid entries return. |
| `return-error` | HTTP 503 ("no valid entries"); PAN-OS keeps the list it already has. |

Publishing disabled also returns 503. The EDL page and `GET /v1/admin/edl` show, per list, the number
published vs currently eligible, which entries differ, whether the previous list is retained, and
whether the last rebuild failed.

## Production authentication recommendations

- Keep **host authentication enabled** (default). Disabling it shows a red warning on every admin
  page; use it only on a closed test network.
- Keep **IP restrictions on** and give each host the narrowest addresses/CIDRs; issue one token per
  submitting system, set expiry (*Token expiry*), and rotate tokens when staff or systems change.
- Management (`API_KEY`), host tokens and the admin password are separate: a host token cannot call
  `/v1/admin` or the management endpoints, and `API_KEY` is not accepted as a host token.
- Put TLS in front (Caddy etc.). Set `FORWARDED_ALLOW_IPS` to **only** the reverse proxy's address.
  Source addresses come from the TCP peer, or from `X-Forwarded-For` only when the peer is listed
  there; the app never reads forwarding headers itself. **Never use `*`**: any client could then claim
  any address and bypass IP restrictions (the admin pages and logs warn if you do).
- Run a **single worker** (the default image). Rate limits, confirmations and the processing engine are
  per process; more workers (`WEB_CONCURRENCY` > 1) make them incorrect, and the app warns.
- Repeated failed host authentication from one address (20/minute) is answered with 429.
- Use Docker secrets (`*_FILE`) for `API_KEY`, `SECRET_KEY`, `ENCRYPTION_KEY`, `ADMIN_PASSWORD`.

## Input limits (2.1.1)

| Field | Limit | Behaviour |
|---|---|---|
| Entry (after normalisation) | 2048 characters | HTTP 422 for the **whole request**, `{"detail": {"errors": ["urls[1]: entry is 2049 characters after normalisation; the maximum is 2048"]}}`. Nothing is stored and Panorama is not queried; every offending index is listed. Never truncated. |
| Raw URL string in a request | 65,536 characters | HTTP 422 (schema). |
| Source (`<host name>:<source>`) | 128 characters | HTTP 422 if the final combined string is longer (host names are up to 64 characters, the supplied `source` up to 100). Never truncated; nothing stored. |
| URLs per request | `max_submission_size` setting | HTTP 413. |
| Entries per sync request | `max_sync_size` setting (default 100,000) | HTTP 413. Invalid sync entries are reported per entry; over-long ones (>2048 after normalisation) are `invalid`, never truncated. |

The length is measured on the normalised value, so a long query string or fragment that normalisation
strips does not count. Other invalid entries (malformed host, wildcard over a public suffix ...) are still
reported per URL as `invalid` in a normal 200 response, as before. The same length check applies to
`DELETE /v1/lists/{name}/entries`.

## Rate-limit and login-failure tracking (2.1.1)

Host rate limits, failed host authentication (20 per minute per source) and failed admin logins (5 per
5 minutes per source) share one in-memory sliding-window tracker. A source's entry is deleted as soon as
its window expires (empty entries are never kept), a sweep of all entries runs opportunistically inside
normal calls (at most every 30 seconds, no background task), and all of this happens under the same lock
as enforcement, so cleanup can neither race with a decision nor shorten an active window. The table is
bounded at 50,000 live sources (least recently active are dropped beyond that), and an IPv6 client is
tracked per /64 so one subscriber cannot create unlimited identities. Remaining limits: state is per
process and lost on restart (run one worker), and it only sees the address uvicorn reports (see
*Production authentication recommendations*).

## Release notes 2.2.0

- **New:** wildcard classification through the apex domain (policy *Classify Apex Domain*), with metadata, caching,
  de-duplicated lookups under the 5-request limit, fail-closed handling and an admin recheck.
- **New:** `POST /v1/lists/{name}/sync` - idempotent, multi-source reconciliation with dry run, `sync_id` recovery,
  atomic apply, audit and reports; tables `entry_sources`, `sync_sources`, `sync_runs`.
- **New:** persistent wildcard suppression (`entries.suppressed_by`); only approved wildcards suppress; nothing deleted.
- **Changed:** canonical entries for domain roots end in `/` (`example.com/`). The **published feed changes**
  (every root line gains a slash) and the ETag changes once at the first start. Path entries keep their form.
- **Changed (behaviour):** under `apex-classification` with classification disabled, wildcards are *pending*
  (v2.1.1 published them); under `apex-classification`, a wildcard whose apex lookup fails or is inconclusive is
  *pending* even in fail-open mode (previously `unverified`, i.e. published).
- **Changed:** wildcard apex lookups submit the apex host only (v2.1.1 also appended a path for `*.example.com/path`).
- **Fixed:** Panorama answers for URLs with a trailing slash on the path were not recognised.
- **New settings:** `max_sync_size`, `sync_classification_budget`. New admin pages and endpoints (see above).
- No new dependencies or environment variables.

## Upgrading from v2.1.1

1. Back up the database (and keep your `ENCRYPTION_KEY`). No new environment variables or dependencies.
2. `docker compose up -d --build`. At first start the app, in one transaction: adds the new `entries` columns and the
   three new tables; sets `entries.enabled`; appends `/` to every **domain-root** entry (`example.com` ->
   `example.com/`, `*.example.com` -> `*.example.com/`; path entries such as `example.com/login` are not rewritten;
   a root that already has a slashed twin is merged keeping the more restrictive status and all owners); records an
   `api` owner for each existing entry (host and note taken from its source string, `legacy` when none); writes a
   `schema-upgrade` audit record; then recomputes suppression and rebuilds every feed. Statuses, reasons, cached
   classifications, hosts, tokens, settings, audit history and list configuration are untouched.
3. **Expect the feed to change once:** every root line gains a slash, and the ETag changes. This is the form
   v2.2.0 is specified to publish; it has not been tested against a firewall here, so confirm on a test firewall
   how your PAN-OS version matches `example.com/` before production. The previous snapshots are replaced by the
   rebuilt ones.
4. The wildcard policy you had stored is kept. If it is `apex-classification` with classification disabled,
   wildcards become *pending* and leave the feed (a warning explains it). Wildcards stored by v2.1.1 have no
   classification metadata until *Recheck wildcard classifications* is run.
5. Check `docker compose logs app` (`schema:` lines), `/healthz` (`"version":"2.2.0"`), the Overview page, then
   *Wildcards*, *Sync* and *Entries*. Run a `dry_run` sync from your importer before the first real one.
6. Rollback: restore the backup. (v2.1.1 would otherwise read the new database, but it would not understand the
   trailing slashes in `entries.value` or the new columns/tables, so do not run it on a migrated database.)

## Release notes 2.1.1

- **Fixed (security):** with policy `exclude` and Panorama classification disabled, wildcard entries were
  marked active and published, and rechecks revived blocked wildcards.
- **Fixed:** entries over 2048 characters and source strings over 128 characters were not validated
  (database error or silent loss on PostgreSQL); they are now rejected with 422 before any write.
- **Fixed:** rate-limiter and admin-login tracking leaked memory (empty entries were never removed).
- Version reported by OpenAPI, `/healthz` and this document is 2.1.1. No schema or dependency changes.

## Upgrading from v2.1.0

1. Back up the database (and keep your `ENCRYPTION_KEY`).
2. Pull the new code and `docker compose up -d --build`. There are no new dependencies, environment
   variables or schema changes; volumes are untouched.
3. At startup, stored wildcard entries that the `exclude` policy forbids but that v2.1.0 published
   (only possible with classification disabled) are set to `blocked` and leave the feed; rows are kept.
   Check the Overview page. To publish wildcards deliberately, choose `apex-classification`.
4. Clients that sent entries over 2048 characters or source strings over 128 characters will now get
   422 where they previously (on SQLite) stored them or (on PostgreSQL) got a server error.
5. Rollback: re-deploy the v2.1.0 image; nothing in the database needs reverting (re-run a recheck if you
   want blocked wildcards re-evaluated).

## Upgrading from v2.0.0

1. Back up the database **and** your `ENCRYPTION_KEY`.
2. Pull the new code and `docker compose up -d --build` (new dependency `publicsuffixlist` is installed
   in the image build). No manual migration: at startup the app adds `edl_snapshots.retained` and
   `edl_snapshots.note`, seeds the new `wildcard_classification_policy` setting, clamps a stored
   `max_concurrent_requests` above 5 to 5, and sets any stored wildcard that targets a public suffix to
   `blocked`. No rows are deleted and existing setting values are untouched.
3. **Behaviour change to expect:** the default wildcard policy is `exclude`, so stored wildcard entries
   (`*.example.com`) are set to `blocked` and **drop out of the published feed** at first start. If you
   rely on them, review the risk (above) and choose `apex-classification` under URL Classification; they
   are re-queued and re-published after their base domain is classified. Check the Overview page first.
4. Check `docker compose logs app` for `upgrade:` / `wildcard reconciliation` lines, `/healthz`, and the
   admin Overview (EDL status, warnings).
5. Rolling back: the new columns are nullable and ignored by v2.0.0; entries re-statused to `blocked` can
   be set back to `active` by switching the wildcard policy and rechecking, or by restoring the backup.

## Develop without Panorama

Choose mode `mock` on the Panorama page (or `PANORAMA_MODE=mock` for the first start).
A host label `cat-<category>` assigns that category (`cat-malware.example.com` is blocked);
`cat-error` simulates Panorama being down; an optional JSON rules file can map hosts to
categories. Run locally with SQLite:

    pip install -r requirements.txt
    API_KEY=dev SECRET_KEY=dev-secret-key ENCRYPTION_KEY=dev-encryption-key-123 ADMIN_PASSWORD=dev ADMIN_COOKIE_SECURE=false \
      PANORAMA_MODE=mock uvicorn app.main:app --reload

## Verify before production

**Panorama integration has not been tested against a real Panorama.** The URL lookup op command
(*URL lookup command*, default `<test><url>{url}</url></test>`) and the reply format are unverified and
vary by PAN-OS version; the connection test uses `show system info`. Verify both on your Panorama.

## Known limits

- Run a **single worker**: the rate limiter, pending-confirmation store, settings cache and
  background loop are per process.
- Host checks are by IP/CIDR, not DNS name.
- Disruptive-change confirmations are held in memory for a few minutes (lost on restart).
- Wildcard subdomains cannot be classified (see above); `apex-classification` is an accepted-risk option, and an approved wildcard also covers an individually blocked subdomain in the same list.
- A sync request is synchronous: live classification per request is bounded by `sync_classification_budget`; very large first imports finish through background processing.
- `last_seen_at` on an ownership row is not touched by identical syncs (to keep them write-free); use the source-level last sync.
- Verified on SQLite and on PostgreSQL 16 in development; **not verified**: a Docker image build, Docker Compose runtime, or a real Panorama.
- Environment variables above 5 for concurrency are clamped, not rejected, on first start.
- Rate-limit and login-failure state is per process and lost on restart.

## Tests

    pip install -r requirements.txt pytest && pytest

The v2.2.0 suites are `tests/test_v220_*.py` (normalisation and upgrade, wildcard classification and
suppression, sync, admin pages/API, integration with a mocked Panorama and a real FastAPI client asserting
the published feed, and a 60,000-entry scale test). Existing tests were kept; where they asserted feed lines
or stored values for domain roots, the expected value now carries the trailing slash, and three tests that
asserted the v2.1.1 behaviour "apex policy with classification disabled publishes wildcards" now assert the
v2.2.0 behaviour (pending).
