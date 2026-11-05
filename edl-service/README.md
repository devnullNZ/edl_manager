# EDL Publisher — release 2.1.1

**Version 2.1.1** (corrective release on 2.1.0): wildcard exclusion is now enforced even when Panorama
classification is disabled; over-long URLs and source strings are rejected with HTTP 422; rate-limiter
and login-failure tracking no longer grow without bound. See *Release notes 2.1.1* and
*Upgrading from v2.1.0*.

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
| URL Classification | enable, cache TTL, failure behaviour (fail-open/closed), available + high-risk categories, reclassification interval, unknown-category behaviour (publish/exclude), **wildcard policy** (exclude / apex-classification) |
| EDL Configuration | enable publishing, name, description, additional endpoint (conflict-checked), max entries, empty behaviour (publish-empty / keep-previous / return-error), optional feed basic auth |
| Processing | enable background processing, interval, batch size, concurrency (1-5, default 5), HTTP timeout, retries, retry delay; "Run now" / "Reclassify now" |
| Security and API | host authentication, IP restrictions, token expiry, max submission size, rate limit, audit API submissions |

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

Management calls (`X-API-Key`): `GET/DELETE /v1/lists/{name}/entries`,
`POST /v1/lists/{name}/recheck`. Feed: `GET /edl/{name}` (ETag / 304 supported). Health:
`GET /healthz`.

## Behaviour

- **Normalisation**: lowercased; scheme, credentials, port, query, fragment, trailing slash
  removed. Only a leading `*.` wildcard is accepted, and it must not target a public suffix
  (see *Public Suffix List* below).
- **De-duplication** on the normalised value, per list.
- **Shadowing** is computed at render time: `*.example.com` shadows `a.example.com` and
  `a.b.example.com`; `example.com` and `*.example.com` never shadow each other.
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
applies additive `ALTER TABLE ... ADD COLUMN` steps: `allowed_hosts.expires_at` (v2.0.0) and
`edl_snapshots.retained`, `edl_snapshots.note` (v2.1.0), all nullable. Existing data and existing settings are
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

| Policy | Behaviour |
|---|---|
| `exclude` (**default**, conservative) | Wildcard entries are never published. They are stored as `blocked` with the reason "wildcard excluded by policy"; no Panorama lookup is made for them. |
| `apex-classification` | Only the base domain is classified (`*.example.com` -> `example.com`). If it is clean and not high-risk, the wildcard is published, and its entry detail says "only the base domain was classified; the category of subdomains is NOT verified". Use only if you accept that risk. |

Ordinary hosts and URLs (`www.example.com`, `example.com/path`) are classified exactly as before,
and `example.com` and `*.example.com` can both be listed. Changing the policy takes effect
immediately for stored entries (rows are re-statused, nothing is deleted) and requires
confirmation.

**Wildcard exclusion does not depend on Panorama.** It is a publishing policy, enforced whether or not
classification is enabled, for new submissions, for rechecks/reclassification, and when the policy is
changed. With policy `exclude`, a wildcard can never become `active`/`unverified`, so it is never in an
EDL snapshot, even with classification switched off (in v2.1.0 it could be; fixed in 2.1.1). With
classification disabled, ordinary hosts and URLs are still all published without any Panorama query, and
under `apex-classification` wildcards are published too (nothing is classified, and the entry says so).

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
- Wildcard subdomains cannot be classified (see above); `apex-classification` is an accepted-risk option.
- Environment variables above 5 for concurrency are clamped, not rejected, on first start.
- Rate-limit and login-failure state is per process and lost on restart.

## Tests

    pip install -r requirements.txt pytest && pytest
