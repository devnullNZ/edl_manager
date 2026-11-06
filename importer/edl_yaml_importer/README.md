# EDL Publisher YAML importer

Imports Palo Alto-style YAML URL lists into EDL Publisher through its host submission API.

## Expected YAML structure

```yaml
---
url:
  - name: example
    description: sample list
    type: URL List
    list:
      member:
        - "*.example.com"
        - example.com
```

Multiple `url` blocks and YAML documents separated by `---` are supported.

## How list names are handled

By default, each YAML `url[].name` becomes an EDL Publisher list name. This preserves membership and allows the same URL to exist in more than one EDL. The application de-duplicates within each EDL list.

If you want every URL in one EDL, use `--target-list default`. The YAML list names are still counted in the pre-import report, but the destination is consolidated.

EDL Publisher list names must match `[A-Za-z0-9_-]{1,64}`. The importer automatically replaces each run of whitespace in a YAML list name with a single underscore (for example, `Threat Feeds APAC` becomes `Threat_Feeds_APAC`). If two distinct YAML names would become the same destination name (for example, `Threat Feeds` and `Threat_Feeds`), the importer stops and reports the collision rather than silently combining them. The submitting host must be permitted to write to every destination list. A host configured with permitted lists `*` can write to all lists. IP restrictions must also permit the machine running the importer.

## Install

Python 3.10+:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure

```bash
export EDL_BASE_URL="https://edl.example.net"
export EDL_HOST_TOKEN="edl_your-host-token"
```

The token is the per-host bearer token shown when the allowed host is created. Do not use the management `API_KEY`; it is not accepted by the submission endpoint.

## Preview first

```bash
python import_edl.py urls.yaml --dry-run
```

The preview reports counts by list, local duplicates and canonical overlaps between lists. Cross-list overlaps are deliberately retained because each list is a separate EDL.

## Import

```bash
python import_edl.py urls.yaml
```

Defaults to batches of 500. Ensure the application's **Maximum Submission Size** setting is at least this value, or lower `--batch-size`:

```bash
python import_edl.py urls.yaml --batch-size 200
```

The importer uses `POST /v1/lists/{list_name}/entries`, `Authorization: Bearer ...`, and a JSON body containing `urls` and `source`. The default source label is `yaml-import`; the app records it with the host identity.

## Resume

A checkpoint file named `<yaml-file>.import-state.json` is created. If the process stops, resume with:

```bash
python import_edl.py urls.yaml --resume
```

The checkpoint is bound to the YAML file hash, application URL, target-list setting, source label and batch size. Keep those unchanged when resuming. Successful batches are skipped. If the server accepted a batch but the client stopped before checkpointing it, the batch may be sent again; the application should report the entries as duplicates rather than create duplicate rows.

To start a completely new import, move or delete the checkpoint file first. Keep the checkpoint file until you have verified the import.

## Error handling

- HTTP 429 and transient 5xx/network failures are retried with backoff.
- HTTP 401/403 stops the import; check token, source IP restrictions and host list permissions.
- HTTP 413/422 batches are recursively split to isolate problematic individual entries.
- A single URL still rejected with 422 is reported with its original YAML line number and recorded in `<state-file>.errors.json` (including `yaml_line`).
- Invalid YAML list names are reported with the line containing the `name:` field. YAML parser errors include their line and column when available.
- Per-URL statuses such as `invalid`, `blocked`, `pending`, `duplicate` and `added` are counted in the summary.

The server is authoritative for URL validation, public-suffix checks, classification, deduplication and wildcard shadowing. Local canonicalisation is only used to reduce duplicate submissions within the same YAML list.

## Operational notes

- Run the importer from a machine whose source IP is permitted for the configured host.
- Use HTTPS and leave certificate verification enabled. `--insecure` is provided only for controlled testing with a private/self-signed certificate.
- Start with `--dry-run`, then import a small test file/list before submitting the full dataset.
- The importer does not use the management API and cannot query existing database entries. Resume state tracks completed request batches, not a full remote inventory.
