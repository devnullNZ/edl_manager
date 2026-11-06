#!/usr/bin/env python3
"""
Import Palo Alto-style YAML URL lists into EDL Publisher (v2.2.0+) with source-based desired-state
synchronisation.

Each YAML list is a SOURCE (``<prefix>:<list name>``, default prefix ``yaml-import``). For every list the
importer sends the complete desired state of that source and the server works out what to add, keep and
remove. A source can only ever remove entries that it owns itself.

Expected YAML shape:
---
url:
  - name: example
    description: sample list
    type: URL List
    list:
      member:
        - "*.example.com"
        - example.com

Requires Python 3.10+.
"""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
import re
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

__version__ = "2.1.1"

try:  # the libyaml parser is several times faster and lighter; fall back to the pure-Python one
    from yaml import CSafeLoader as _Loader
except ImportError:  # pragma: no cover
    from yaml import SafeLoader as _Loader

LIST_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
SYNC_ID_MAX = 128
SOURCE_MAX = 100            # the server's limit for a sync source
RETRY_STATUS = (429, 500, 502, 503, 504)
STATE_FORMAT = 2

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_UNSUPPORTED = 0, 1, 2, 3


class ImportErrorDetail(Exception):
    """A problem that stops the import (or one list of it) with a message for the operator."""


class SessionLost(Exception):
    """The server no longer has the upload session (expired, aborted or purged). Nothing was applied."""


class ServerRefused(ImportErrorDetail):
    def __init__(self, status: int, detail: str, body: Any = None):
        super().__init__(detail)
        self.status, self.body = status, body


# --------------------------------------------------------------------------- #
# Canonicalisation (mirrors the server's app/normalize.py; the server stays authoritative)
# --------------------------------------------------------------------------- #
def canonical_key(raw: str) -> str:
    """The key the server would store for `raw`, computed locally for de-duplication and reporting.

    Same rules as the server: lower-case; scheme, credentials, port, query and fragment are removed;
    a domain root is ``host/`` (so ``example.com``, ``example.com/`` and ``https://example.com`` agree);
    a path keeps exactly its own trailing-slash form, so ``a.com/x`` and ``a.com/x/`` are DIFFERENT.

    Validation (labels, public-suffix wildcards, length) is deliberately not repeated here: input the
    server would reject still gets a best-effort key, and the server reports it as invalid.
    """
    s = raw.strip().lower()
    s = SCHEME_RE.sub("", s)
    s = s.split("#", 1)[0].split("?", 1)[0]
    host, _, path = s.partition("/")
    host = host.rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host).strip(".")
    path = path.lstrip("/")
    if path.endswith("/"):
        path = path.rstrip("/") + "/"
    if path == "/":
        path = ""
    return f"{host}/{path}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# YAML
# --------------------------------------------------------------------------- #
@dataclass
class YamlList:
    name: str
    description: str = ""
    raws: list[str] = field(default_factory=list)                  # members exactly as written (never stripped)
    lines: array.array = field(default_factory=lambda: array.array("I"))   # YAML line of each member
    blank: int = 0                                                  # blank members skipped
    name_line: int = 0


@dataclass
class ParsedYaml:
    lists: dict[str, YamlList]
    blocks: int
    skipped_types: list[str]


def _mapping_value(node: Any, key_name: str):
    if not isinstance(node, yaml.MappingNode):
        return None
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key_name:
            return value_node
    return None


def _iter_documents(path: Path):
    """(document number, node tree, data) one document at a time, so only one document's nodes are alive."""
    with path.open("r", encoding="utf-8-sig") as stream:
        loader = _Loader(stream)
        try:
            doc_no = 0
            while loader.check_node():
                doc_no += 1
                node = loader.get_node()
                data = loader.construct_document(node)
                yield doc_no, node, data
        finally:
            loader.dispose()


def parse_yaml(path: Path) -> ParsedYaml:
    """Read every url list. Member text is kept EXACTLY as written (the server canonicalises); only
    blank members are skipped (and counted). Errors carry the YAML line."""
    lists: dict[str, YamlList] = {}
    original_names: dict[str, str] = {}
    skipped: list[str] = []
    blocks = 0
    try:
        for doc_no, doc_node, doc in _iter_documents(path):
            if doc is None:
                continue
            if not isinstance(doc, dict):
                raise ImportErrorDetail(f"YAML document {doc_no}: expected a mapping at the document root")
            url_section = doc.get("url", [])
            url_node = _mapping_value(doc_node, "url")
            if isinstance(url_section, dict):
                url_blocks, block_nodes = [url_section], [url_node]
            elif isinstance(url_section, list):
                url_blocks = url_section
                block_nodes = url_node.value if isinstance(url_node, yaml.SequenceNode) else [None] * len(url_blocks)
            elif url_section is None:
                continue
            else:
                raise ImportErrorDetail(f"YAML document {doc_no}: 'url' must be a list or mapping")

            for block_no, (item, bnode) in enumerate(zip(url_blocks, block_nodes), start=1):
                blocks += 1
                if not isinstance(item, dict):
                    raise ImportErrorDetail(f"YAML document {doc_no}, url item {block_no}: expected a mapping")
                original_name = str(item.get("name", "")).strip()
                name_node = _mapping_value(bnode, "name")
                name_line = name_node.start_mark.line + 1 if name_node is not None else 0
                where = f"line {name_line}: " if name_line else f"document {doc_no}, url item {block_no}: "
                if not original_name:
                    raise ImportErrorDetail(f"{where}missing 'name'")
                name = re.sub(r"\s+", "_", original_name)
                if name != original_name:
                    print(f"List name normalised: {original_name!r} -> {name!r}", file=sys.stderr)
                if not LIST_NAME_RE.fullmatch(name):
                    raise ImportErrorDetail(
                        f"{where}YAML list name {original_name!r} becomes {name!r}, which is still invalid for "
                        "EDL Publisher. After whitespace replacement, names must contain only letters, digits, "
                        "underscores or hyphens and be 1-64 characters long.")
                previous = original_names.get(name)
                if previous is not None and previous != original_name:
                    raise ImportErrorDetail(
                        f"{where}YAML list-name collision: {previous!r} and {original_name!r} both become "
                        f"{name!r} after whitespace replacement. Rename one of the YAML lists.")
                original_names[name] = original_name

                list_type = str(item.get("type", "URL List")).strip().lower()
                if list_type not in ("url list", "url"):
                    print(f"Warning: skipping YAML list {name!r} with unsupported type {item.get('type')!r}",
                          file=sys.stderr)
                    skipped.append(name)
                    continue

                list_obj = item.get("list") or {}
                if not isinstance(list_obj, dict):
                    raise ImportErrorDetail(f"{where}YAML list {name!r}: 'list' must be a mapping")
                members = list_obj.get("member", [])
                if members is None:
                    members = []
                if isinstance(members, str):
                    members = [members]
                if not isinstance(members, list):
                    raise ImportErrorDetail(f"{where}YAML list {name!r}: 'list.member' must be a list of strings")

                member_node = _mapping_value(_mapping_value(bnode, "list"), "member")
                if isinstance(member_node, yaml.SequenceNode) and len(member_node.value) == len(members):
                    member_lines = [n.start_mark.line + 1 for n in member_node.value]
                elif isinstance(member_node, yaml.ScalarNode):
                    member_lines = [member_node.start_mark.line + 1]
                else:
                    member_lines = []

                yl = lists.get(name)
                if yl is None:
                    yl = lists[name] = YamlList(name=name, name_line=name_line)
                desc = str(item.get("description", "") or "").strip()
                if desc and not yl.description:
                    yl.description = desc
                for i, member in enumerate(members):
                    line = member_lines[i] if i < len(member_lines) else 0
                    if not isinstance(member, str):
                        at = f"line {line}: " if line else f"YAML list {name!r}, member {i + 1}: "
                        raise ImportErrorDetail(f"{at}expected a string, got {type(member).__name__}")
                    if not member.strip():
                        yl.blank += 1
                        continue
                    yl.raws.append(member)
                    yl.lines.append(line)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        at = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ImportErrorDetail(f"invalid YAML{at}: {exc}") from exc
    return ParsedYaml(lists=lists, blocks=blocks, skipped_types=skipped)


# --------------------------------------------------------------------------- #
# Units: one YAML list = one source = one sync
# --------------------------------------------------------------------------- #
@dataclass
class Unit:
    name: str                       # YAML list name (after whitespace replacement)
    source: str                     # stable source id: "<prefix>:<name>"
    target: str                     # EDL Publisher list
    raws: list[str]                 # exactly what will be submitted, in YAML order
    lines: array.array
    occurrences: int                # non-blank members read from the YAML
    blank_skipped: int
    unique_local: int
    duplicates_removed: int         # 0 when importer-side deduplication is off
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.target}|{self.source}"


def build_units(parsed: ParsedYaml, *, prefix: str, target_list: str | None, deduplicate: bool) -> list[Unit]:
    if not prefix or len(prefix) > 40 or any(c.isspace() for c in prefix):
        raise ImportErrorDetail("--source-prefix must be 1-40 characters without whitespace")
    units: list[Unit] = []
    for name in sorted(parsed.lists):
        yl = parsed.lists[name]
        source = f"{prefix}:{name}"
        if len(source) > SOURCE_MAX:
            raise ImportErrorDetail(f"source id {source!r} is {len(source)} characters; the server allows {SOURCE_MAX}")
        target = target_list or name
        if not LIST_NAME_RE.fullmatch(target):
            raise ImportErrorDetail(f"target list {target!r} is invalid; use letters, digits, '_' or '-' (max 64)")
        seen: set[str] = set()
        kept_raws: list[str] = []
        kept_lines = array.array("I")
        for raw, line in zip(yl.raws, yl.lines):
            key = canonical_key(raw)
            first = key not in seen
            seen.add(key)
            if first or not deduplicate:
                kept_raws.append(raw)
                kept_lines.append(line)
        units.append(Unit(name=name, source=source, target=target, raws=kept_raws, lines=kept_lines,
                          occurrences=len(yl.raws), blank_skipped=yl.blank, unique_local=len(seen),
                          duplicates_removed=len(yl.raws) - len(kept_raws), description=yl.description))
    return units


def cross_list_overlaps(parsed: ParsedYaml) -> int:
    count: Counter = Counter()
    for yl in parsed.lists.values():
        for key in {canonical_key(r) for r in yl.raws}:
            count[key] += 1
    return sum(1 for c in count.values() if c > 1)


def chunk_ranges(total: int, size: int) -> list[tuple[int, int]]:
    return [(i, min(i + size, total)) for i in range(0, total, size)]


def chunk_digest(raws: list[str], start: int, end: int) -> str:
    h = hashlib.sha256()
    for r in raws[start:end]:
        h.update(r.encode("utf-8", "surrogatepass"))
        h.update(b"\n")
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Checkpoint
# --------------------------------------------------------------------------- #
def new_sync_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", prefix)[:40]
    return f"{safe}-{stamp}-{uuid.uuid4().hex[:12]}"[:SYNC_ID_MAX]


class Checkpoint:
    """Recoverable progress of one import operation. Written atomically after every acknowledged step and
    kept after success (marked completed) as the record of what the server confirmed."""

    def __init__(self, path: Path, data: dict[str, Any]):
        self.path, self.data = path, data

    @classmethod
    def create(cls, path: Path, fingerprint: dict[str, Any]) -> "Checkpoint":
        cp = cls(path, {"format": STATE_FORMAT, "created_at": datetime.now(timezone.utc).isoformat(),
                        "importer_version": __version__, "fingerprint": fingerprint, "units": {}})
        cp.save()
        return cp

    @classmethod
    def load(cls, path: Path) -> "Checkpoint":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ImportErrorDetail(f"cannot read checkpoint {path}: {exc}") from exc
        if data.get("format") != STATE_FORMAT:
            raise ImportErrorDetail(
                f"checkpoint {path} was written by an older importer (format {data.get('format')!r}) and cannot "
                "be resumed. Move it aside to start a new import.")
        return cls(path, data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    def unit(self, key: str, prefix: str) -> dict[str, Any]:
        """The unit's record; its sync_id is generated once and persisted BEFORE anything is sent."""
        u = self.data["units"].get(key)
        if u is None:
            u = {"sync_id": new_sync_id(prefix), "status": "new", "uploaded": {}}
            self.data["units"][key] = u
            self.save()
        return u

    @property
    def all_completed(self) -> bool:
        units = self.data["units"]
        return bool(units) and all(u.get("status") in ("completed", "skipped_empty") for u in units.values())


# --------------------------------------------------------------------------- #
# Server API
# --------------------------------------------------------------------------- #
def describe(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:500]
    detail = body.get("detail", body) if isinstance(body, dict) else body
    if isinstance(detail, dict):
        errs = detail.get("errors")
        if errs:
            return "; ".join(str(e) for e in errs)[:1000]
    if isinstance(detail, list):  # FastAPI request validation
        return "; ".join(f"{'.'.join(str(p) for p in d.get('loc', []))}: {d.get('msg')}" for d in detail[:5])
    return str(detail)[:1000]


class Api:
    """The endpoints this importer uses, exactly as the v2.2.0 server defines them:

      POST   /v1/lists/{list}/sync                                  one request (small lists)
      POST   /v1/lists/{list}/sync/sessions                         start or resume a chunked sync
      GET    /v1/lists/{list}/sync/sessions/{id}                    progress
      PUT    /v1/lists/{list}/sync/sessions/{id}/chunks/{index}     stage one chunk (idempotent)
      POST   /v1/lists/{list}/sync/sessions/{id}/commit             verify completeness, then reconcile
      GET    /v1/lists/{list}/sync/sessions/{id}/invalid            entries the server rejected (chunk, position)
      DELETE /v1/lists/{list}/sync/sessions/{id}                    abandon
    """

    def __init__(self, client: httpx.Client, base_url: str, *, max_retries: int = 5, timeout: float = 60.0,
                 commit_timeout: float = 900.0, sleep: Callable[[float], None] = time.sleep, log=print):
        self.client, self.base = client, base_url.rstrip("/")
        self.max_retries, self.timeout, self.commit_timeout = max_retries, timeout, commit_timeout
        self.sleep, self.log = sleep, log
        self.requests: Counter = Counter()

    # ---- transport
    def _delay(self, response: httpx.Response | None, attempt: int) -> float:
        if response is not None:
            value = response.headers.get("Retry-After")
            if value:
                try:
                    return min(120.0, max(1.0, float(value)))
                except ValueError:
                    pass
        return min(60.0, 2.0 ** attempt)

    def request(self, method: str, path: str, *, json_body: Any = None, timeout: float | None = None,
                what: str = "request") -> httpx.Response:
        """Send with retries for network errors, timeouts, 429 and 5xx. Every call this importer makes is
        safe to repeat (the server de-duplicates by sync_id, chunk index and session)."""
        url = self.base + path
        response: httpx.Response | None = None
        for attempt in range(self.max_retries + 1):
            self.requests[f"{method} {path.split('?')[0]}"] += 1
            try:
                response = self.client.request(method, url, json=json_body, timeout=timeout or self.timeout)
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                if attempt >= self.max_retries:
                    raise ImportErrorDetail(f"network failure during {what}: {type(exc).__name__}") from exc
                delay = self._delay(None, attempt)
                self.log(f"  transient network error during {what}; retrying in {delay:.0f}s", file=sys.stderr)
                self.sleep(delay)
                continue
            if response.status_code in RETRY_STATUS and attempt < self.max_retries:
                delay = self._delay(response, attempt)
                self.log(f"  HTTP {response.status_code} during {what}; retrying in {delay:.0f}s", file=sys.stderr)
                self.sleep(delay)
                continue
            break
        assert response is not None
        if response.status_code in (401, 403):
            raise ImportErrorDetail(
                f"HTTP {response.status_code} during {what}. Check the host token, allowed source IP and "
                f"permitted-list configuration. Response: {response.text[:500]}")
        return response

    # ---- sync
    def sync_once(self, target: str, payload: dict) -> dict:
        r = self.request("POST", f"/v1/lists/{target}/sync", json_body=payload, timeout=self.commit_timeout,
                         what=f"sync of {target!r}")
        if r.status_code != 200:
            raise ServerRefused(r.status_code, describe(r), _json(r))
        return r.json()

    def start_session(self, target: str, payload: dict) -> dict:
        r = self.request("POST", f"/v1/lists/{target}/sync/sessions", json_body=payload,
                         what=f"starting the upload session for {target!r}")
        if r.status_code == 404 or r.status_code == 405:
            raise ImportErrorDetail(
                "this server does not offer chunked sync (POST /v1/lists/{list}/sync/sessions returned "
                f"HTTP {r.status_code}). Upgrade the server, or use --mode single for lists no larger than "
                "the server's 'Maximum sync size'.")
        if r.status_code != 200:
            raise ServerRefused(r.status_code, describe(r), _json(r))
        return r.json()

    def session_status(self, target: str, session_id: int) -> dict | None:
        r = self.request("GET", f"/v1/lists/{target}/sync/sessions/{session_id}", what="reading upload progress")
        if r.status_code in (404, 410):
            return None
        if r.status_code != 200:
            raise ServerRefused(r.status_code, describe(r), _json(r))
        return r.json()

    def put_chunk(self, target: str, session_id: int, index: int, entries: list[str]) -> dict:
        r = self.request("PUT", f"/v1/lists/{target}/sync/sessions/{session_id}/chunks/{index}",
                         json_body={"entries": entries}, what=f"uploading chunk {index}")
        if r.status_code in (404, 410):
            raise SessionLost(describe(r))
        if r.status_code != 200:
            raise ServerRefused(r.status_code, describe(r), _json(r))
        return r.json()

    def commit(self, target: str, session_id: int, total_chunks: int, total_entries: int, *, dry_run=False,
               max_removals: int | None = None) -> dict:
        body = {"total_chunks": total_chunks, "total_entries": total_entries, "dry_run": dry_run}
        if max_removals is not None:
            body["max_removals"] = max_removals      # only passed when the server's schema defines it
        r = self.request("POST", f"/v1/lists/{target}/sync/sessions/{session_id}/commit",
                         json_body=body,
                         timeout=self.commit_timeout, what="the final commit")
        if r.status_code in (404, 410):
            raise SessionLost(describe(r))
        if r.status_code != 200:
            raise ServerRefused(r.status_code, describe(r), _json(r))
        return r.json()

    def invalid_entries(self, target: str, session_id: int, offset: int, limit: int) -> dict | None:
        r = self.request("GET", f"/v1/lists/{target}/sync/sessions/{session_id}/invalid?offset={offset}&limit={limit}",
                         what="listing rejected entries")
        return r.json() if r.status_code == 200 else None

    def abort_session(self, target: str, session_id: int) -> None:
        try:
            self.client.request("DELETE", f"{self.base}/v1/lists/{target}/sync/sessions/{session_id}",
                                timeout=self.timeout)
        except httpx.HTTPError:
            pass

    def supports(self, model: str, prop: str) -> bool:
        """Does the server's published schema define `prop` on `model`? (cached; False when unknown)"""
        cache = self.__dict__.setdefault("_supports", {})
        if model not in cache:
            cache[model] = self.schema_properties(model)
        return bool(cache[model]) and prop in cache[model]

    def schema_properties(self, model: str) -> set[str] | None:
        """Property names of a request model in the server's published OpenAPI schema (None if unavailable)."""
        try:
            r = self.client.get(f"{self.base}/openapi.json", timeout=self.timeout)
            if r.status_code != 200:
                return None
            return set(r.json()["components"]["schemas"][model]["properties"])
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            return None


def _json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Running one unit
# --------------------------------------------------------------------------- #
@dataclass
class Options:
    mode: str = "auto"                  # auto | single | chunked
    chunk_size: int = 10000
    delete_missing: bool = False        # the safe default: entries that left the YAML are kept
    confirm_empty: bool = False
    reclassify: bool = False
    verbose_report: bool = False
    max_removals: int | None = None     # refuse to commit if the server's preview removes more than this


@dataclass
class Outcome:
    unit: Unit
    status: str = "pending"             # completed | failed | skipped_empty | dry_run
    mode: str = ""
    sync_id: str = ""
    report: dict = field(default_factory=dict)
    error: str = ""
    chunks: int = 0
    chunks_sent_this_run: int = 0
    chunks_skipped: int = 0
    session_restarts: int = 0
    resumed: bool = False
    removal_preview: dict = field(default_factory=dict)
    invalid_full: list = field(default_factory=list)   # every rejected entry the server listed, with YAML lines


def choose_mode(opts: Options, n: int) -> str:
    if n == 0:
        return "single"
    if opts.mode == "single":
        return "single"
    if opts.mode == "chunked":
        return "chunked"
    return "single" if n <= opts.chunk_size else "chunked"


def server_limit(api: Api, model: str, opts: Options, say=None) -> int | None:
    """The --max-removals value to hand to the server for enforcement inside its commit transaction, or None
    when there is none to send (no limit, deletion off, or a server whose schema has no such field; then
    only the importer's own preview check applies and the operator is told so)."""
    if opts.max_removals is None or not opts.delete_missing:
        return None
    if api.supports(model, "max_removals"):
        return opts.max_removals
    if say:
        say("  note: this server cannot enforce --max-removals itself (no 'max_removals' in its API); the limit is "
            "checked against the preview only, so a change made between preview and commit is not covered. "
            "Upgrade the server to 2.3.1 or later.")
    return None


def _limit_refused(exc: "ServerRefused") -> dict | None:
    d = (exc.body or {}).get("detail") if isinstance(exc.body, dict) else None
    return d if exc.status == 409 and isinstance(d, dict) and d.get("removal_limit_exceeded") else None


def _limit_error(d: dict, unit: Unit, resumable: bool) -> "ImportErrorDetail":
    return ImportErrorDetail(
        f"the server refused the commit for {unit.source!r}: it would now remove {d.get('would_remove'):,} "
        f"entries but --max-removals is {d.get('max_removals'):,} (the list changed since the preview, or the "
        "preview was out of date). Nothing was removed. Re-run with a higher --max-removals if this is intended"
        + (" and --resume (the staged upload is kept, nothing is re-sent)." if resumable else "."))


def base_payload(unit: Unit, sync_id: str, opts: Options) -> dict:
    payload = {"source": unit.source, "sync_id": sync_id, "delete_missing": opts.delete_missing,
               "confirm_empty": opts.confirm_empty and not unit.raws}
    if opts.reclassify:
        payload["reclassify"] = True        # only ever sent after the server's schema was found to define it
    return payload


def run_unit(api: Api, unit: Unit, opts: Options, cp: Checkpoint | None, prefix: str, *, dry_run: bool = False,
             say=print) -> Outcome:
    out = Outcome(unit=unit)
    n = len(unit.raws)
    rec = cp.unit(unit.key, prefix) if cp else {"sync_id": new_sync_id("dryrun"), "status": "new", "uploaded": {}}
    out.sync_id = rec["sync_id"]

    def save():
        if cp:
            cp.save()

    if rec.get("status") == "completed":
        out.status, out.mode, out.report = "completed", rec.get("mode", ""), rec.get("report", {})
        out.resumed = True
        say(f"[{unit.name}] already completed in this checkpoint (sync_id {rec['sync_id']}); skipped")
        return out

    if n == 0:
        if not opts.delete_missing:
            out.status = "skipped_empty"
            out.error = "no entries and --delete-missing is not set: nothing to do (nothing is removed by default)"
            rec["status"] = "skipped_empty"
            save()
            return out
        if not opts.confirm_empty:
            out.status = "failed"
            out.error = (f"the YAML list {unit.name!r} has no members. Syncing an empty desired state would remove "
                         f"every entry that source {unit.source!r} owns in {unit.target!r}. Nothing was sent; "
                         "re-run with --confirm-empty if that is what you want.")
            rec["status"] = "failed"
            rec["error"] = out.error
            save()
            return out

    mode = choose_mode(opts, n)
    out.mode = rec["mode"] = mode
    try:
        if mode == "single":
            _run_single(api, unit, opts, rec, out, dry_run, save, say)
        else:
            _run_chunked(api, unit, opts, rec, out, dry_run, save, say)
    except ServerRefused as exc:
        out.status, out.error = "failed", f"HTTP {exc.status}: {exc}"
        detail = (exc.body or {}).get("detail") if isinstance(exc.body, dict) else None
        out.report = {"refusal": exc.body, "invalid": (detail or {}).get("invalid", []) if isinstance(detail, dict) else []}
        rec["status"], rec["error"] = "failed", out.error
        save()
    except ImportErrorDetail as exc:
        out.status, out.error = "failed", str(exc)
        rec["status"], rec["error"] = "failed", out.error
        save()
    return out


def _finish(out: Outcome, rec: dict, report: dict, dry_run: bool, save) -> None:
    out.report = report
    if dry_run:
        out.status = "dry_run"
        return
    out.status = "completed"
    rec.update(status="completed", report=_compact(report), completed_at=datetime.now(timezone.utc).isoformat(),
               result_status=report.get("status"))
    save()


def _compact(report: dict) -> dict:
    """What the checkpoint keeps of a server report: the counts, feed totals and the invalid list."""
    return {k: report.get(k) for k in ("status", "counts", "feed", "invalid", "run_id", "warning",
                                      "removals_deferred", "duplicate", "dry_run", "session",
                                      "reclassification") if k in report}


def removal_preview(api: Api, unit: Unit, opts: Options, report: dict, rec: dict, out: Outcome, say) -> None:
    """Show, BEFORE anything is committed, how many entries the server will remove. `report` is the
    server's own dry-run of exactly this desired state. Raises when it exceeds --max-removals."""
    c = report.get("counts", {}) or {}
    removed, deleted, kept = c.get("removed", 0), c.get("entries_deleted", 0), c.get("kept_other_owners", 0)
    out.removal_preview = {"would_remove_ownership": removed, "entries_deleted": deleted,
                           "kept_because_other_sources_own_them": kept, "stay": c.get("total_desired")}
    rec["removal_preview"] = out.removal_preview
    if removed:
        say(f"  [{unit.name}] --delete-missing: committing will remove {removed:,} entr"
            f"{'y' if removed == 1 else 'ies'} that {unit.source} owned and no longer lists "
            f"({deleted:,} deleted outright, {kept:,} kept because another source also owns them); "
            f"{c.get('total_desired', 0):,} entries remain desired.")
    else:
        say(f"  [{unit.name}] --delete-missing: committing will remove nothing "
            f"({c.get('total_desired', 0):,} entries desired, none missing).")
    if opts.max_removals is not None and removed > opts.max_removals:
        raise ImportErrorDetail(
            f"the server would remove {removed:,} entries from {unit.source!r} but --max-removals is "
            f"{opts.max_removals:,}. Nothing was removed. If this is intended, re-run with a higher "
            "--max-removals" + (" and --resume (the staged upload is kept, nothing is re-sent)."
                                if rec.get("session_id") else "."))


def _run_single(api, unit, opts, rec, out, dry_run, save, say) -> None:
    payload = {**base_payload(unit, rec["sync_id"], opts), "entries": unit.raws, "dry_run": dry_run,
               "verbose": opts.verbose_report}
    limit = server_limit(api, "SyncIn", opts, say if not dry_run else None)
    if limit is not None:
        payload["max_removals"] = limit
    say(f"[{unit.name}] sending {len(unit.raws):,} entries to {unit.target!r} in one request "
        f"(source {unit.source}, sync_id {rec['sync_id']})")
    rec["status"] = "committing"
    save()
    if opts.delete_missing and not dry_run:
        preview = api.sync_once(unit.target, {**payload, "dry_run": True})   # a dry run never consumes the sync_id
        removal_preview(api, unit, opts, preview, rec, out, say)
        save()
    try:
        report = api.sync_once(unit.target, payload)
    except ServerRefused as exc:
        d = _limit_refused(exc)
        if d:
            raise _limit_error(d, unit, False) from None
        raise
    _finish(out, rec, report, dry_run, save)


def _run_chunked(api, unit, opts, rec, out, dry_run, save, say) -> None:
    n = len(unit.raws)
    size = rec.get("chunk_size") or opts.chunk_size
    session_id = rec.get("session_id")
    sync_id = rec["sync_id"]
    start_payload = {k: v for k, v in base_payload(unit, sync_id, opts).items()}
    session = None

    def start() -> dict:
        s = api.start_session(unit.target, start_payload)
        return s

    # --- find or start the session. An existing session is looked up by id; a new one is created only
    # when there is none (first run, or the server lost it).
    if session_id and not dry_run:
        session = api.session_status(unit.target, session_id)
        if session is not None and session.get("status") != "receiving":
            session = None
        out.resumed = session is not None
    if session is None:
        session = start()
        if session.get("status") == "already_applied":
            say(f"[{unit.name}] the server already applied sync_id {sync_id}; nothing to upload")
            report = {"status": session.get("result", "applied"), "counts": session.get("summary", {}),
                      "duplicate": True, "run_id": session.get("run_id"),
                      "note": "full report unavailable: the server returned the stored summary only"}
            _finish(out, rec, report, dry_run, save)
            return
        out.resumed = bool(session.get("resumed"))
        if session.get("resumed") is False:
            rec["uploaded"] = {}
    session_id = rec["session_id"] = session["session_id"]
    max_chunk = int(session.get("max_chunk_size") or size)
    if rec.get("chunk_size") is None:
        rec["chunk_size"] = size = min(size, max_chunk)
    elif size > max_chunk:
        raise ImportErrorDetail(
            f"the checkpoint uses chunks of {size:,} entries but the server now accepts at most {max_chunk:,}. "
            "Start a new import (--discard-checkpoint) with a smaller --chunk-size.")
    ranges = chunk_ranges(n, size)
    out.chunks = rec["total_chunks"] = len(ranges)
    rec["total_entries"] = n
    rec["status"] = "uploading"
    save()
    digests = {i: chunk_digest(unit.raws, a, b) for i, (a, b) in enumerate(ranges)}
    for i, d in rec["uploaded"].items():
        if digests.get(int(i)) != d:
            raise ImportErrorDetail(f"chunk {i} no longer matches what was uploaded earlier: the input changed")
    say(f"[{unit.name}] {n:,} entries in {len(ranges)} chunk(s) of up to {size:,} -> {unit.target!r} "
        f"(source {unit.source}, sync_id {sync_id}, session {session_id}"
        f"{', resuming' if out.resumed else ''})")

    restarts = 0
    while True:
        try:
            have = _server_chunks(session)
            _upload_missing(api, unit, rec, ranges, digests, have, out, save, say)
            say(f"  [{unit.name}] all {len(ranges)} chunk(s) uploaded. Waiting for the server to validate, classify "
                "and apply; this can take several minutes for large lists...")
            rec["status"] = "committing"
            save()
            try:
                _collect_invalid(api, unit, ranges, session_id, out, say)
                limit = server_limit(api, "CommitIn", opts, say if not dry_run else None)
                if opts.delete_missing and not dry_run:
                    preview = api.commit(unit.target, session_id, len(ranges), n, dry_run=True, max_removals=limit)
                    removal_preview(api, unit, opts, preview, rec, out, say)
                    save()
                report = api.commit(unit.target, session_id, len(ranges), n, dry_run=dry_run, max_removals=limit)
            except ServerRefused as exc:
                d = _limit_refused(exc)
                if d:                                   # the session stays open on the server; --resume re-commits
                    raise _limit_error(d, unit, True) from None
                if exc.status == 409 and isinstance(exc.body, dict) and \
                        (exc.body.get("detail") or {}).get("nothing_applied"):
                    # the server says chunks are missing: refresh what it has and send those again
                    session = api.session_status(unit.target, session_id)
                    if session is None:
                        raise SessionLost("session vanished") from None
                    rec["uploaded"] = {k: v for k, v in rec["uploaded"].items() if int(k) in _server_chunks(session)}
                    if restarts >= 2:
                        raise
                    restarts += 1
                    continue
                if exc.status in (413, 422, 409):      # a definitive refusal: free the source for the next run
                    api.abort_session(unit.target, session_id)
                    rec.pop("session_id", None)
                    rec["uploaded"] = {}
                    save()
                raise
            break
        except SessionLost as exc:
            if restarts >= 2:
                raise ImportErrorDetail(f"the server keeps losing the upload session ({exc}); nothing was applied") \
                    from None
            restarts += 1
            out.session_restarts = restarts
            say(f"  [{unit.name}] the server no longer has session {session_id} ({exc}); nothing was applied. "
                "Restarting the upload with the same sync_id.")
            rec["uploaded"] = {}
            session = start()
            session_id = rec["session_id"] = session["session_id"]
            save()
    if dry_run:
        api.abort_session(unit.target, session_id)       # discard the staged copy; the list was not touched
    else:
        rec["session_id"] = session_id
    _finish(out, rec, report, dry_run, save)


def _collect_invalid(api: Api, unit: Unit, ranges: list[tuple[int, int]], session_id: int, out: Outcome, say) -> None:
    """Ask the server which entries of the staged upload it rejected (chunk + position -> YAML line). Done
    BEFORE the commit because a committed session's staged data is gone."""
    st = api.session_status(unit.target, session_id)
    total = (st or {}).get("received_invalid", 0)
    if not total:
        return
    found: list[dict] = []
    offset = 0
    while offset < total and offset < 5000:
        page = api.invalid_entries(unit.target, session_id, offset, 1000)
        if not page or not page.get("items"):
            break
        for it in page["items"]:
            idx = ranges[it["chunk"]][0] + it["position"] if 0 <= it["chunk"] < len(ranges) else None
            line = unit.lines[idx] if idx is not None and idx < len(unit.lines) else None
            found.append({"entry": it["entry"], "reason": it["reason"], "yaml_line": line, "chunk": it["chunk"]})
        offset += len(page["items"])
    out.invalid_full = found
    say(f"  [{unit.name}] the server rejected {total:,} entr{'y' if total == 1 else 'ies'} during upload "
        "(listed in the summary with their YAML lines)")


def _server_chunks(session: dict) -> set[int]:
    have: set[int] = set()
    for a, b in session.get("received_ranges", []):
        have.update(range(a, b + 1))
    return have


def _upload_missing(api, unit, rec, ranges, digests, have, out, save, say) -> None:
    n = len(unit.raws)
    for i, (a, b) in enumerate(ranges):
        mine = str(i) in rec["uploaded"]
        if i in have and mine:
            out.chunks_skipped += 1
            continue
        # The same session, the same chunk index: sending it again is harmless (the server acknowledges an
        # identical chunk and refuses a different one). No new session is created for a retry.
        ack = api.put_chunk(unit.target, rec["session_id"], i, unit.raws[a:b])
        rec["uploaded"][str(i)] = digests[i]
        out.chunks_sent_this_run += 1
        save()
        note = " (already on the server)" if ack.get("already_received") else ""
        if ack.get("invalid_in_chunk"):
            note += f" - {ack['invalid_in_chunk']} entr{'y' if ack['invalid_in_chunk'] == 1 else 'ies'} rejected by the server"
        say(f"  [{unit.name}] uploaded chunk {i + 1}/{len(ranges)}{note}: {b:,}/{n:,} entries "
            f"({b / n * 100:.1f}%)")


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def lines_for_invalid(unit: Unit, invalid: list[dict]) -> list[dict]:
    wanted = {i["entry"] for i in invalid}
    first: dict[str, int] = {}
    for raw, line in zip(unit.raws, unit.lines):
        r = raw[:200]
        if r in wanted and r not in first:
            first[r] = line
        elif raw.strip()[:200] in wanted and raw.strip()[:200] not in first:
            first[raw.strip()[:200]] = line
    return [{**i, "yaml_line": first.get(i["entry"]) or None} for i in invalid]


def unit_summary(o: Outcome, dedupe: bool) -> dict:
    c = (o.report or {}).get("counts", {}) or {}
    u = o.unit
    return {
        "list": u.target, "source": u.source, "status": o.status, "mode": o.mode, "sync_id": o.sync_id,
        "server_status": (o.report or {}).get("status"), "error": o.error or None,
        "yaml_occurrences_read": u.occurrences, "blank_members_skipped": u.blank_skipped,
        "unique_locally": u.unique_local,
        "duplicates_removed_by_importer": u.duplicates_removed if dedupe else None,
        "occurrences_submitted": len(u.raws),
        "server_new": c.get("new"), "server_unchanged": c.get("unchanged"),
        "server_ownership_added": c.get("ownership_added"), "server_removed": c.get("removed"),
        "server_duplicates_in_submission": c.get("duplicates_in_request"),
        "server_invalid": c.get("invalid"),
        "blocked_by_policy": c.get("blocked_by_policy"), "blocked_by_classification": c.get("blocked_by_classification"),
        "pending_classification": c.get("pending_classification"),
        "suppressed_by_wildcard": c.get("suppressed_by_shadowing"), "published_of_desired": c.get("published_of_desired"),
        "kept_missing_not_removed": c.get("missing_not_removed"), "removals_deferred": (o.report or {}).get("removals_deferred"),
        "removal_preview": o.removal_preview or None,
        "reclassification": (o.report or {}).get("reclassification"),
        "chunks": o.chunks, "chunks_sent_this_run": o.chunks_sent_this_run, "chunks_already_on_server": o.chunks_skipped,
        "feed": (o.report or {}).get("feed"),
    }


def fmt(v) -> str:
    return "-" if v is None else f"{v:,}" if isinstance(v, int) else str(v)


def print_summary(outcomes: list[Outcome], dedupe: bool, dry_run: bool, say=print) -> None:
    head = "Server dry run (nothing was changed)" if dry_run else "Import summary"
    say(f"\n{head}")
    say(f"  Importer-side deduplication: {'ENABLED' if dedupe else 'DISABLED (every occurrence was submitted)'}")
    total = Counter()
    for o in outcomes:
        s = unit_summary(o, dedupe)
        say(f"\n  [{o.unit.name}] -> list {o.unit.target!r}, source {o.unit.source}: {o.status.upper()}"
            f"{' (' + o.mode + ' sync, sync_id ' + o.sync_id + ')' if o.mode else ''}")
        if o.error:
            say(f"    ERROR: {o.error}")
        say(f"    URL occurrences read from YAML:        {fmt(s['yaml_occurrences_read'])}"
            f"{' (+' + str(o.unit.blank_skipped) + ' blank skipped)' if o.unit.blank_skipped else ''}")
        say(f"    Unique URLs (computed locally):        {fmt(s['unique_locally'])}")
        say("    Duplicates removed by the importer:    "
            + (fmt(s['duplicates_removed_by_importer']) if dedupe else "0 (deduplication disabled; none performed)"))
        say(f"    URL occurrences submitted to server:   {fmt(s['occurrences_submitted'])}")
        if o.status in ("completed", "dry_run") and o.report:
            say(f"    Entries newly created by the server:   {fmt(s['server_new'])}")
            say(f"    Already present and unchanged:         {fmt(s['server_unchanged'])}"
                f"   (ownership added to existing entries: {fmt(s['server_ownership_added'])})")
            say(f"    Duplicates identified by the server:   {fmt(s['server_duplicates_in_submission'])}"
                "   (repeated occurrences within the submission)")
            say(f"    Rejected by server validation:         {fmt(s['server_invalid'])}")
            word = "Would remove" if dry_run else "Removed"
            say(f"    {word} (no longer listed):".ljust(43) + f"{fmt(s['server_removed'])}"
                + (f"   (kept, NOT removed because --delete-missing is not set: {fmt(s['kept_missing_not_removed'])})"
                   if s['kept_missing_not_removed'] else ""))
            say(f"    Blocked by policy / by classification: {fmt(s['blocked_by_policy'])} / {fmt(s['blocked_by_classification'])}")
            say(f"    Pending classification:                {fmt(s['pending_classification'])}")
            say(f"    Suppressed by a wildcard:              {fmt(s['suppressed_by_wildcard'])}")
            say(f"    Published (of this source's entries):  {fmt(s['published_of_desired'])}")
            feed = s.get("feed") or {}
            if feed:
                say(f"    Effective EDL: {fmt(feed.get('entries_before'))} -> {fmt(feed.get('entries_after'))} entries "
                    f"({'changed' if feed.get('changed') else 'unchanged'})")
            rc = (o.report or {}).get("reclassification") or {}
            if rc.get("requested"):
                if rc.get("dry_run"):
                    say(f"    Reclassification: would ask Panorama again about {fmt(rc.get('in_scope'))} existing entries "
                        f"({fmt(rc.get('panorama_lookups_needed'))} distinct lookups)")
                else:
                    say(f"    Reclassification (job {rc.get('job_id')}): {fmt(rc.get('in_scope'))} existing entries, "
                        f"{fmt(rc.get('reclassified_inline'))} re-checked now ({fmt(rc.get('changed_inline'))} changed), "
                        f"{fmt(rc.get('queued_for_engine'))} queued for the server, "
                        f"{fmt(rc.get('kept_after_error'))} failed and will be retried; "
                        f"{fmt(rc.get('remaining'))} remaining -> {rc.get('status')}")
            if o.report.get("removals_deferred"):
                say("    WARNING: removals were NOT applied because classification failed during this run; repeat the sync.")
            if o.chunks:
                say(f"    Chunks: {o.chunks} (sent this run {o.chunks_sent_this_run}, already on server "
                    f"{o.chunks_skipped}{', session restarted ' + str(o.session_restarts) + 'x' if o.session_restarts else ''})")
        inv = o.invalid_full or lines_for_invalid(o.unit, (o.report or {}).get("invalid") or [])
        for i in inv[:20]:
            at = f"line {i['yaml_line']}" if i.get("yaml_line") else "line unknown"
            say(f"    rejected ({at}): {i['entry']!r}: {i['reason']}")
        if len(inv) > 20:
            say(f"    ... and {len(inv) - 20} more rejected entries (see --report-file)")
        for k in ("occurrences_submitted",):
            total[k] += s[k]
        if o.status in ("completed", "dry_run"):
            for k in ("server_new", "server_removed", "pending_classification", "server_invalid"):
                total[k] += s[k] or 0
    running = [(o.unit.name, (o.report or {}).get("reclassification") or {}) for o in outcomes
               if ((o.report or {}).get("reclassification") or {}).get("status") == "running"]
    for name, rc in running:
        say(f"\n  RECLASSIFICATION OF [{name}] IS STILL RUNNING ON THE SERVER: {fmt(rc.get('remaining'))} entries wait for "
            f"its background engine. They keep their current status meanwhile. Progress: "
            f"GET /v1/lists/<list>/sync/reclassifications/{rc.get('job_id')} (host token).")
    pending = total["pending_classification"]
    if pending and not dry_run:
        say(f"\n  UPLOAD COMPLETE, BUT CLASSIFICATION IS STILL PENDING for {pending:,} entr"
            f"{'y' if pending == 1 else 'ies'}. They are stored and owned by their sources but are NOT published "
            "until the server's background engine classifies them (Panorama allows at most 5 concurrent requests, "
            "so large imports take a while). Re-running the same import later is safe.")


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def make_client(token: str, timeout: float, verify: bool) -> httpx.Client:
    return httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=timeout, verify=verify)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Synchronise Palo Alto YAML URL lists into EDL Publisher (v2.2.0+).")
    p.add_argument("yaml_file", type=Path, help="YAML file containing one or more url lists")
    p.add_argument("--base-url", default=os.getenv("EDL_BASE_URL"), help="Application base URL (or EDL_BASE_URL)")
    p.add_argument("--token", default=os.getenv("EDL_HOST_TOKEN"), help="Allowed host bearer token (or EDL_HOST_TOKEN)")
    p.add_argument("--target-list", help="Put every YAML list into this one EDL list. Each YAML list still has its "
                                         "own source, so lists never remove each other's entries.")
    p.add_argument("--source-prefix", "--source", dest="source_prefix", default="yaml-import",
                   help="Source ids are '<prefix>:<YAML list name>' (default prefix: yaml-import). Keep it stable.")
    p.add_argument("--mode", choices=("auto", "single", "chunked"), default="auto",
                   help="auto: one request for lists up to --chunk-size entries, chunked sessions above that")
    p.add_argument("--chunk-size", type=int, default=10000, help="Entries per upload chunk (default 10000)")
    p.add_argument("--delete-missing", dest="delete_missing", action="store_true", default=False,
                   help="Remove entries this source owns that are no longer in the YAML list. OFF by default: "
                        "without it entries are only ever added or updated. The number to be removed is shown "
                        "(from a server dry run) before anything is committed.")
    p.add_argument("--no-delete-missing", dest="delete_missing", action="store_false",
                   help="The default; accepted for compatibility with importer 2.0 scripts")
    p.add_argument("--max-removals", type=int, metavar="N",
                   help="With --delete-missing: refuse to commit if the server would remove more than N entries "
                        "from a list")
    p.add_argument("--confirm-empty", action="store_true",
                   help="Allow a YAML list with no members to remove everything its source owns")
    p.add_argument("--reclassify", action="store_true",
                   help="Ask the server for fresh classification of existing entries (needs server support)")
    p.add_argument("--deduplicate", action=argparse.BooleanOptionalAction, default=True,
                   help="Remove duplicate URLs before submitting (default: on). --no-deduplicate submits every "
                        "occurrence and lets the server deduplicate.")
    p.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds (default 60)")
    p.add_argument("--commit-timeout", type=float, default=900.0,
                   help="Timeout for the final commit / single-request sync, which classifies and applies (default 900)")
    p.add_argument("--max-retries", type=int, default=5, help="Retries for transient failures")
    p.add_argument("--state-file", type=Path, help="Checkpoint file (default: <yaml_file>.import-state.json)")
    p.add_argument("--resume", action="store_true", help="Continue an interrupted import from its checkpoint")
    p.add_argument("--discard-checkpoint", action="store_true",
                   help="Delete an unfinished checkpoint and start a new import (new sync_ids)")
    p.add_argument("--dry-run", action="store_true", help="Parse and report only; do not contact the server")
    p.add_argument("--server-dry-run", action="store_true",
                   help="Upload and ask the server what it WOULD do; nothing is changed and no checkpoint is kept")
    p.add_argument("--report-file", type=Path, help="Write a JSON report of the run")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def print_plan(parsed: ParsedYaml, units: list[Unit], dedupe: bool, say=print) -> None:
    occ = sum(u.occurrences for u in units)
    say(f"YAML documents/lists parsed: {parsed.blocks}")
    say(f"Sources (one per YAML list): {len(units)}")
    say(f"URL occurrences read from YAML:        {occ:,}")
    say(f"Unique URLs (computed locally):        {sum(u.unique_local for u in units):,}")
    say("Duplicates removed by the importer:    "
        + (f"{sum(u.duplicates_removed for u in units):,}" if dedupe else "0 (deduplication disabled)"))
    say(f"URL occurrences to submit:             {sum(len(u.raws) for u in units):,}")
    say(f"Canonical entries shared across lists: {cross_list_overlaps(parsed):,}")
    for u in units:
        extra = f", {u.blank_skipped} blank skipped" if u.blank_skipped else ""
        say(f"  {u.name} -> {u.target} (source {u.source}): {u.occurrences:,} read, {u.unique_local:,} unique, "
            f"{len(u.raws):,} to submit{extra}")
        if u.description:
            say(f"    description: {u.description}")


def main(argv: list[str] | None = None, *, client_factory=make_client, sleep=time.sleep, out=print) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.chunk_size < 1 or args.chunk_size > 200000:
        parser.error("--chunk-size must be between 1 and 200000")
    if args.max_retries < 0:
        parser.error("--max-retries cannot be negative")
    local_only = args.dry_run
    if not local_only and (not args.base_url or not args.token):
        parser.error("--base-url/EDL_BASE_URL and --token/EDL_HOST_TOKEN are required")
    if args.resume and args.discard_checkpoint:
        parser.error("--resume and --discard-checkpoint cannot be combined")
    if not args.yaml_file.is_file():
        parser.error(f"YAML file does not exist: {args.yaml_file}")

    try:
        parsed = parse_yaml(args.yaml_file)
        if not parsed.lists:
            raise ImportErrorDetail("the YAML file contains no URL lists; refusing to synchronise nothing")
        units = build_units(parsed, prefix=args.source_prefix, target_list=args.target_list,
                            deduplicate=args.deduplicate)
    except ImportErrorDetail as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print_plan(parsed, units, args.deduplicate, say=out)
    if local_only:
        out("\nDry run complete; the server was not contacted.")
        return EXIT_OK

    opts = Options(mode=args.mode, chunk_size=args.chunk_size, delete_missing=args.delete_missing,
                   confirm_empty=args.confirm_empty, reclassify=args.reclassify, max_removals=args.max_removals)
    base = args.base_url.rstrip("/")
    fingerprint = {"input_sha256": sha256_file(args.yaml_file), "base_url": base, "target_list": args.target_list,
                   "source_prefix": args.source_prefix, "chunk_size": args.chunk_size, "mode": args.mode,
                   "deduplicate": args.deduplicate, "delete_missing": args.delete_missing,
                   "reclassify": args.reclassify}     # --confirm-empty is a decision about an empty list, not content

    state_path = args.state_file or Path(str(args.yaml_file) + ".import-state.json")
    if args.insecure:
        print("WARNING: TLS certificate verification is disabled.", file=sys.stderr)
    outcomes: list[Outcome] = []
    exit_code = EXIT_OK
    cp: Checkpoint | None = None
    with client_factory(args.token, args.timeout, not args.insecure) as client:
        api = Api(client, base, max_retries=args.max_retries, timeout=args.timeout,
                  commit_timeout=args.commit_timeout, sleep=sleep, log=lambda *a, **k: print(*a, **k))
        if args.reclassify:       # before anything is written locally or sent
            problem = _check_reclassify_support(api, units, opts)
            if problem:
                print(f"ERROR: {problem}", file=sys.stderr)
                return EXIT_UNSUPPORTED
        if not args.server_dry_run:
            try:
                cp = _open_checkpoint(state_path, args, fingerprint, out, api)
            except ImportErrorDetail as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return EXIT_USAGE
            out(f"Checkpoint: {state_path}")
        out(f"\n{'Server dry run against' if args.server_dry_run else 'Synchronising with'} {base}")
        try:
            for unit in units:
                outcomes.append(run_unit(api, unit, opts, cp, args.source_prefix, dry_run=args.server_dry_run, say=out))
        except KeyboardInterrupt:
            print("\nInterrupted. Nothing partial was applied; re-run with --resume to continue.", file=sys.stderr)
            return EXIT_FAILED
    print_summary(outcomes, args.deduplicate, args.server_dry_run, say=out)
    if any(o.status == "failed" for o in outcomes):
        exit_code = EXIT_FAILED
        out("\nSome lists did not complete. Completed lists are recorded in the checkpoint; fix the problem and "
            "re-run with --resume" + ("." if cp else " (a server dry run keeps no checkpoint)."))
    elif cp:
        out(f"\nAll lists confirmed by the server. The checkpoint {state_path} is kept as a record of this run "
            "(a new run without --resume replaces it).")
    if args.report_file:
        args.report_file.write_text(json.dumps({
            "importer_version": __version__, "yaml_file": str(args.yaml_file), "base_url": base,
            "deduplicate": args.deduplicate, "dry_run": args.server_dry_run,
            "units": [dict(unit_summary(o, args.deduplicate), invalid=o.invalid_full or lines_for_invalid(
                o.unit, (o.report or {}).get("invalid") or [])) for o in outcomes]}, indent=1), encoding="utf-8")
        out(f"Report written to {args.report_file}")
    return exit_code


def _open_checkpoint(path: Path, args, fingerprint: dict, out, api: Api | None = None) -> Checkpoint:
    if args.resume:
        if not path.exists():
            raise ImportErrorDetail(f"--resume requested but the checkpoint does not exist: {path}")
        cp = Checkpoint.load(path)
        if cp.data.get("fingerprint") != fingerprint:
            diff = sorted(k for k in fingerprint if cp.data.get("fingerprint", {}).get(k) != fingerprint[k])
            raise ImportErrorDetail(
                "the checkpoint does not match this input/configuration (differs in: " + ", ".join(diff) + "). "
                "Resume with exactly the same YAML file and options, or start a new import with "
                "--discard-checkpoint.")
        if cp.all_completed:
            out("The checkpoint records this import as already confirmed by the server; reporting it again.")
        return cp
    if path.exists():
        try:
            old = Checkpoint.load(path)
            finished = old.all_completed or not old.data.get("units")   # nothing was ever started
        except ImportErrorDetail:
            finished = False
        if not finished and not args.discard_checkpoint:
            raise ImportErrorDetail(
                f"an unfinished checkpoint exists: {path}. Use --resume to continue that import (the server may "
                "already hold part of it), or --discard-checkpoint to abandon it and start again.")
        if not finished and api is not None and "old" in locals():
            # free the sources: an open upload session would block the next import of the same source
            for key, rec in (old.data.get("units") or {}).items():
                if rec.get("session_id") and rec.get("status") != "completed":
                    api.abort_session(key.split("|")[0], rec["session_id"])
    return Checkpoint.create(path, fingerprint)


def _check_reclassify_support(api: Api, units: list[Unit], opts: Options) -> str | None:
    needed = {"SyncIn"} if all(choose_mode(opts, len(u.raws)) == "single" for u in units) else {"SyncIn", "SessionStart"}
    for model in sorted(needed):
        props = api.schema_properties(model)
        if props is None:
            return ("--reclassify: could not read the server's API schema (/openapi.json), so support cannot be "
                    "confirmed. Nothing was sent.")
        if "reclassify" not in props:
            return (f"--reclassify: this server's sync API has no 'reclassify' option ({model} accepts: "
                    f"{', '.join(sorted(props))}). The sync API reclassifies only new and still-pending entries, "
                    "so there is no supported way to request fresh classification of existing entries through "
                    "it. Nothing was sent. See the README, 'Server API requirements'.")
    return None


if __name__ == "__main__":
    raise SystemExit(main())
