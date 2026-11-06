#!/usr/bin/env python3
"""
Import Palo Alto-style YAML URL lists into EDL Publisher.

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

Each YAML list is imported into an EDL Publisher list with the same name unless
--target-list is supplied. Duplicate entries are removed within each target list.
The same URL in two different YAML lists is deliberately imported into both,
preserving list membership.

Requires Python 3.10+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml


LIST_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


class ImportErrorDetail(Exception):
    pass


def canonical_key(raw: str) -> str:
    """
    Conservative local key matching the application's normalisation rules.
    The server remains authoritative for validation and final deduplication.
    """
    value = raw.strip().lower()
    value = SCHEME_RE.sub("", value)
    value = value.split("#", 1)[0].split("?", 1)[0]
    host, _, path = value.partition("/")
    host = host.rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host).strip(".")
    path = path.strip("/")
    return f"{host}/{path}" if path else host


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_yaml(path: Path) -> tuple[dict[str, list[str]], dict[str, str], int]:
    """Return target-list -> members, descriptions, and number of YAML list blocks."""
    lists: dict[str, list[str]] = defaultdict(list)
    descriptions: dict[str, str] = {}
    block_count = 0
    original_names: dict[str, str] = {}

    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            documents = yaml.safe_load_all(stream)
            for doc_no, doc in enumerate(documents, start=1):
                if doc is None:
                    continue
                if not isinstance(doc, dict):
                    raise ImportErrorDetail(f"YAML document {doc_no}: expected a mapping at the document root")
                url_section = doc.get("url", [])
                if isinstance(url_section, dict):
                    url_blocks = [url_section]
                elif isinstance(url_section, list):
                    url_blocks = url_section
                elif url_section in (None, []):
                    continue
                else:
                    raise ImportErrorDetail(
                        f"YAML document {doc_no}: 'url' must be a list or mapping"
                    )

                for block_no, item in enumerate(url_blocks, start=1):
                    block_count += 1
                    if not isinstance(item, dict):
                        raise ImportErrorDetail(
                            f"YAML document {doc_no}, url item {block_no}: expected a mapping"
                        )
                    original_name = str(item.get("name", "")).strip()
                    if not original_name:
                        raise ImportErrorDetail(
                            f"YAML document {doc_no}, url item {block_no}: missing 'name'"
                        )

                    # Convert each contiguous whitespace run to one underscore.
                    name = re.sub(r"\s+", "_", original_name)
                    if name != original_name:
                        print(
                            f"List name normalised: {original_name!r} -> {name!r}",
                            file=sys.stderr,
                        )

                    if not LIST_NAME_RE.fullmatch(name):
                        raise ImportErrorDetail(
                            f"YAML list name {original_name!r} becomes {name!r}, which is "
                            "still invalid for EDL Publisher. After whitespace replacement, "
                            "names must contain only letters, digits, underscores or hyphens "
                            "and be 1-64 characters long. Use --target-list to map all YAML "
                            "lists into one valid EDL."
                        )

                    previous_original = original_names.get(name)
                    if previous_original is not None and previous_original != original_name:
                        raise ImportErrorDetail(
                            f"YAML list-name collision: {previous_original!r} and "
                            f"{original_name!r} both become {name!r} after whitespace "
                            "replacement. Rename one of the YAML lists or use --target-list "
                            "if you intentionally want to combine them."
                        )
                    original_names[name] = original_name

                    list_type = str(item.get("type", "URL List")).strip().lower()
                    if list_type not in ("url list", "url"):
                        print(
                            f"Warning: skipping YAML list {name!r} with unsupported type "
                            f"{item.get('type')!r}",
                            file=sys.stderr,
                        )
                        continue

                    list_obj = item.get("list") or {}
                    if not isinstance(list_obj, dict):
                        raise ImportErrorDetail(f"YAML list {name!r}: 'list' must be a mapping")
                    members = list_obj.get("member", [])
                    if members is None:
                        members = []
                    if isinstance(members, str):
                        members = [members]
                    if not isinstance(members, list):
                        raise ImportErrorDetail(
                            f"YAML list {name!r}: 'list.member' must be a list of strings"
                        )

                    desc = str(item.get("description", "") or "").strip()
                    if desc:
                        descriptions.setdefault(name, desc)

                    for member_no, member in enumerate(members, start=1):
                        if not isinstance(member, str):
                            raise ImportErrorDetail(
                                f"YAML list {name!r}, member {member_no}: expected a string, "
                                f"got {type(member).__name__}"
                            )
                        if member.strip():
                            lists[name].append(member.strip())
    except yaml.YAMLError as exc:
        raise ImportErrorDetail(f"invalid YAML: {exc}") from exc

    return dict(lists), descriptions, block_count


def prepare_lists(raw_lists: dict[str, list[str]], target_list: str | None):
    """Deduplicate within each target list and calculate cross-list overlaps."""
    prepared: dict[str, list[str]] = {}
    raw_counts: dict[str, int] = {}
    duplicate_counts: dict[str, int] = {}
    global_membership: dict[str, set[str]] = defaultdict(set)

    for yaml_name, members in raw_lists.items():
        target = target_list or yaml_name
        if not LIST_NAME_RE.fullmatch(target):
            raise ImportErrorDetail(
                f"target list {target!r} is invalid; use letters, digits, '_' or '-' (max 64)"
            )
        unique: list[str] = []
        seen: set[str] = set()
        for raw in members:
            key = canonical_key(raw)
            if key in seen:
                continue
            seen.add(key)
            unique.append(raw)
            global_membership[key].add(target)
        raw_counts[target] = raw_counts.get(target, 0) + len(members)
        duplicate_counts[target] = duplicate_counts.get(target, 0) + (len(members) - len(unique))
        prepared.setdefault(target, []).extend(unique)

    # If multiple YAML blocks map to one target list, deduplicate again across blocks.
    for target, values in list(prepared.items()):
        seen: set[str] = set()
        deduped: list[str] = []
        for raw in values:
            key = canonical_key(raw)
            if key not in seen:
                seen.add(key)
                deduped.append(raw)
        duplicate_counts[target] += len(values) - len(deduped)
        prepared[target] = deduped

    overlap_keys = sum(1 for names in global_membership.values() if len(names) > 1)
    return prepared, raw_counts, duplicate_counts, overlap_keys


def batches(items: list[str], size: int):
    for start in range(0, len(items), size):
        yield start // size, items[start:start + size]


def retry_after(response: httpx.Response | None, attempt: int) -> float:
    if response is not None:
        value = response.headers.get("Retry-After")
        if value:
            try:
                return min(120.0, max(1.0, float(value)))
            except ValueError:
                pass
    return min(60.0, 2.0 ** attempt)


def load_or_create_state(
    state_path: Path,
    *,
    resume: bool,
    fingerprint: dict[str, Any],
) -> dict[str, Any]:
    if resume:
        if not state_path.exists():
            raise ImportErrorDetail(f"--resume requested but state file does not exist: {state_path}")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("fingerprint") != fingerprint:
            raise ImportErrorDetail(
                "resume state does not match this input/configuration. "
                "Use the same YAML file, API URL, target-list, source label and batch size."
            )
        state.setdefault("completed_batches", [])
        state.setdefault("totals", {})
        return state

    if state_path.exists():
        raise ImportErrorDetail(
            f"state file already exists: {state_path}. Use --resume to continue, "
            "or move/delete it to start a fresh import."
        )
    state = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint,
        "completed_batches": [],
        "totals": {},
    }
    save_state(state_path, state)
    return state


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temp.replace(path)


def batch_key(list_name: str, urls: list[str]) -> str:
    digest = hashlib.sha256(("\n".join(urls)).encode("utf-8")).hexdigest()
    return f"{list_name}:{digest}"


def submit_batch(
    client: httpx.Client,
    base_url: str,
    token: str,
    list_name: str,
    urls: list[str],
    source: str,
    state_path: Path,
    state: dict[str, Any],
    stats: Counter,
    *,
    max_retries: int,
    split_422: bool = True,
) -> None:
    key = batch_key(list_name, urls)
    completed = set(state["completed_batches"])
    if key in completed:
        stats["resumed_batches_skipped"] += 1
        return

    endpoint = f"{base_url.rstrip('/')}/v1/lists/{list_name}/entries"
    payload = {"urls": urls, "source": source}
    response: httpx.Response | None = None

    for attempt in range(max_retries + 1):
        try:
            response = client.post(endpoint, json=payload)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            if attempt >= max_retries:
                raise ImportErrorDetail(
                    f"network failure submitting list {list_name!r}: {type(exc).__name__}"
                ) from exc
            delay = retry_after(None, attempt)
            print(f"  transient network error; retrying in {delay:.0f}s", file=sys.stderr)
            time.sleep(delay)
            continue

        if response.status_code in (429, 500, 502, 503, 504):
            if attempt >= max_retries:
                raise ImportErrorDetail(
                    f"server returned HTTP {response.status_code} for list {list_name!r}: "
                    f"{response.text[:500]}"
                )
            delay = retry_after(response, attempt)
            print(f"  HTTP {response.status_code}; retrying in {delay:.0f}s", file=sys.stderr)
            time.sleep(delay)
            continue
        break

    if response is None:
        raise ImportErrorDetail(f"no response received for list {list_name!r}")

    if response.status_code in (401, 403):
        raise ImportErrorDetail(
            f"HTTP {response.status_code} for list {list_name!r}. Check the host token, "
            "allowed source IP and permitted-list configuration. Response: {response.text[:500]}"
        )

    # A 413 or 422 may be caused by one problematic URL in an otherwise valid batch.
    # Split recursively so good entries can still be imported; a singleton failure is recorded.
    if response.status_code in (413, 422) and len(urls) > 1 and split_422:
        mid = len(urls) // 2
        stats["split_batches"] += 1
        submit_batch(client, base_url, token, list_name, urls[:mid], source,
                     state_path, state, stats, max_retries=max_retries)
        submit_batch(client, base_url, token, list_name, urls[mid:], source,
                     state_path, state, stats, max_retries=max_retries)
        return

    if response.status_code == 422:
        stats["rejected_entries"] += len(urls)
        stats["http_422_batches"] += 1
        stats["errors"].append({
            "list": list_name,
            "urls": urls,
            "status_code": 422,
            "detail": response.text[:1000],
        })
        print(f"  rejected one URL in {list_name!r}: {urls[0]!r} ({response.text[:250]})",
              file=sys.stderr)
        return

    if response.status_code == 413:
        raise ImportErrorDetail(
            f"HTTP 413 for a single entry in list {list_name!r}: {urls[0]!r}"
        )

    if response.status_code != 200:
        raise ImportErrorDetail(
            f"unexpected HTTP {response.status_code} for list {list_name!r}: {response.text[:500]}"
        )

    try:
        data = response.json()
        results = data["results"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ImportErrorDetail(
            f"unexpected response from list {list_name!r}: {response.text[:500]}"
        ) from exc

    batch_totals: Counter = Counter()
    for result in results:
        status = str(result.get("status", "unknown"))
        batch_totals[f"api_{status}"] += 1
        if status == "invalid":
            batch_totals["invalid_entries"] += 1
        elif status in ("blocked", "pending"):
            batch_totals[f"not_published_{status}"] += 1
        elif status == "added":
            batch_totals["added_entries"] += 1
        elif status == "duplicate":
            batch_totals["duplicate_entries_server"] += 1

    batch_totals["submitted_batches"] += 1
    batch_totals["submitted_urls"] += len(urls)
    for metric, count in batch_totals.items():
        stats[metric] += count
        state.setdefault("totals", {})[metric] = (
            int(state.setdefault("totals", {}).get(metric, 0)) + count
        )

    state["completed_batches"].append(key)
    save_state(state_path, state)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import Palo Alto YAML URL lists into EDL Publisher."
    )
    parser.add_argument("yaml_file", type=Path, help="YAML file containing one or more url lists")
    parser.add_argument("--base-url", default=os.getenv("EDL_BASE_URL"),
                        help="Application base URL, e.g. https://edl.example.net "
                             "(or EDL_BASE_URL)")
    parser.add_argument("--token", default=os.getenv("EDL_HOST_TOKEN"),
                        help="Allowed host bearer token (or EDL_HOST_TOKEN)")
    parser.add_argument("--target-list",
                        help="Import all YAML lists into this one EDL list instead of preserving names")
    parser.add_argument("--source", default="yaml-import",
                        help="Source label recorded alongside the host name (default: yaml-import)")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="URLs per API request (default: 500; must not exceed app's max submission size)")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds")
    parser.add_argument("--max-retries", type=int, default=5, help="Retries for transient failures")
    parser.add_argument("--state-file", type=Path,
                        help="Checkpoint file (default: <yaml_file>.import-state.json)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from a matching checkpoint")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and report counts without contacting the application")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (not recommended)")
    args = parser.parse_args()

    if args.batch_size < 1 or args.batch_size > 100000:
        parser.error("--batch-size must be between 1 and 100000")
    if args.max_retries < 0:
        parser.error("--max-retries cannot be negative")
    if not args.base_url and not args.dry_run:
        parser.error("--base-url or EDL_BASE_URL is required")
    if not args.token and not args.dry_run:
        parser.error("--token or EDL_HOST_TOKEN is required")
    if len(args.source) > 63:
        parser.error("--source must be 63 characters or fewer (combined host:source max is 128)")

    path = args.yaml_file
    if not path.is_file():
        parser.error(f"YAML file does not exist: {path}")

    try:
        raw_lists, descriptions, yaml_blocks = parse_yaml(path)
        prepared, raw_counts, local_duplicates, cross_list_overlaps = prepare_lists(
            raw_lists, args.target_list
        )
    except ImportErrorDetail as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"YAML documents/lists parsed: {yaml_blocks}")
    print(f"Target EDL lists: {len(prepared)}")
    total_raw = sum(raw_counts.values())
    total_unique = sum(len(v) for v in prepared.values())
    print(f"Entries before local deduplication: {total_raw:,}")
    print(f"Entries after local deduplication:  {total_unique:,}")
    print(f"Local duplicates removed:          {sum(local_duplicates.values()):,}")
    print(f"Canonical entries shared across lists: {cross_list_overlaps:,}")
    for name in sorted(prepared):
        print(
            f"  {name}: {len(prepared[name]):,} unique "
            f"(from {raw_counts.get(name, 0):,} source rows)"
        )
        if descriptions.get(name):
            print(f"    description: {descriptions[name]}")

    if args.dry_run:
        print("\nDry run complete; nothing was submitted.")
        return 0

    state_path = args.state_file or Path(str(path) + ".import-state.json")
    fingerprint = {
        "input_sha256": sha256_file(path),
        "base_url": args.base_url.rstrip("/"),
        "target_list": args.target_list,
        "source": args.source,
        "batch_size": args.batch_size,
    }
    try:
        state = load_or_create_state(state_path, resume=args.resume, fingerprint=fingerprint)
    except (ImportErrorDetail, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    stats: Counter = Counter(state.get("totals", {}))
    stats["errors"] = []
    headers = {"Authorization": f"Bearer {args.token}"}
    verify: bool | str = not args.insecure

    print(f"\nSubmitting to {args.base_url.rstrip('/')}")
    print(f"Checkpoint: {state_path}")
    if args.insecure:
        print("WARNING: TLS certificate verification is disabled.", file=sys.stderr)

    try:
        with httpx.Client(headers=headers, timeout=args.timeout, verify=verify) as client:
            for list_name in sorted(prepared):
                values = prepared[list_name]
                print(f"\n[{list_name}] {len(values):,} entries")
                total_batches = (len(values) + args.batch_size - 1) // args.batch_size
                for batch_no, chunk in batches(values, args.batch_size):
                    before = stats["submitted_urls"]
                    submit_batch(
                        client, args.base_url, args.token, list_name, chunk, args.source,
                        state_path, state, stats, max_retries=args.max_retries,
                    )
                    done = min((batch_no + 1) * args.batch_size, len(values))
                    print(
                        f"  progress {done:,}/{len(values):,} "
                        f"({(done / max(1, len(values)) * 100):.1f}%) "
                        f"| API batches {stats['submitted_batches']:,} "
                        f"| resumed skips {stats['resumed_batches_skipped']:,}"
                    )
    except (ImportErrorDetail, httpx.HTTPError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        print("Successful batches are checkpointed. Re-run with --resume to continue.", file=sys.stderr)
        return 1

    print("\nImport summary")
    print(f"  API batches submitted:          {stats['submitted_batches']:,}")
    print(f"  API batches skipped on resume:  {stats['resumed_batches_skipped']:,}")
    print(f"  URLs submitted:                 {stats['submitted_urls']:,}")
    print(f"  Added:                          {stats['added_entries']:,}")
    print(f"  Duplicates reported by server:  {stats['duplicate_entries_server']:,}")
    print(f"  Invalid per-URL results:        {stats['invalid_entries']:,}")
    print(f"  Blocked by policy:              {stats['not_published_blocked']:,}")
    print(f"  Pending classification:         {stats['not_published_pending']:,}")
    print(f"  Rejected oversized entries:     {stats['rejected_entries']:,}")
    print(f"  Batches split after 413/422:    {stats['split_batches']:,}")
    print(f"  Checkpoint:                     {state_path}")

    if stats["errors"]:
        report_path = Path(str(state_path) + ".errors.json")
        report_path.write_text(json.dumps(stats["errors"], indent=2), encoding="utf-8")
        print(f"  Error report:                   {report_path}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
