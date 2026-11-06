"""Importer logic that needs no server: canonicalisation, YAML parsing, units, deduplication, checkpoint."""
import json

import httpx
import pytest

import import_edl as imp
from conftest import yaml_doc


# ---- canonical_key -------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,key", [
    ("example.com", "example.com/"),
    ("example.com/", "example.com/"),
    ("https://Example.COM", "example.com/"),
    ("http://user:pw@example.com:8080/", "example.com/"),
    ("*.example.com", "*.example.com/"),
    ("  example.com  ", "example.com/"),
    ("example.com//", "example.com/"),                   # slashes only: still the domain root
    ("a.com/x", "a.com/x"),                              # a path is NOT given a slash
    ("a.com/x/", "a.com/x/"),                            # ... and keeps the one it has
    ("a.com/x//", "a.com/x/"),                           # repeated trailing slashes collapse to one
    ("https://a.com//x", "a.com/x"),
    ("a.com/x?utm=1", "a.com/x"),                        # query stripped
    ("a.com/x/?utm=1", "a.com/x/"),
    ("a.com/x#frag", "a.com/x"),                         # fragment stripped
    ("a.com?q=1", "a.com/"),
    ("a.com#f", "a.com/"),
    ("a.com/x?a=1#f", "a.com/x"),
    ("a.com/x#f?not-a-query", "a.com/x"),                # '#' first: everything after it is the fragment
    ("A.com/Path/Case", "a.com/path/case"),
])
def test_canonical_key_follows_server_rules(raw, key):
    assert imp.canonical_key(raw) == key


def test_path_trailing_slash_is_not_collapsed():
    assert imp.canonical_key("a.com/x") != imp.canonical_key("a.com/x/")


def test_domain_root_forms_agree():
    assert len({imp.canonical_key(x) for x in ("a.com", "a.com/", "https://a.com", "a.com?x=1", "A.COM/")}) == 1


# ---- defects fixed ---------------------------------------------------------------------------------
def test_parse_yaml_return_annotation_is_accurate():
    assert imp.parse_yaml.__annotations__["return"] == "ParsedYaml"
    assert set(imp.ParsedYaml.__dataclass_fields__) == {"lists", "blocks", "skipped_types"}


def test_401_message_includes_the_real_response_body():
    def handler(request):
        return httpx.Response(401, text="bad token xyz")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    api = imp.Api(client, "http://x", max_retries=0, log=lambda *a, **k: None)
    with pytest.raises(imp.ImportErrorDetail) as e:
        api.request("POST", "/v1/lists/a/sync", json_body={})
    assert "bad token xyz" in str(e.value) and "{response.text" not in str(e.value) and "HTTP 401" in str(e.value)


# ---- YAML ------------------------------------------------------------------------------------------
def write(tmp_path, text, name="in.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_members_are_kept_exactly_as_written_with_their_lines(tmp_path):
    p = write(tmp_path, '---\nurl:\n  - name: one\n    list:\n      member:\n        - "  A.com  "\n        - ""\n        - a.com\n')
    y = imp.parse_yaml(p)
    one = y.lists["one"]
    assert one.raws == ["  A.com  ", "a.com"]          # not stripped, not lower-cased; blank skipped
    assert one.blank == 1 and list(one.lines) == [6, 8]


def test_error_lines_for_bad_members_and_names(tmp_path):
    p = write(tmp_path, "---\nurl:\n  - name: ok\n    list:\n      member:\n        - a.com\n        - 123\n")
    with pytest.raises(imp.ImportErrorDetail, match=r"line 7: expected a string, got int"):
        imp.parse_yaml(p)
    p = write(tmp_path, "---\nurl:\n  - name: 'bad/name'\n    list: {member: [a.com]}\n", "b.yaml")
    with pytest.raises(imp.ImportErrorDetail, match=r"line 3: .*still invalid"):
        imp.parse_yaml(p)
    p = write(tmp_path, "---\nurl: [\n", "c.yaml")
    with pytest.raises(imp.ImportErrorDetail, match=r"invalid YAML at line"):
        imp.parse_yaml(p)


def test_name_whitespace_and_collision(tmp_path, capsys):
    p = write(tmp_path, yaml_doc({"Threat Feeds": ["a.com"]}))
    assert list(imp.parse_yaml(p).lists) == ["Threat_Feeds"]
    p = write(tmp_path, yaml_doc({"A B": ["a.com"], "A_B": ["b.com"]}), "d.yaml")
    with pytest.raises(imp.ImportErrorDetail, match="collision"):
        imp.parse_yaml(p)


def test_same_name_in_two_blocks_is_one_source(tmp_path):
    p = write(tmp_path, "---\nurl:\n  - name: x\n    list: {member: [a.com]}\n  - name: x\n    list: {member: [b.com]}\n")
    assert imp.parse_yaml(p).lists["x"].raws == ["a.com", "b.com"]


# ---- units and sources ------------------------------------------------------------------------------
def units(tmp_path, lists, *, dedupe=True, prefix="yaml-import", target=None, name="a.yaml"):
    return imp.build_units(imp.parse_yaml(write(tmp_path, yaml_doc(lists), name)), prefix=prefix,
                           target_list=target, deduplicate=dedupe)


def test_source_ids_are_per_yaml_list_and_independent_of_the_file_name(tmp_path):
    lists = {"threat-feeds": ["a.com"], "malware-domains": ["b.com"], "corporate-blocklist": ["c.com"]}
    one = units(tmp_path, lists, name="first.yaml")
    two = units(tmp_path, lists, name="renamed-file-2026.yaml")
    assert [u.source for u in one] == [u.source for u in two] == [
        "yaml-import:corporate-blocklist", "yaml-import:malware-domains", "yaml-import:threat-feeds"]
    assert all(u.target == u.name for u in one)


def test_target_list_merges_destination_but_not_sources(tmp_path):
    us = units(tmp_path, {"one": ["a.com"], "two": ["b.com"]}, target="default")
    assert {u.target for u in us} == {"default"} and len({u.source for u in us}) == 2


def test_custom_source_prefix_and_limits(tmp_path):
    assert units(tmp_path, {"one": ["a.com"]}, prefix="corp")[0].source == "corp:one"
    with pytest.raises(imp.ImportErrorDetail):
        units(tmp_path, {"one": ["a.com"]}, prefix="has space")
    with pytest.raises(imp.ImportErrorDetail, match="allows 100"):
        units(tmp_path, {"n" * 64: ["a.com"]}, prefix="p" * 40)


def test_dedupe_on_removes_and_counts_duplicates(tmp_path):
    u = units(tmp_path, {"l": ["a.com", "A.COM", " a.com/ ", "https://a.com", "b.com"]})[0]
    assert (u.occurrences, u.unique_local, u.duplicates_removed, len(u.raws)) == (5, 2, 3, 2)
    assert u.raws == ["a.com", "b.com"]                  # first occurrence wins, in YAML order


def test_dedupe_off_keeps_every_occurrence_untouched(tmp_path):
    members = ["a.com", "A.COM", " a.com/ ", "https://a.com", "b.com"]
    u = units(tmp_path, {"l": members}, dedupe=False)[0]
    assert u.raws == [m for m in members]                # byte for byte, including the whitespace
    assert (u.occurrences, u.unique_local, u.duplicates_removed) == (5, 2, 0)   # unique still reported


def test_path_slash_variants_are_distinct_for_dedupe(tmp_path):
    u = units(tmp_path, {"l": ["a.com/x", "a.com/x/", "a.com/x?q=1", "a.com/x#f"]})[0]
    assert u.raws == ["a.com/x", "a.com/x/"] and u.unique_local == 2


def test_chunks_are_deterministic(tmp_path):
    raws = [f"h{i}.example.com" for i in range(25)]
    assert imp.chunk_ranges(25, 10) == [(0, 10), (10, 20), (20, 25)]
    assert imp.chunk_digest(raws, 0, 10) == imp.chunk_digest(list(raws), 0, 10)
    assert imp.chunk_digest(raws, 0, 10) != imp.chunk_digest(raws, 10, 20)
    assert imp.chunk_ranges(0, 10) == []


# ---- checkpoint -------------------------------------------------------------------------------------
def test_sync_ids_are_unique_and_valid(tmp_path):
    ids = {imp.new_sync_id("yaml-import") for _ in range(200)}
    assert len(ids) == 200
    import re
    assert all(re.fullmatch(r"[A-Za-z0-9._:@/+=-]+", i) and len(i) <= 128 for i in ids)


def test_checkpoint_persists_sync_id_before_anything_is_sent(tmp_path):
    cp = imp.Checkpoint.create(tmp_path / "s.json", {"x": 1})
    rec = cp.unit("list|src", "yaml-import")
    again = imp.Checkpoint.load(tmp_path / "s.json")
    assert again.data["units"]["list|src"]["sync_id"] == rec["sync_id"]
    assert imp.Checkpoint.load(tmp_path / "s.json").unit("list|src", "yaml-import")["sync_id"] == rec["sync_id"]


def test_old_format_checkpoint_is_refused(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps({"fingerprint": {}, "completed_batches": []}))
    with pytest.raises(imp.ImportErrorDetail, match="older importer"):
        imp.Checkpoint.load(tmp_path / "old.json")
