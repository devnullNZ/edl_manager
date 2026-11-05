import pytest

from app.normalize import normalize
from app.panorama import evaluate, lookup_target
from app.shadow import compute_shadows


@pytest.mark.parametrize("raw,expected", [
    ("HTTPS://Example.COM/", "example.com"),
    ("http://user:pw@www.example.com:8080/a/b/?q=1#frag", "www.example.com/a/b"),
    ("*.Example.com", "*.example.com"),
    ("example.com.", "example.com"),
    ("  example.com/path/  ", "example.com/path"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "*.", "a.*.com", "exa mple.com", "-bad.com", "http:///x"])
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):
        normalize(raw)


def test_wildcard_shadows_subdomains():
    got = compute_shadows(["*.example.com", "1.example.com", "a.b.example.com"])
    assert got == {"1.example.com": "*.example.com", "a.b.example.com": "*.example.com"}


def test_apex_and_wildcard_both_kept():
    assert compute_shadows(["example.com", "*.example.com"]) == {}


def test_nested_wildcard_shadowed_by_parent_wildcard():
    got = compute_shadows(["*.a.example.com", "*.example.com"])
    assert got == {"*.a.example.com": "*.example.com"}


def test_nearest_wildcard_reported():
    got = compute_shadows(["*.example.com", "*.b.example.com", "x.b.example.com"])
    assert got["x.b.example.com"] == "*.b.example.com"


def test_path_entries():
    # wildcard without path covers any path; wildcard with same path covers that path only
    assert compute_shadows(["*.example.com", "a.example.com/x"]) == {"a.example.com/x": "*.example.com"}
    assert compute_shadows(["*.example.com/x", "a.example.com/x", "a.example.com/y"]) == {
        "a.example.com/x": "*.example.com/x"}
    # host-only entry does not shadow path entries on the same host
    assert compute_shadows(["example.com", "example.com/x"]) == {}


def test_unrelated_suffix_not_shadowed():
    assert compute_shadows(["*.example.com", "notexample.com", "example.com.evil.net"]) == {}


def test_lookup_target():
    assert lookup_target("*.example.com") == "example.com"
    assert lookup_target("www.example.com/a") == "www.example.com/a"


BLOCKED = {"malware", "phishing"}


def test_evaluate_hits_category():
    raw = "bad.example.net malware (Cloud db) expires in 3600 seconds"
    assert evaluate(raw, "bad.example.net", BLOCKED) == ["malware"]


def test_evaluate_ignores_name_in_hostname():
    raw = "malware.example.com computer-and-internet-info (Base db)"
    assert evaluate(raw, "malware.example.com", BLOCKED) == []


def test_evaluate_clean():
    assert evaluate("example.com search-engines (Base db)", "example.com", BLOCKED) == []
