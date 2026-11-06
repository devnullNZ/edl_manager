"""Public Suffix List validation of wildcards, and shadowing semantics."""
import pytest
from sqlalchemy import select

from app import service
from app.db import Entry
from app.normalize import normalize
from app.psl import is_public_suffix
from app.shadow import compute_shadows
from conftest import KEY, apex_policy, feed, post


@pytest.mark.parametrize("entry", ["*.com", "*.net", "*.co.uk", "*.com.au", "*.org.au", "*.gov.uk",
                                   "*.github.io", "*.blogspot.com", "*.internal", "*.COM", "*.com.",
                                   "https://*.com/path", "*.com:443"])
def test_wildcards_over_public_suffixes_rejected(entry):
    with pytest.raises(ValueError, match="public suffix"):
        normalize(entry)


@pytest.mark.parametrize("entry,expected", [
    ("*.example.com", "*.example.com/"),
    ("*.example.com.au", "*.example.com.au/"),
    ("*.sub.example.com", "*.sub.example.com/"),
    ("*.EXAMPLE.co.uk", "*.example.co.uk/"),
    ("*.corp.internal", "*.corp.internal/"),
    ("https://*.example.com/", "*.example.com/"),
    ("*.example.com/path", "*.example.com/path"),
])
def test_legitimate_wildcards_accepted(entry, expected):
    assert normalize(entry) == expected


@pytest.mark.parametrize("entry", ["com", "co.uk", "github.io", "example.com", "a.b.example.com.au"])
def test_non_wildcard_entries_are_not_subject_to_suffix_rule(entry):
    assert normalize(entry) == entry + "/"      # only wildcards are restricted


def test_is_public_suffix():
    assert is_public_suffix("com") and is_public_suffix("co.uk") and is_public_suffix("com.au")
    assert not is_public_suffix("example.com") and not is_public_suffix("example.com.au")
    assert not is_public_suffix("")


def test_psl_exception_rules_respected():
    # PSL rule "*.ck" with exception "!www.ck": www.ck is registrable, so a wildcard on it is fine
    assert not is_public_suffix("www.ck")
    assert is_public_suffix("foo.ck")


# ------------------------------------------------------------------ shadowing (original requirements)
def test_subdomain_shadowed_by_wildcard():
    assert compute_shadows({"1.example.com/", "*.example.com/"}) == {"1.example.com/": "*.example.com/"}


def test_apex_not_shadowed_by_its_own_wildcard():
    assert compute_shadows({"example.com/", "*.example.com/"}) == {}


def test_siblings_do_not_shadow_each_other():
    assert compute_shadows({"a.example.com/", "b.example.com/"}) == {}


def test_narrower_wildcard_shadowed_by_wider():
    assert compute_shadows({"*.sub.example.com/", "*.example.com/"}) == {"*.sub.example.com/": "*.example.com/"}


def test_deep_subdomain_and_nearest_wildcard_reported():
    s = compute_shadows({"a.b.example.com/", "*.b.example.com/", "*.example.com/"})
    assert s["a.b.example.com/"] == "*.b.example.com/" and s["*.b.example.com/"] == "*.example.com/"


def test_wildcard_with_path_only_covers_same_path():
    s = compute_shadows({"a.example.com/x", "a.example.com/y", "*.example.com/x"})
    assert s == {"a.example.com/x": "*.example.com/x"}


def test_unrelated_domains_untouched():
    assert compute_shadows({"example.com/", "*.example.org/", "badexample.com/", "x.badexample.com/"}) == {}


def test_suffix_lookalike_is_not_a_shadow():
    assert compute_shadows({"notexample.com/", "*.example.com/"}) == {}


# ------------------------------------------------------------------ through the API
def test_api_rejects_suffix_wildcards_with_reason(client):
    out = post(client, ["*.com", "*.co.uk", "*.example.com.au"])
    by = {r["url"]: r for r in out["results"]}
    assert by["*.com"]["status"] == "invalid" and "public suffix" in by["*.com"]["detail"]
    assert by["*.co.uk"]["status"] == "invalid"
    assert by["*.example.com.au"]["status"] != "invalid"


def test_rejected_wildcards_are_not_stored(client):
    post(client, ["*.com"])
    with client.factory() as s:
        assert s.scalars(select(Entry).where(Entry.value == "*.com/")).first() is None


def test_feed_semantics_end_to_end(client):
    apex_policy(client)
    post(client, ["example.com", "*.example.com", "1.example.com", "*.sub.example.com", "b.other.org",
                  "a.other.org"])
    assert feed(client).text.splitlines() == ["*.example.com/", "a.other.org/", "b.other.org/", "example.com/"]


# ------------------------------------------------------------------ legacy data
def test_stored_suffix_wildcard_is_quarantined_not_deleted(client):
    apex_policy(client)
    with client.factory() as s:
        s.add(Entry(list_name="default", value="*.com/", status="active"))
        s.add(Entry(list_name="default", value="ok.example.net/", status="active"))
        s.commit()
        counts = service.reconcile_wildcards(s)
        assert counts["public_suffix"] == 1
        row = s.scalars(select(Entry).where(Entry.value == "*.com/")).one()      # still there
        assert row.status == "blocked" and "public suffix" in row.detail
    assert feed(client).text.splitlines() == ["ok.example.net/"]                  # and not published/shadowing
    client.post("/v1/lists/default/recheck", headers=KEY)                         # recheck cannot revive it
    assert feed(client).text.splitlines() == ["ok.example.net/"]


def test_startup_quarantines_legacy_suffix_wildcards(client):
    apex_policy(client)
    with client.factory() as s:
        s.add(Entry(list_name="default", value="*.net/", status="active"))
        s.commit()
    client.main.init_app(client.engine, client.factory)
    with client.factory() as s:
        assert s.scalars(select(Entry).where(Entry.value == "*.net/")).one().status == "blocked"
