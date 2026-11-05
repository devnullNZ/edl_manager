import pytest
from fastapi.testclient import TestClient

from app import hosts
from conftest import apex_policy, KEY, bearer, post


# ---------------------------------------------------------------- core behaviour
def test_dedupe_shadow_and_category(client):
    apex_policy(client)
    out = post(client, ["https://Example.com/", "example.com", "*.example.com", "1.example.com",
                        "bad.evil.net", "not a url!"])
    by = {r["url"]: r for r in out["results"]}
    assert by["https://Example.com/"]["status"] == "added"
    assert by["example.com"]["status"] == "duplicate"
    assert by["*.example.com"]["status"] == "added"
    assert by["1.example.com"]["published"] is False
    assert by["1.example.com"]["shadowed_by"] == "*.example.com"
    assert by["bad.evil.net"]["status"] == "blocked"
    assert by["not a url!"]["status"] == "invalid"

    assert client.get("/edl/default").text.splitlines() == ["*.example.com", "example.com"]

    n = len(client.fake.calls)
    again = post(client, ["example.com", "bad.evil.net"])
    assert {r["status"] for r in again["results"]} == {"duplicate"}
    assert len(client.fake.calls) == n


def test_removing_wildcard_unshadows(client):
    apex_policy(client)
    post(client, ["*.example.com", "1.example.com"])
    assert client.get("/edl/default").text.splitlines() == ["*.example.com"]
    r = client.request("DELETE", "/v1/lists/default/entries", json={"urls": ["*.example.com"]}, headers=KEY)
    assert r.json() == {"deleted": 1}
    assert client.get("/edl/default").text.splitlines() == ["1.example.com"]


def test_panorama_failure_is_pending_not_published_then_recovers(client):
    client.fake.fail.add("flaky.com")
    assert post(client, ["flaky.com"])["results"][0]["status"] == "pending"
    assert client.get("/edl/default").text == ""

    client.fake.fail.clear()
    r = client.post("/v1/lists/default/recheck", headers=KEY)
    assert r.json() == {"checked": 1, "changed": 1}
    assert client.get("/edl/default").text.splitlines() == ["flaky.com"]


def test_recheck_pulls_entry_that_became_malicious(client):
    post(client, ["turned.bad.com"])
    assert client.get("/edl/default").text.splitlines() == ["turned.bad.com"]
    client.fake.lookup = lambda t: f"{t} malware (Cloud db)"
    client.post("/v1/lists/default/recheck", headers=KEY)
    assert client.get("/edl/default").text == ""


def test_wildcard_checked_by_base_domain(client):
    apex_policy(client)
    post(client, ["*.bad.net"])
    assert client.fake.calls == ["bad.net"]


# ---------------------------------------------------------------- management API key
def test_management_endpoints_need_api_key(client):
    assert client.get("/v1/lists/default/entries").status_code == 401
    assert client.get("/v1/lists/default/entries", headers=bearer(client.token)).status_code == 401
    assert client.get("/v1/lists/default/entries", headers=KEY).status_code == 200


# ---------------------------------------------------------------- host-level auth on POST
def _raw_post(c, headers=None, list_name="default"):
    return c.post(f"/v1/lists/{list_name}/entries", json={"urls": ["a.example.com"]}, headers=headers or {})


def test_post_without_token_rejected(client):
    assert _raw_post(client).status_code == 401


def test_post_with_global_api_key_is_not_enough(client):
    assert _raw_post(client, KEY).status_code == 401


def test_post_with_unknown_token_rejected(client):
    assert _raw_post(client, bearer("edl_nope")).status_code == 401


def test_post_from_wrong_address_rejected(client):
    other = TestClient(client.main.app, client=("192.0.2.9", 1))
    r = _raw_post(other, bearer(client.token))
    assert r.status_code == 403
    assert client.get("/edl/default").text == ""


def test_post_from_non_ip_client_rejected(client):
    other = TestClient(client.main.app)  # starlette reports the client as "testclient"
    assert _raw_post(other, bearer(client.token)).status_code == 403


def test_ipv4_mapped_ipv6_source_is_matched(client):
    other = TestClient(client.main.app, client=("::ffff:10.0.0.7", 1))
    assert _raw_post(other, bearer(client.token)).status_code == 200


def test_disabled_host_rejected(client):
    with client.factory() as s:
        host = s.query(hosts.AllowedHost).one()
        host.enabled = False
        s.commit()
    assert _raw_post(client, bearer(client.token)).status_code == 401


def test_list_restriction(client):
    with client.factory() as s:
        s.query(hosts.AllowedHost).one().lists = "ops, staging"
        s.commit()
    assert _raw_post(client, bearer(client.token), "ops").status_code == 200
    assert _raw_post(client, bearer(client.token), "default").status_code == 403


def test_source_attribution_and_last_used(client):
    post(client, ["a.example.com"], source="ticket-9")
    entry = client.get("/v1/lists/default/entries", headers=KEY).json()["entries"][0]
    assert entry["source"] == "ticketing:ticket-9"
    with client.factory() as s:
        host = s.query(hosts.AllowedHost).one()
        assert host.last_ip == "10.0.0.5" and host.last_used_at is not None


def test_token_stored_hashed(client):
    with client.factory() as s:
        host = s.query(hosts.AllowedHost).one()
        assert client.token not in (host.token_hash, host.token_prefix)
        assert host.token_hash == hosts.hash_token(client.token)


# ---------------------------------------------------------------- address parsing
@pytest.mark.parametrize("text,expected", [
    ("10.0.0.1", "10.0.0.1/32"),
    ("10.0.0.0/24, 2001:db8::/32", "10.0.0.0/24, 2001:db8::/32"),
    ("10.0.0.1\n10.0.0.2", "10.0.0.1/32, 10.0.0.2/32"),
    ("10.0.0.5/24", "10.0.0.0/24"),
])
def test_normalize_addresses(text, expected):
    assert hosts.normalize_addresses(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "example.com", "300.1.1.1", "0.0.0.0/0", "::/0", "10.0.0.1, nope"])
def test_bad_addresses_rejected(text):
    with pytest.raises(ValueError):
        hosts.normalize_addresses(text)


def test_normalize_lists():
    assert hosts.normalize_lists("") == "*"
    assert hosts.normalize_lists("a, b a") == "a, b"
    assert hosts.normalize_lists("a, *") == "*"
    with pytest.raises(ValueError):
        hosts.normalize_lists("bad/name")
