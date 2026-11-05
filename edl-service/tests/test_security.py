"""Authentication and security review."""
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import hosts, ratelimit, security_checks
from app.config import Settings, get_settings
from app.db import AllowedHost
from conftest import KEY, bearer, login, post, put_settings

ENTRY = {"urls": ["a.example.com"]}


def submit(c, token=None, headers=None, list_name="default"):
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    return c.post(f"/v1/lists/{list_name}/entries", json=ENTRY, headers=h)


# ------------------------------------------------------------------ defaults
def test_host_authentication_enabled_by_default():
    assert Settings.model_fields["host_api_auth_enabled"].default is True
    assert Settings.model_fields["host_ip_restrictions_enabled"].default is True


def test_fresh_install_requires_authentication(client):
    assert get_settings().host_api_auth_enabled is True
    assert submit(client).status_code == 401


# ------------------------------------------------------------------ warning when disabled
def test_disabling_host_auth_shows_prominent_warning_on_every_admin_page(client):
    login(client)
    for path in ("/admin/settings", "/admin/settings/edl", "/admin/hosts", "/admin/audit"):
        assert "Host authentication is DISABLED" not in client.get(path).text
    put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
    for path in ("/admin/settings", "/admin/settings/edl", "/admin/hosts", "/admin/audit"):
        html = client.get(path).text
        assert "Host authentication is DISABLED" in html and 'banner err' in html and 'role="alert"' in html


def test_disabling_requires_confirmation(client):
    r = client.put("/v1/admin/settings", json={"values": {"host_api_auth_enabled": False}}, headers=KEY)
    assert r.status_code == 409 and "Host authentication" in r.json()["detail"]["requires_confirmation"][0]


def test_warning_disappears_when_reenabled(client):
    login(client)
    put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
    put_settings(client, {"host_api_auth_enabled": True})
    assert "DISABLED" not in client.get("/admin/settings").text


def test_ip_restrictions_off_warns(client):
    put_settings(client, {"host_ip_restrictions_enabled": False}, confirm=True)
    assert any("IP restrictions are off" in m for _, m in security_checks.system_warnings())


# ------------------------------------------------------------------ credential separation
@pytest.mark.parametrize("method,path", [("GET", "/v1/admin/settings"), ("PUT", "/v1/admin/settings"),
                                         ("GET", "/v1/admin/edl"), ("GET", "/v1/admin/audit"),
                                         ("POST", "/v1/admin/panorama/test-connection"),
                                         ("GET", "/v1/lists/default/entries"), ("POST", "/v1/lists/default/recheck"),
                                         ("DELETE", "/v1/lists/default/entries")])
def test_host_token_cannot_reach_management_endpoints(client, method, path):
    kw = {"json": {"values": {}, "urls": ["a.com"]}} if method in ("PUT", "DELETE") else {}
    for headers in (bearer(client.token), {"X-API-Key": client.token}):
        assert client.request(method, path, headers=headers, **kw).status_code == 401


def test_host_token_is_not_an_admin_ui_session(client):
    r = client.get("/admin/settings", headers=bearer(client.token), follow_redirects=False)
    assert r.status_code == 303 and "/admin/login" in r.headers["location"]


def test_management_key_cannot_authenticate_as_a_host(client):
    assert submit(client, token="k").status_code == 401                               # as bearer token
    assert submit(client, headers={"X-API-Key": "k"}).status_code == 401              # as management header
    assert submit(client, token="k", headers={"X-API-Key": "k"}).status_code == 401


def test_admin_password_is_not_a_host_token(client):
    assert submit(client, token="pw").status_code == 401


def test_management_key_not_accepted_even_when_host_auth_off_is_irrelevant_to_admin_api(client):
    put_settings(client, {"host_api_auth_enabled": False}, confirm=True)
    assert client.get("/v1/admin/settings").status_code == 401          # admin API stays protected


def test_tokens_are_stored_hashed(client):
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        assert client.token not in (h.token_hash, h.token_prefix) and len(h.token_hash) == 64


# ------------------------------------------------------------------ expired / disabled
def test_expired_host_rejected_and_future_expiry_accepted(client):
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        h.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    r = submit(client, client.token)
    assert r.status_code == 401 and "expired" in r.json()["detail"]
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        h.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        s.commit()
    assert submit(client, client.token).status_code == 200


def test_disabled_host_rejected_and_reenabled(client):
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        h.enabled = False
        s.commit()
    assert submit(client, client.token).status_code == 401
    with client.factory() as s:
        h = s.scalars(select(AllowedHost)).one()
        h.enabled = True
        s.commit()
    assert submit(client, client.token).status_code == 200


def test_expired_token_cannot_be_used_even_from_allowed_address(client):
    with client.factory() as s:
        s.scalars(select(AllowedHost)).one().expires_at = datetime.now(timezone.utc) - timedelta(days=30)
        s.commit()
    assert submit(client, client.token).status_code == 401


# ------------------------------------------------------------------ IP restrictions
@pytest.mark.parametrize("ip,code", [("10.0.0.0", 200), ("10.0.0.255", 200), ("10.0.1.0", 403), ("10.0.0.5", 200),
                                     ("192.0.2.1", 403), ("::ffff:10.0.0.7", 200), ("2001:db8::1", 403)])
def test_ip_restriction_boundaries(client, ip, code):
    other = TestClient(client.main.app, client=(ip, 1))
    assert submit(other, client.token).status_code == code


def test_valid_token_from_wrong_address_is_403_not_401(client):
    other = TestClient(client.main.app, client=("192.0.2.1", 1))
    assert submit(other, client.token).status_code == 403
    assert submit(other, "nonsense").status_code == 401


def test_forwarded_headers_cannot_spoof_the_source_address(client):
    other = TestClient(client.main.app, client=("192.0.2.77", 1))
    spoof = {"X-Forwarded-For": "10.0.0.5", "X-Real-IP": "10.0.0.5", "Forwarded": "for=10.0.0.5",
             "X-Forwarded-Host": "10.0.0.5", "True-Client-IP": "10.0.0.5", "CF-Connecting-IP": "10.0.0.5"}
    assert submit(other, client.token, headers=spoof).status_code == 403
    assert submit(client, client.token, headers={"X-Forwarded-For": "192.0.2.77"}).status_code == 200


def test_application_never_reads_forwarding_headers():
    """The trusted client address comes only from the TCP peer as resolved by uvicorn
    (FORWARDED_ALLOW_IPS). Guard against code that would trust a header directly."""
    for path in Path(__file__).resolve().parent.parent.joinpath("app").glob("*.py"):
        code = path.read_text()
        assert not re.search(r"(headers|Header)[^\n]*(x-forwarded|x_forwarded|x-real-ip|true-client-ip|cf-connecting|forwarded)",
                             code, re.I), path
        assert "x_forwarded_for" not in code.lower(), path


def test_dockerfile_uses_uvicorn_default_trust_not_wildcard():
    d = Path(__file__).resolve().parent.parent.joinpath("Dockerfile").read_text()
    assert "--proxy-headers" in d and "forwarded-allow-ips" not in d.lower()      # trust comes from FORWARDED_ALLOW_IPS only


def test_ip_restrictions_can_be_disabled(client):
    other = TestClient(client.main.app, client=("192.0.2.1", 1))
    put_settings(client, {"host_ip_restrictions_enabled": False}, confirm=True)
    assert submit(other, client.token).status_code == 200


def test_wildcard_forwarded_allow_ips_is_flagged(client, monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert security_checks.forwarded_trusts_everyone()
    login(client)
    assert "FORWARDED_ALLOW_IPS=*" in client.get("/admin/settings").text
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "172.18.0.2")
    assert not security_checks.forwarded_trusts_everyone()
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "172.18.0.2, *")
    assert security_checks.forwarded_trusts_everyone()


def test_multiple_workers_flagged(client, monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    assert any("WEB_CONCURRENCY=4" in m for _, m in security_checks.system_warnings())
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    assert not any("WEB_CONCURRENCY" in m for _, m in security_checks.system_warnings())


# ------------------------------------------------------------------ rate limiting
def test_rate_limit_is_per_host_and_effective(client):
    with client.factory() as s:
        _, other_token = hosts.create_host(s, "second", "10.0.0.0/24", "*")
    put_settings(client, {"rate_limit_requests": 3, "rate_limit_interval_seconds": 60})
    codes = [submit(client, client.token).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert submit(client, other_token).status_code == 200            # another host is unaffected


def test_rate_limit_window_expires(client, monkeypatch):
    put_settings(client, {"rate_limit_requests": 1, "rate_limit_interval_seconds": 5})
    assert submit(client, client.token).status_code == 200
    r = submit(client, client.token)
    assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 6
    import time
    real = time.monotonic
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: real() + 10)
    assert submit(client, client.token).status_code == 200


def test_rate_limit_applies_when_auth_disabled_per_source(client):
    put_settings(client, {"host_api_auth_enabled": False, "rate_limit_requests": 2}, confirm=True)
    assert [submit(client).status_code for _ in range(3)] == [200, 200, 429]


def test_failed_authentication_is_throttled_per_source(client):
    codes = [submit(client, f"guess-{i}").status_code for i in range(25)]
    assert codes[:20] == [401] * 20 and set(codes[20:]) == {429}
    assert submit(client, client.token).status_code == 429          # same source is paused briefly...
    other = TestClient(client.main.app, client=("10.0.0.99", 1))
    assert submit(other, client.token).status_code == 200            # ...but other sources are unaffected


def test_failed_attempts_from_wrong_address_also_count(client):
    other = TestClient(client.main.app, client=("192.0.2.1", 1))
    for _ in range(20):
        assert submit(other, client.token).status_code == 403
    assert submit(other, client.token).status_code == 429


def test_successful_requests_do_not_consume_the_failure_budget(client):
    for _ in range(30):
        assert submit(client, client.token).status_code == 200


def test_single_worker_documented_in_dockerfile():
    d = Path(__file__).resolve().parent.parent.joinpath("Dockerfile").read_text()
    assert "--workers" not in d and "Single worker" in d


# ------------------------------------------------------------------ size
def test_oversize_submission_rejected_before_processing(client):
    put_settings(client, {"max_submission_size": 3})
    r = client.post("/v1/lists/default/entries", json={"urls": [f"a{i}.com" for i in range(4)]},
                    headers=bearer(client.token))
    assert r.status_code == 413
