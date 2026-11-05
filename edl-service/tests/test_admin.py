import re

from sqlalchemy import select

from app.db import AllowedHost, AppSetting
from conftest import bearer, post

CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def csrf(c, path="/admin/login"):
    return CSRF.search(c.get(path).text).group(1)


def login(c, password="pw", user="admin"):
    return c.post("/admin/login", data={"csrf_token": csrf(c), "username": user, "password": password},
                  follow_redirects=False)


def form(c, path, **data):
    return c.post(path, data={"csrf_token": csrf(c, path_for_token(path)), **data}, follow_redirects=False)


def path_for_token(path):
    return "/admin/settings" if path.startswith("/admin/settings") else "/admin/hosts"


def token_from(html):
    return re.search(r"edl_[A-Za-z0-9_-]+", html).group(0)


# ---------------------------------------------------------------- access control
def test_admin_pages_require_login(client):
    for path in ("/admin", "/admin/hosts", "/admin/settings"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"


def test_login_wrong_password_and_throttle(client):
    for _ in range(5):
        assert login(client, "nope").status_code == 401
    assert login(client, "pw").status_code == 429  # even the right password is held off


def test_login_and_logout(client):
    assert login(client).status_code == 303
    assert client.get("/admin/hosts").status_code == 200
    form(client, "/admin/logout")
    assert client.get("/admin/hosts", follow_redirects=False).status_code == 303


def test_post_without_csrf_rejected(client):
    login(client)
    r = client.post("/admin/hosts", data={"name": "x", "addresses": "10.1.1.1"}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/admin/hosts", data={"csrf_token": "wrong", "name": "x", "addresses": "10.1.1.1"})
    assert r.status_code == 403


def test_admin_responses_are_not_cacheable_and_have_csp(client):
    login(client)
    r = client.get("/admin/settings")
    assert r.headers["cache-control"] == "no-store"
    assert "script" not in r.headers["content-security-policy"].replace("default-src 'none'", "")
    assert "<script" not in r.text


# ---------------------------------------------------------------- hosts
def test_create_host_shows_token_once_and_it_works(client):
    login(client)
    r = form(client, "/admin/hosts", name="build-server", addresses="10.0.0.0/24", lists="*")
    assert r.status_code == 200
    token = token_from(r.text)

    assert client.get("/admin/hosts").text.count(token) == 0  # not shown again
    with client.factory() as s:
        row = s.scalars(select(AllowedHost).where(AllowedHost.name == "build-server")).one()
        assert token not in (row.token_hash, row.token_prefix) and row.token_prefix in token

    r = client.post("/v1/lists/default/entries", json={"urls": ["x.example.com"]}, headers=bearer(token))
    assert r.status_code == 200


def test_create_host_validation(client):
    login(client)
    for name, addr in [("ok", "0.0.0.0/0"), ("ok", "not-an-ip"), ("bad name!", "10.1.1.1"), ("ticketing", "10.1.1.1")]:
        r = form(client, "/admin/hosts", name=name, addresses=addr, lists="*")
        assert r.status_code == 422, (name, addr)
        assert "banner err" in r.text


def test_edit_host_changes_what_is_accepted(client):
    login(client)
    with client.factory() as s:
        hid = s.scalars(select(AllowedHost)).one().id
    r = form(client, f"/admin/hosts/{hid}/update", name="ticketing", addresses="192.0.2.0/24", lists="*")
    assert r.status_code == 303
    r = client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=bearer(client.token))
    assert r.status_code == 403  # our test client is 10.0.0.5, no longer allowed


def test_toggle_and_delete_host(client):
    login(client)
    with client.factory() as s:
        hid = s.scalars(select(AllowedHost)).one().id
    form(client, f"/admin/hosts/{hid}/toggle")
    r = client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]}, headers=bearer(client.token))
    assert r.status_code == 401
    form(client, f"/admin/hosts/{hid}/toggle")
    assert client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]},
                       headers=bearer(client.token)).status_code == 200
    form(client, f"/admin/hosts/{hid}/delete")
    assert client.post("/v1/lists/default/entries", json={"urls": ["b.example.com"]},
                       headers=bearer(client.token)).status_code == 401


def test_regenerate_token_invalidates_old(client):
    login(client)
    with client.factory() as s:
        hid = s.scalars(select(AllowedHost)).one().id
    new = token_from(form(client, f"/admin/hosts/{hid}/regenerate").text)
    assert new != client.token
    body = {"urls": ["a.example.com"]}
    assert client.post("/v1/lists/default/entries", json=body, headers=bearer(client.token)).status_code == 401
    assert client.post("/v1/lists/default/entries", json=body, headers=bearer(new)).status_code == 200


def test_no_hosts_means_no_posts(client):
    login(client)
    with client.factory() as s:
        hid = s.scalars(select(AllowedHost)).one().id
    form(client, f"/admin/hosts/{hid}/delete")
    assert client.post("/v1/lists/default/entries", json={"urls": ["a.example.com"]},
                       headers=bearer(client.token)).status_code == 401


# ---------------------------------------------------------------- settings
