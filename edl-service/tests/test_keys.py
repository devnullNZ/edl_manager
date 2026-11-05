"""Encryption key management: stability, wrong keys, rotation, recovery, no leaks."""
import io
import logging
from contextlib import redirect_stdout

import pytest
from sqlalchemy import select

from app import keytool, security_checks, settings_store
from app.config import get_bootstrap, get_settings
from app.db import AppSetting
from conftest import KEY, login, put_settings

SECRET = "PAN-API-KEY-super-secret-value-0123456789"
KEY_A = "key-A-" + "a" * 30
KEY_B = "key-B-" + "b" * 30
KEY_C = "key-C-" + "c" * 30


@pytest.fixture
def keys(client, monkeypatch):
    """Switch bootstrap keys on the fly (the bootstrap object is read at each use)."""
    b = get_bootstrap()

    def set_keys(current, previous=""):
        monkeypatch.setattr(b, "encryption_key", current)
        monkeypatch.setattr(b, "encryption_key_previous", previous)

    set_keys(KEY_A)
    return set_keys


def raw(client, key="panorama_api_key"):
    with client.factory() as s:
        return s.get(AppSetting, key).value


def restart(client):
    client.main.init_app(client.engine, client.factory)


def store_secret(client):
    put_settings(client, {"panorama_api_key": SECRET})
    assert get_settings().panorama_api_key == SECRET


# ------------------------------------------------------------------ missing / invalid keys
def test_missing_key_gives_actionable_error(monkeypatch):
    monkeypatch.setattr(get_bootstrap(), "encryption_key", "")
    with pytest.raises(settings_store.EncryptionConfigError) as e:
        settings_store.check_encryption_config()
    msg = str(e.value)
    assert "ENCRYPTION_KEY is not set" in msg and "secrets.token_urlsafe" in msg and "stay the same" in msg


def test_short_key_rejected_with_rotation_hint(monkeypatch):
    monkeypatch.setattr(get_bootstrap(), "encryption_key", "short")
    with pytest.raises(settings_store.EncryptionConfigError, match="too short.*ENCRYPTION_KEY_PREVIOUS"):
        settings_store.check_encryption_config()


def test_encrypt_without_key_fails_clearly(monkeypatch):
    monkeypatch.setattr(get_bootstrap(), "encryption_key", "")
    with pytest.raises(settings_store.EncryptionConfigError):
        settings_store.encrypt("x")


def test_app_refuses_to_start_without_key(monkeypatch):
    import asyncio
    from app import main
    monkeypatch.setattr(get_bootstrap(), "encryption_key", "")

    async def go():
        async with main.lifespan(main.app):
            pass
    with pytest.raises(settings_store.EncryptionConfigError, match="ENCRYPTION_KEY is not set"):
        asyncio.run(go())


# ------------------------------------------------------------------ wrong key
def test_wrong_key_marks_secret_unreadable_and_never_overwrites(client, keys, caplog):
    store_secret(client)
    before = raw(client)
    keys(KEY_B)                                            # operator restarts with the wrong key
    caplog.set_level(logging.DEBUG)
    restart(client)

    assert raw(client) == before                           # not overwritten, not re-encrypted, not blanked
    assert settings_store.secret_problems() == ["panorama_api_key"]
    assert not get_settings().panorama_api_key             # unusable, not guessed
    assert any("cannot be decrypted" in r.getMessage() and "re-enter" in r.getMessage() for r in caplog.records)
    assert SECRET not in caplog.text and before not in caplog.text

    # saving unrelated settings must not touch the unreadable secret
    put_settings(client, {"max_batch_size": 33})
    assert raw(client) == before
    # a Panorama form saved with the secret left blank is refused (live mode needs a key); still untouched
    put_settings(client, {"panorama_api_key": "", "panorama_port": 444}, section="panorama", expect=422)
    assert raw(client) == before


def test_wrong_key_is_visible_to_administrators(client, keys):
    store_secret(client)
    keys(KEY_B)
    restart(client)
    assert client.get("/healthz").json()["secrets"] == "unreadable"
    item = next(x for x in client.get("/v1/admin/settings/panorama", headers=KEY).json()["settings"]
                if x["key"] == "panorama_api_key")
    assert item["status"] == "unreadable" and item["configured"] is True and item["value"] is None
    login(client)
    page = client.get("/admin/settings/panorama").text
    assert "cannot be decrypted" in page and SECRET not in page


def test_restoring_the_original_key_recovers_everything(client, keys):
    store_secret(client)
    keys(KEY_B)
    restart(client)
    keys(KEY_A)
    restart(client)
    assert get_settings().panorama_api_key == SECRET and not settings_store.secret_problems()


def test_lost_key_recovery_by_reentering_secret(client, keys):
    """Documented recovery: the key is gone for good -> set a new ENCRYPTION_KEY, restart, re-enter."""
    store_secret(client)
    old = raw(client)
    keys(KEY_C)
    restart(client)
    assert settings_store.secret_problems()
    put_settings(client, {"panorama_api_key": "brand-new-panorama-key-value"})
    assert get_settings().panorama_api_key == "brand-new-panorama-key-value"
    assert raw(client) != old and not settings_store.secret_problems()
    restart(client)
    assert get_settings().panorama_api_key == "brand-new-panorama-key-value"


# ------------------------------------------------------------------ rotation
def test_rotation_keeps_old_credentials_usable_and_reencrypts(client, keys):
    store_secret(client)
    put_settings(client, {"edl_user": "fw", "edl_password": "feed-password"})
    old_raw = raw(client)

    keys(KEY_B, previous=KEY_A)                            # step 1: new key + previous key, restart
    restart(client)
    assert get_settings().panorama_api_key == SECRET       # still usable
    assert get_settings().edl_password == "feed-password"
    assert raw(client) != old_raw                          # re-encrypted
    assert settings_store.decrypt(raw(client)) == (SECRET, 0)     # now under the CURRENT key
    assert not settings_store.secret_problems()

    keys(KEY_B)                                            # step 2: previous key removed
    restart(client)
    assert get_settings().panorama_api_key == SECRET and get_settings().edl_password == "feed-password"


def test_usable_during_rotation_window_before_restart(client, keys):
    store_secret(client)
    keys(KEY_B, previous=KEY_A)
    with client.factory() as s:
        settings_store.reload(s)                           # no re-encrypt yet, just a reload
    assert get_settings().panorama_api_key == SECRET


def test_rotation_without_previous_key_does_not_destroy_secrets(client, keys):
    store_secret(client)
    before = raw(client)
    keys(KEY_B)                                            # operator forgot ENCRYPTION_KEY_PREVIOUS
    restart(client)
    assert raw(client) == before and settings_store.secret_problems()
    keys(KEY_B, previous=KEY_A)                            # ...and fixes it
    restart(client)
    assert get_settings().panorama_api_key == SECRET and not settings_store.secret_problems()


def test_previous_key_banner_while_rotation_window_open(client, keys):
    keys(KEY_B, previous=KEY_A)
    login(client)
    assert "ENCRYPTION_KEY_PREVIOUS is set" in client.get("/admin/settings").text
    assert any("ENCRYPTION_KEY_PREVIOUS" in m for _, m in security_checks.system_warnings())


def test_legacy_secret_key_derived_secrets_still_readable_and_migrated(client, keys):
    legacy = settings_store._fernet(get_bootstrap().secret_key).encrypt(SECRET.encode()).decode()
    with client.factory() as s:
        s.get(AppSetting, "panorama_api_key").value = "enc:" + legacy
        s.commit()
    restart(client)
    assert get_settings().panorama_api_key == SECRET
    assert settings_store.decrypt(raw(client)) == (SECRET, 0)


# ------------------------------------------------------------------ keytool
def run_tool(*args):
    out = io.StringIO()
    with redirect_stdout(out):
        code = keytool.main(list(args))
    return code, out.getvalue()


def test_keytool_status_and_reencrypt(client, keys, monkeypatch):
    from app import db as dbmod
    store_secret(client)
    code, out = run_tool("status")
    assert code == 0 and "panorama_api_key: current-key" in out and SECRET not in out

    keys(KEY_B, previous=KEY_A)
    code, out = run_tool("status")
    assert code == 1 and "older-key" in out and "reencrypt" in out
    code, out = run_tool("reencrypt")
    assert code == 0 and "current-key" in out

    keys(KEY_C)
    code, out = run_tool("status")
    assert code == 1 and "unreadable" in out and "Nothing has been modified" in out


def test_keytool_without_key_explains(keys):
    keys("")
    code, out = run_tool("status")
    assert code == 1 and "ENCRYPTION_KEY is not set" in out


# ------------------------------------------------------------------ no leaks
def test_secrets_never_leak_through_logs_api_or_pages(client, keys, caplog):
    caplog.set_level(logging.DEBUG)
    store_secret(client)
    stored = raw(client)
    keys(KEY_B, previous=KEY_A)
    restart(client)
    keys(KEY_C)
    restart(client)
    login(client)
    bodies = [client.get("/v1/admin/settings", headers=KEY).text, client.get("/v1/admin/audit", headers=KEY).text,
              client.get("/healthz").text, client.get("/admin/settings").text, client.get("/admin/settings/panorama").text,
              client.get("/admin/audit").text]
    for text in bodies + [caplog.text]:
        assert SECRET not in text and stored not in text and "enc:gAAAA" not in text
        for k in (KEY_A, KEY_B, KEY_C):
            assert k not in text


def test_secret_values_not_in_exceptions(client, keys):
    store_secret(client)
    keys(KEY_C)
    plain, idx = settings_store.decrypt(raw(client))
    assert (plain, idx) == (None, -1)
