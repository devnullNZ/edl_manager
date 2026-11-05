"""Encryption-key maintenance:  python -m app.keytool status | reencrypt

status    show, per stored secret, whether it can be decrypted and with which key (never the value)
reencrypt re-encrypt every secret readable with ENCRYPTION_KEY_PREVIOUS (or the v1 SECRET_KEY-derived
          key) under the current ENCRYPTION_KEY. Unreadable secrets are reported and left untouched.
"""
import sys

from sqlalchemy import select

from . import db as dbmod
from . import settings_store
from .db import AppSetting


def collect(session) -> dict[str, str]:
    out = {}
    for row in session.scalars(select(AppSetting).where(AppSetting.key.in_(settings_store.SECRET_KEYS))):
        if not row.value:
            continue
        if not row.value.startswith("enc:"):
            out[row.key] = "plaintext"
            continue
        plain, idx = settings_store.decrypt(row.value)
        out[row.key] = "unreadable" if plain is None else ("current-key" if idx == 0 else "older-key")
    return out


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "status"
    if cmd not in ("status", "reencrypt"):
        print(__doc__)
        return 2
    try:
        settings_store.check_encryption_config()
    except settings_store.EncryptionConfigError as exc:
        print(f"ERROR: {exc}")
        return 1
    with dbmod.SessionLocal() as session:
        if cmd == "reencrypt":
            for row in session.scalars(select(AppSetting).where(AppSetting.key.in_(settings_store.SECRET_KEYS))):
                if row.value.startswith("enc:"):
                    plain, idx = settings_store.decrypt(row.value)
                    if plain is not None and idx > 0:
                        row.value = settings_store.encrypt(plain)
            session.commit()
        states = collect(session)
    if not states:
        print("no secrets stored")
    for key, state in sorted(states.items()):
        print(f"{key}: {state}")
    bad = [k for k, v in states.items() if v == "unreadable"]
    if bad:
        print("\nUNREADABLE: restore the original ENCRYPTION_KEY, or re-enter these secrets in the admin "
              "interface. Nothing has been modified or deleted.")
        return 1
    if any(v == "older-key" for v in states.values()):
        print("\nSome secrets are still under an older key. Run:  python -m app.keytool reencrypt")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
