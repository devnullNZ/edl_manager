import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .config import get_bootstrap, get_settings

basic = HTTPBasic(auto_error=False)


def require_api_key(x_api_key: Annotated[str | None, Header()] = None):
    """Administrative API authentication. Separate from host (submission) credentials."""
    if not x_api_key or not secrets.compare_digest(x_api_key.encode(), get_bootstrap().api_key.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing X-API-Key")


def edl_auth(creds: Annotated[HTTPBasicCredentials | None, Depends(basic)]):
    """Optional HTTP basic auth on the feed (configured on the Settings page)."""
    s = get_settings()
    if not s.edl_user:
        return
    ok = creds is not None and secrets.compare_digest(creds.username.encode(), s.edl_user.encode()) \
        and secrets.compare_digest(creds.password.encode(), s.edl_password.encode())
    if not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required",
                            headers={"WWW-Authenticate": "Basic"})
