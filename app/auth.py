"""API-key authentication, quota enforcement and a token-bucket rate limiter."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .db import db


@dataclass
class Principal:
    key_id: str
    name: str | None
    quota_bytes: int | None
    used_bytes: int
    rate_limit: int | None


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """In-process token bucket.

    Adequate for a single-instance deployment. Multiple workers each hold
    their own bucket, so the effective limit scales with worker count; a
    shared Redis would be needed for exact global enforcement.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str, per_minute: int) -> bool:
        now = time.monotonic()
        rate = per_minute / 60.0
        burst = float(per_minute)

        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=burst, updated=now)
                self._buckets[key] = b
            else:
                b.tokens = min(burst, b.tokens + (now - b.updated) * rate)
                b.updated = now

            if b.tokens < 1.0:
                return False
            b.tokens -= 1.0
            return True


limiter = RateLimiter()


# Declaring the scheme as a dependency -- rather than reading the header by
# hand with Header(default=None) -- is what puts an "Authorize" button on /docs.
# Reading the header manually produces no securitySchemes entry at all, so the
# OpenAPI document claims every endpoint is public and Swagger UI offers no way
# to attach a token. The result is that authenticated endpoints cannot be
# exercised from the docs page at all: each call just returns 401 with no
# visible cause.
_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="ApiKey",
    description=(
        "Paste the API key on its own; Swagger UI prepends 'Bearer ' for you. "
        "Mint one with: python -m scripts.mintkey <label>"
    ),
)


def _extract_key(
    credentials: HTTPAuthorizationCredentials | None,
    raw_header: str | None,
) -> str:
    """Resolve the API key from the Authorization header.

    Both arguments are needed. ``HTTPBearer(auto_error=False)`` hands back None
    for *any* header it cannot parse -- absent, empty, or a non-Bearer scheme --
    so on its own it cannot tell "no header at all" from "sent Basic instead of
    Bearer". The raw header separates those two, and they deserve different
    messages.
    """
    if not raw_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="expected 'Bearer <api_key>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials.strip()


async def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> Principal:
    plaintext = _extract_key(credentials, request.headers.get("authorization"))
    row = db.lookup_api_key(plaintext)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid api key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    limit = row["rate_limit"] or settings.rate_limit_per_min
    if not limiter.check(row["key_id"], limit):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={"Retry-After": "60"},
        )

    return Principal(
        key_id=row["key_id"],
        name=row["name"],
        quota_bytes=row["quota_bytes"],
        used_bytes=row["used_bytes"],
        rate_limit=row["rate_limit"],
    )


def enforce_quota(principal: Principal, incoming_bytes: int) -> None:
    """Reject an upload that would push the key past its storage quota."""
    if principal.quota_bytes is None:
        return
    if principal.used_bytes + incoming_bytes > principal.quota_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="storage quota exceeded",
        )


ApiKeyDep = Depends(require_api_key)
