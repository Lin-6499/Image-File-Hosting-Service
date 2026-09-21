"""HMAC signed-URL primitives.

A signed URL carries its own expiry and purpose, so verification needs no
database round-trip. The signature covers ``file_id``, ``exp`` and ``purpose``
together -- omitting ``purpose`` would let an attacker take an image URL and
flip it into a download URL while keeping a valid signature.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Literal

Purpose = Literal["dl", "img"]

# Field separator. A plain concatenation is ambiguous: ("a1", "2") and
# ("a12", "") produce the same string. Newline cannot appear in a file_id,
# so it is a safe delimiter.
_SEP = "\n"


class SignatureError(Exception):
    """Raised when a signature fails verification."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _payload(file_id: str, exp: int, purpose: str) -> bytes:
    return f"{file_id}{_SEP}{exp}{_SEP}{purpose}".encode("utf-8")


def sign(file_id: str, exp: int, purpose: str, secret: str) -> str:
    """Return the base64url signature for the given claims."""
    digest = hmac.new(
        secret.encode("utf-8"),
        _payload(file_id, exp, purpose),
        hashlib.sha256,
    ).digest()
    return _b64u_encode(digest)


def verify(
    file_id: str,
    exp: int,
    purpose: str,
    sig: str,
    secret: str,
    *,
    clock_skew: int = 5,
    now: int | None = None,
) -> None:
    """Validate ``sig``. Raises :class:`SignatureError` on any failure.

    ``clock_skew`` tolerates small NTP drift: a server whose clock runs a few
    seconds ahead would otherwise reject links it just issued.
    """
    current = int(time.time()) if now is None else now

    if exp < current - clock_skew:
        raise SignatureError("expired")

    expected = sign(file_id, exp, purpose, secret)
    # compare_digest, never ==. A short-circuiting comparison leaks, through
    # response timing, how many leading bytes of the signature were correct.
    if not hmac.compare_digest(expected, sig):
        raise SignatureError("bad_signature")


def clamp_ttl(requested: int | None, default: int, maximum: int) -> int:
    """Clamp a caller-supplied TTL into [1, maximum].

    Without an upper bound a caller can request exp=year-2099 and defeat the
    expiry mechanism entirely.
    """
    if requested is None:
        return default
    return max(1, min(requested, maximum))
