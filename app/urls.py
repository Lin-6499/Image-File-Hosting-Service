"""URL builders for signed download links and public image links."""

from __future__ import annotations

import time
from urllib.parse import quote, urlencode

from .config import settings
from .signing import sign


def build_download_url(file_id: str, ttl: int) -> tuple[str, int]:
    """Return (url, expires_at) for a time-limited download link."""
    exp = int(time.time()) + ttl
    sig = sign(file_id, exp, "dl", settings.secret_key)
    query = urlencode({"exp": exp, "p": "dl", "sig": sig})
    return f"{settings.base_url}/d/{file_id}?{query}", exp


def build_image_url(file_id: str, sha8: str) -> str:
    """Public, long-lived image URL.

    ``sha8`` is embedded so the URL changes whenever the content does. That
    makes ``Cache-Control: immutable`` safe -- a stale entry can never be
    served for new content, because new content implies a new URL.
    """
    return f"{settings.base_url}/i/{file_id}/{sha8}.webp"


def build_original_image_url(file_id: str, sha8: str) -> str:
    return f"{settings.base_url}/i/{file_id}/{sha8}.original"


def content_disposition(filename: str | None, *, inline: bool = False) -> str:
    """Build a Content-Disposition header safe against header injection.

    ``filename`` originates from the client, so newlines must be stripped --
    otherwise a crafted name can inject arbitrary response headers. The
    ``filename*`` form is used for non-ASCII names.
    """
    disposition = "inline" if inline else "attachment"
    if not filename:
        return disposition

    safe = filename.replace("\r", "").replace("\n", "").replace('"', "")
    ascii_fallback = safe.encode("ascii", "ignore").decode("ascii") or "download"
    encoded = quote(safe, safe="")
    return (
        f'{disposition}; filename="{ascii_fallback}"; '
        f"filename*=UTF-8''{encoded}"
    )
