"""Image inspection and thumbnail generation.

Security-relevant behaviour lives here: EXIF is stripped by default because it
routinely carries GPS coordinates and device identifiers.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

from .config import settings

# SVG is deliberately absent. SVG can embed <script> and event handlers, making
# it a stored-XSS vector when served from the same origin. Supporting it safely
# requires allowlist parsing (defusedxml + attribute filtering) or rasterisation.
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "GIF", "WEBP", "BMP", "TIFF"}

publishers = None  # placeholder to keep import graph obvious


@dataclass
class ImageInfo:
    mime_type: str
    width: int
    height: int
    format: str


class NotAnImage(Exception):
    pass


def sniff_mime(data: bytes) -> str:
    """Identify type from magic bytes.

    The client-supplied Content-Type is untrusted: a caller can label a
    payload ``image/png`` while sending anything at all.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM":
        return "image/bmp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if data[:5] == b"%PDF-":
        return "application/pdf"
    if data[:4] == b"PK\x03\x04":
        return "application/zip"
    return "application/octet-stream"


def inspect_image(path: Path) -> ImageInfo:
    try:
        with Image.open(path) as im:
            fmt = (im.format or "").upper()
            if fmt not in ALLOWED_IMAGE_FORMATS:
                raise NotAnImage(f"unsupported image format: {fmt or 'unknown'}")
            return ImageInfo(
                mime_type=Image.MIME.get(fmt, "application/octet-stream"),
                width=im.width,
                height=im.height,
                format=fmt,
            )
    except (UnidentifiedImageError, OSError) as exc:
        raise NotAnImage(str(exc)) from exc


def make_thumbnail(source: Path, sha256: str) -> Path | None:
    """Generate a 512px WebP thumbnail. Returns None if not applicable.

    Animated GIFs are skipped rather than flattened: converting them would
    silently discard the animation, which is usually the point of the file.
    """
    dest = settings.thumbs_dir / sha256[:2] / f"{sha256}_512.webp"
    if dest.exists():
        return dest

    try:
        with Image.open(source) as im:
            # Must inspect n_frames before any transform. ImageOps.exif_transpose
            # returns a plain (single-frame) image, so checking afterwards would
            # always report 1 frame and silently flatten the animation.
            is_animated = getattr(im, "n_frames", 1) > 1
            if (im.format or "").upper() == "GIF" and is_animated:
                return None

            im = ImageOps.exif_transpose(im)
            im = im.convert("RGB")
            im.thumbnail((settings.thumb_size, settings.thumb_size), Image.LANCZOS)

            dest.parent.mkdir(parents=True, exist_ok=True)
            buf = io.BytesIO()
            im.save(buf, format="WEBP", quality=settings.thumb_quality, method=4)
            dest.write_bytes(buf.getvalue())
        return dest
    except (UnidentifiedImageError, OSError):
        return None


def strip_exif(source: Path) -> bool:
    """Rewrite a staged file in place without metadata.

    Returns True when the file was modified. Applied to JPEG/TIFF only, since
    those are the formats that actually carry EXIF.

    Intended as the ``sanitize`` hook for :func:`app.storage.stream_to_blob`,
    i.e. it runs **before** the blob is hashed and committed. That ordering is
    load-bearing: rewriting a blob after it has been committed under its
    content hash leaves the file not hashing to its own name, which makes the
    ``sha256`` handed to the client unverifiable and ``size_bytes`` wrong.

    ``im.format`` must be captured *before* ``exif_transpose``: that call
    returns a new image whose ``format`` is None, so reading it afterwards
    raises ``ValueError: unknown file extension`` and the rewrite silently
    fails -- leaving GPS coordinates in place.

    A magic-byte check gates the PIL open. Uploads are frequently not images
    at all, and handing arbitrary bytes to ``Image.open`` is needless work
    plus needless exposure to decoder bugs.
    """
    try:
        head = source.read_bytes()[:12]
    except OSError:
        return False

    if not (head[:3] == b"\xff\xd8\xff" or head[:4] in (b"II*\x00", b"MM\x00*")):
        return False

    try:
        with Image.open(source) as im:
            fmt = (im.format or "").upper()
            if fmt not in {"JPEG", "TIFF"}:
                return False
            if not im.getexif():
                return False

            # Keep the original format string; exif_transpose loses it.
            save_kwargs: dict = {"format": fmt}
            if fmt == "JPEG":
                save_kwargs["quality"] = 95
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")

            cleaned = ImageOps.exif_transpose(im)
            buf = io.BytesIO()
            cleaned.save(buf, **save_kwargs)
        source.write_bytes(buf.getvalue())
        return True
    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        # A crafted header can declare enormous dimensions. Pillow raises this
        # past 2x MAX_IMAGE_PIXELS; it derives straight from Exception, so the
        # narrower clauses above would miss it and the upload would 500.
        Image.DecompressionBombError,
    ):
        return False
