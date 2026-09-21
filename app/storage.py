"""Blob storage on the local filesystem, content-addressed by SHA-256.

Content addressing gives three things for free: deduplication, integrity
verification, and unguessable paths (the hash *is* the random string). The
cost is that a blob cannot be deleted on behalf of a single upload -- other
records may reference the same content. Deletion therefore goes through the
reference-counting path in :mod:`app.db`.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from .config import settings

log = logging.getLogger("host.storage")

CHUNK = 1 << 20  # 1 MiB


class FileTooLarge(Exception):
    pass


class StorageFull(Exception):
    pass


def _discard(path: Path) -> bool:
    """Best-effort removal of a file that must never break the caller.

    Cleanup is a side effect, not the operation the client asked for. Two
    distinct hazards make a bare ``unlink`` unsafe here:

    * ``BaseException`` -- some host runtimes monkeypatch
      :meth:`pathlib.Path.unlink` (interposing a trash/recycle-bin shim). Those
      shims can raise ``SystemExit`` or ``KeyboardInterrupt``, which a plain
      ``except OSError`` will not catch and which will tear down an otherwise
      healthy request with a 500.
    * Any ordinary I/O refusal (EPERM on Windows when an antivirus or indexer
      holds a handle) should also leave the request intact -- the stale
      fragment is later reclaimed by :func:`sweep_tmp`.

    Returns ``True`` when the file is gone, ``False`` when it survived.
    """
    try:
        path.unlink(missing_ok=True)
        return True
    except BaseException:  # noqa: BLE001 - cleanup must never propagate
        log.debug("could not discard %s; sweep_tmp will reclaim it", path, exc_info=True)
        return False


@dataclass
class StoredBlob:
    sha256: str
    size_bytes: int
    path: Path
    reused: bool


def _shard(sha256: str) -> str:
    """Two-level directory fan-out.

    A flat directory degrades badly past ~100k entries on ext4/NTFS because
    lookups stop being effectively constant-time. Sharding by the first two
    hex characters caps each directory at 1/256 of the total.
    """
    return sha256[:2]


def blob_path(sha256: str) -> Path:
    return settings.blobs_dir / _shard(sha256) / sha256


def thumb_path(sha256: str) -> Path:
    return settings.thumbs_dir / _shard(sha256) / f"{sha256}_512.webp"


def disk_usage_ratio() -> float:
    total, used, _free = shutil.disk_usage(settings.data_dir)
    return used / total if total else 1.0


def check_capacity() -> None:
    """Fail fast before accepting a body.

    A full disk is worse than a rejected upload: SQLite cannot commit once
    writes fail, so the whole service becomes unavailable rather than just
    degrading.
    """
    if disk_usage_ratio() >= settings.disk_high_watermark:
        raise StorageFull(
            f"disk usage {disk_usage_ratio():.1%} exceeds "
            f"{settings.disk_high_watermark:.0%} watermark"
        )


async def stream_to_blob(
    upload,
    *,
    max_size: int | None = None,
    sanitize=None,
) -> StoredBlob:
    """Consume an ``UploadFile`` into the blob store.

    Three properties matter here and all are easy to get wrong:

    1. The size limit is enforced *while* reading, not after. Buffering a
       10 GB body to check its length afterwards lets a single request fill
       the disk.
    2. ``Content-Length`` is never trusted -- it is attacker-controlled and
       may be absent on chunked transfer encoding.
    3. Any content transform runs **before** the blob is hashed and committed.

    On point 3: ``sanitize`` is an optional ``callable(Path) -> bool`` that may
    rewrite the staged temp file in place and reports whether it changed
    anything. It runs pre-commit so the stored bytes are the ones the filename
    describes. Doing it afterwards (as an earlier revision did) silently breaks
    the store's core invariant -- see :func:`blob_path` -- because the file on
    disk no longer hashes to its own name. That makes the ``sha256`` returned
    to the client unverifiable and ``size_bytes`` wrong for every sanitised
    file.

    The write is staged in ``tmp/`` and committed with :func:`os.replace`,
    which is atomic only within a single filesystem. That is why ``tmp/``
    lives under ``data/`` rather than the system temp directory, which is
    usually a separate mount.
    """
    limit = settings.max_file_size if max_size is None else max_size
    settings.tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = settings.tmp_dir / f"up_{uuid.uuid4().hex}.part"

    hasher = hashlib.sha256()
    total = 0

    try:
        with open(tmp_path, "wb") as fp:
            while True:
                chunk = await upload.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise FileTooLarge(f"exceeds {limit} bytes")
                hasher.update(chunk)
                fp.write(chunk)

        if total == 0:
            raise FileTooLarge("empty file")

        if sanitize is not None:
            # A transform invalidates the incremental digest, so re-hash from
            # disk. Only files that were actually rewritten pay for this.
            try:
                changed = sanitize(tmp_path)
            except Exception:
                # A sanitizer failure must not lose the upload. Serving the
                # original is the safer default only because the caller (the
                # router) decides what "original" means for its own policy;
                # here we simply leave the bytes untouched and log loudly.
                log.warning(
                    "sanitizer failed on %s; storing the original bytes",
                    tmp_path,
                    exc_info=True,
                )
                changed = False
            if changed:
                hasher = hashlib.sha256()
                total = 0
                with open(tmp_path, "rb") as fp:
                    while True:
                        chunk = fp.read(CHUNK)
                        if not chunk:
                            break
                        total += len(chunk)
                        hasher.update(chunk)

        sha256 = hasher.hexdigest()
        final = blob_path(sha256)

        if final.exists():
            # Same content already stored. Discard the duplicate; the file
            # row is still created so the second upload keeps its own
            # lifecycle and id.
            _discard(tmp_path)
            return StoredBlob(sha256=sha256, size_bytes=total, path=final, reused=True)

        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp_path, final)
        return StoredBlob(sha256=sha256, size_bytes=total, path=final, reused=False)

    except Exception:
        # `_discard`, not `unlink`: this runs on the *failure* path, where an
        # exception from the cleanup itself would replace a useful error
        # (FileTooLarge, StorageFull) with an opaque 500.
        _discard(tmp_path)
        raise


def delete_blob(sha256: str) -> bool:
    p = blob_path(sha256)
    existed = p.exists()
    _discard(p)
    _discard(thumb_path(sha256))
    return existed


def sweep_tmp(max_age_seconds: int = 86400) -> int:
    """Remove orphaned upload fragments left by crashed or aborted requests."""
    import time

    removed = 0
    if not settings.tmp_dir.exists():
        return 0
    cutoff = time.time() - max_age_seconds
    for p in settings.tmp_dir.iterdir():
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                if _discard(p):
                    removed += 1
        except OSError:
            continue
    return removed


def local_path_for_serving(sha256: str) -> Path:
    """Path handed to the file server.

    Behind nginx this becomes the ``X-Accel-Redirect`` target; the internal
    mount maps ``/_blobs/`` onto ``data/blobs/``. In local debug mode FastAPI
    streams the file itself.
    """
    return blob_path(sha256)
