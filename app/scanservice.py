"""Scan queue orchestration.

Scanning runs synchronously inside the upload request in this implementation,
which is the right trade-off for the target workload: uploads are infrequent
and a verdict before responding means the caller never receives a link to a
file that is still unverified.

The queue helpers below exist for the asynchronous variant (a background
worker) and for repairing state when the scanner was unavailable -- a file
left ``pending`` is unservable, so something must resolve it eventually. That
repair is wired into the cleanup sweep (``cleanup.run_once``), which is the
cron entry point: it first *scans* whatever is queued, then falls back to
marking anything still stuck as ``error``.

Both halves are needed. Scanning alone leaves rows stranded if the sweep never
runs; releasing alone -- which is what the sweep used to do -- marks files
``error`` without ever asking the scanner, and ``error`` is not servable. A
clean file whose upload was interrupted between insert and scan would then be
permanently undownloadable for no reason.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from .config import settings
from .db import db
from .scanner import ScanError, ScanResult, Scanner, build_scanner
from .storage import blob_path

log = logging.getLogger("host.scanservice")

_scanner: Scanner | None = None
_scanner_resolved = False


def get_scanner() -> Scanner | None:
    """Resolve the configured scanner once and cache it.

    Resolution is lazy so that importing the app never requires ClamAV to be
    installed. A failed probe is retried on the next call after a short delay,
    because clamd commonly starts a few seconds after the app in a container
    stack.
    """
    global _scanner, _scanner_resolved
    if _scanner_resolved:
        return _scanner
    _scanner = build_scanner()
    _scanner_resolved = True
    return _scanner


def reset_scanner_cache() -> None:
    """Forget the cached scanner. Used by tests and after config changes."""
    global _scanner, _scanner_resolved
    _scanner = None
    _scanner_resolved = False


def scanning_enabled() -> bool:
    return get_scanner() is not None


def initial_status() -> str:
    """Scan status to record at insert time.

    ``pending`` when a scanner is configured so the file starts unservable,
    ``skipped`` when scanning is off so behaviour is unchanged from before the
    feature existed.
    """
    return "pending" if scanning_enabled() else "skipped"


def scan_blob(sha256: str) -> ScanResult:
    """Scan a stored blob and return the verdict.

    Raises :class:`ScanError` when no verdict could be produced; callers
    decide whether that leaves the file pending or marks it failed.
    """
    scanner = get_scanner()
    if scanner is None:
        return ScanResult("skipped", "scanning disabled")

    path = blob_path(sha256)
    if not path.exists():
        raise ScanError(f"blob missing: {sha256[:12]}")

    return scanner.scan(path)


def apply_result(file_id: str, result: ScanResult) -> bool:
    """Persist a verdict for a file record."""
    return db.set_scan_result(file_id, result.status, result.detail)


def scan_and_apply(file_id: str, sha256: str) -> ScanResult:
    """Scan and persist, converting scanner failures into an ``error`` verdict.

    An unreachable scanner deliberately does NOT produce ``clean``: silently
    treating "could not scan" as "safe" is exactly the failure mode that makes
    antivirus integration worthless.
    """
    try:
        result = scan_blob(sha256)
    except ScanError as exc:
        log.warning("scan failed for %s: %s", file_id, exc)
        result = ScanResult("error", str(exc)[:200])

    apply_result(file_id, result)
    return result


def _pickup_candidates(limit: int, min_age_seconds: int) -> list[tuple[str, object]]:
    """Pending records old enough to be safe to resolve.

    ``pending_scan_ids`` yields oldest first, so the first row that is too
    young means every remaining row is too young as well -- stopping there is
    equivalent to filtering and avoids paging past the whole in-flight window.
    """
    cutoff = int(time.time()) - min_age_seconds if min_age_seconds else None
    picked: list[tuple[str, object]] = []
    for file_id in db.pending_scan_ids(limit):
        rec = db.get_file(file_id)
        if rec is None:
            continue
        if cutoff is not None and rec.created_at > cutoff:
            break
        picked.append((file_id, rec))
    return picked


def resolve_pending(
    limit: int = 100, min_age_seconds: int = 0
) -> tuple[dict[str, int], bool]:
    """Scan queued files, reporting whether the batch ran out of room.

    Returns ``(tally, saturated)``. ``saturated`` means there may be eligible
    rows this call never looked at, because ``limit`` was reached -- a caller
    that also has a "mark the leftovers failed" step must not run it, or it
    would fail rows it never scanned, and ``error`` is not servable.

    ``min_age_seconds`` skips rows younger than that. The upload request
    inserts its row as ``pending`` and only scans *afterwards*, so without a
    guard a sweeper can resolve a row out from under a live request. The
    damage is not a double scan -- ``set_scan_result`` only writes to rows
    still in ``pending``, so the loser is a no-op -- it is that the *request's*
    successful verdict gets dropped when the sweeper wins the race with a
    transient ``error``. The response then claims ``clean`` while the database
    says ``error``, and ``error`` is not servable.

    The default of 0 keeps this primitive meaning "process everything", which
    is what a dedicated worker wants; the grace belongs at the call site that
    can actually race (see ``cleanup.SCAN_PICKUP_GRACE``).
    """
    tally = {"clean": 0, "infected": 0, "error": 0, "skipped": 0}
    candidates = _pickup_candidates(limit, min_age_seconds)
    saturated = len(candidates) >= limit

    if not scanning_enabled():
        # With scanning off, nothing should be pending. If rows are -- the
        # config changed from clamd to none, say -- release them as 'skipped'
        # so they become servable, rather than letting the stale-pending
        # backstop mark a perfectly good file 'error' and unservable forever.
        for file_id, _rec in candidates:
            apply_result(file_id, ScanResult("skipped", "scanning disabled"))
            tally["skipped"] += 1
        return tally, saturated

    for file_id, rec in candidates:
        result = scan_and_apply(file_id, rec.sha256)
        tally[result.status] = tally.get(result.status, 0) + 1
        if result.status == "infected":
            log.warning(
                "malware detected: file_id=%s signature=%s", file_id, result.detail
            )

    return tally, saturated


def process_pending(limit: int = 100, min_age_seconds: int = 0) -> dict[str, int]:
    """Scan queued files. Intended for a background worker or cron.

    Thin wrapper over :func:`resolve_pending` that drops the saturation flag,
    which only matters to a caller that would otherwise act on the leftovers.
    """
    tally, _saturated = resolve_pending(limit, min_age_seconds)
    return tally


def release_stale_pending(grace_seconds: int | None = None) -> int:
    """Unstick files that have been pending beyond the grace window.

    Without this, a scanner that stops working leaves every subsequent upload
    permanently unservable, with no error anywhere. The file is marked
    ``error`` rather than ``clean`` so the record shows what actually happened.
    """
    grace = settings.av_pending_grace if grace_seconds is None else grace_seconds
    cutoff = int(time.time()) - grace
    released = 0

    for file_id in db.pending_scan_ids(1000):
        rec = db.get_file(file_id)
        if rec is None or rec.created_at > cutoff:
            continue
        log.warning("releasing stale pending file %s", file_id)
        apply_result(
            file_id,
            ScanResult("error", f"still pending after {grace}s; scanner unresponsive"),
        )
        released += 1

    return released
