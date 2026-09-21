"""Maintenance: expiry marking, blob reclamation, tmp sweep.

Run on a schedule (see scripts/cleanup.py for a runnable entry point).
"""

from __future__ import annotations

import logging

from .db import db
from .scanservice import release_stale_pending, resolve_pending
from .storage import blob_path, delete_blob, sweep_tmp, thumb_path

log = logging.getLogger("host.cleanup")

# Blobs are kept this long after their last live reference disappears, so an
# accidental deletion can be reversed before the bytes are gone.
GRACE_SECONDS = 24 * 3600

# A pending row younger than this may belong to an upload request that is still
# scanning it. The request inserts the row as `pending` and only scans after
# that, so a sweeper that ignores age can resolve the row first -- and because
# `set_scan_result` only writes to rows still in `pending`, the request's own
# successful verdict is then silently dropped, leaving the response saying
# `clean` while the database says `error` (which is not servable).
#
# 60s is comfortably longer than any in-request scan and far shorter than
# AV_PENDING_GRACE, so nothing sits queued longer than it has to.
SCAN_PICKUP_GRACE = 60

# Cap on how many queued files one sweep will scan, so a large backlog cannot
# make the sweep run long. Hitting the cap is reported as saturation rather
# than treated as a failure -- see step 0b.
SCAN_PICKUP_BATCH = 100


def run_once() -> dict[str, int]:
    result = {
        "marked": 0,
        "blobs_removed": 0,
        "hashes_purged": 0,
        "tmp_removed": 0,
        "scan_resolved": 0,
        "scan_released": 0,
    }

    # 0a. Give queued files their real verdict.
    #
    #     A file is left `pending` when the upload request died between
    #     inserting the row and scanning it. Nothing used to scan those: the
    #     only recovery was step 0b, which marks them `error` -- and `error` is
    #     not servable, so a clean file stayed permanently undownloadable while
    #     a perfectly healthy scanner was never asked. Scanning first means the
    #     verdict is usually `clean` and 0b then has nothing to do.
    #
    #     The whole step is contained: scanning talks to an external daemon
    #     over a socket and can raise anything, and this sweep's primary job is
    #     reclaiming disk. A scanner hiccup must not stop expiry marking or
    #     blob deletion, and it must not skip step 0b either -- that is the
    #     fallback for exactly this situation.
    saturated = False
    try:
        tally, saturated = resolve_pending(
            limit=SCAN_PICKUP_BATCH, min_age_seconds=SCAN_PICKUP_GRACE
        )
    except Exception:  # noqa: BLE001 -- the sweep must outlive the scanner
        log.exception("scan pickup failed; continuing with the rest of the sweep")
    else:
        resolved = sum(tally.values())
        if resolved:
            log.info("scan pickup: %s", tally)
        result["scan_resolved"] = resolved

    # 0b. Unstick whatever is still pending past the grace window. This remains
    #     as a backstop rather than being redundant: it covers rows whose scan
    #     attempt left them pending, and rows the batch above could not reach.
    #
    #     Skipped when 0a filled its batch, because "did not get to it" is not
    #     "failed": marking a row `error` here would brick a file the scanner
    #     never saw, and `error` is not servable. The next sweep continues
    #     where this one stopped.
    if saturated:
        log.warning(
            "scan pickup hit its batch limit; deferring stale release to the next sweep"
        )
    else:
        result["scan_released"] = release_stale_pending()

    # 1. Mark records whose retention window has passed.
    for file_id in db.expired_file_ids():
        if db.soft_delete(file_id):
            result["marked"] += 1

    # 2. Find hashes with no live reference past the grace period.
    orphans = db.find_orphan_blobs(grace_seconds=GRACE_SECONDS)

    gone: list[str] = []
    for sha in orphans:
        # 2b. Re-check before unlinking. Between step 2 and here, a concurrent
        #     upload may have inserted a new live row pointing at this same
        #     content. Deleting without re-checking would destroy the blob of
        #     a file that was just uploaded.
        if db.is_hash_referenced(sha):
            log.debug("skip %s: referenced again", sha[:12])
            continue
        if delete_blob(sha):
            result["blobs_removed"] += 1

        # 2c. Only a hash whose bytes are actually gone may lose its row.
        #
        #     `delete_blob` reports "did it exist", not "did it succeed":
        #     `_discard` swallows OSError, so a file held open by antivirus or
        #     a backup agent leaves the bytes in place while the call still
        #     reports success. Purging that row would throw away the only
        #     record that the orphan exists, and because `find_orphan_blobs`
        #     works from `files`, nothing would ever retry -- the disk stays
        #     consumed forever with no trace of why. Keeping the row means the
        #     next sweep tries again, and it also retries the thumbnail, which
        #     may be the file that was locked.
        if not blob_path(sha).exists() and not thumb_path(sha).exists():
            gone.append(sha)

    # 3. Drop the metadata rows whose bytes are gone.
    if gone:
        result["hashes_purged"] = db.purge_hashes(gone)

    # 4. Clear upload fragments left by aborted requests.
    result["tmp_removed"] = sweep_tmp()

    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(run_once())
