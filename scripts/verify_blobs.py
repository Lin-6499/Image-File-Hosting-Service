"""Audit the blob store against its content-addressing invariant.

    .venv\\Scripts\\python.exe scripts/verify_blobs.py

Content addressing only pays off if it actually holds: every file under
``data/blobs/`` must hash to its own filename, and every live row in the
database must describe the bytes it points at. This script checks both.

It exists because a real defect violated that invariant. EXIF stripping used to
run *after* a blob had been committed under the digest of the original upload,
leaving the stored file not hashing to its own name -- which made the
``sha256`` returned to clients unverifiable and ``size_bytes`` wrong. Fresh
uploads are correct now, but an instance that ran the older build can still
hold inconsistent blobs and stale row metadata. Run this after upgrading.

Two distinct checks, because they fail independently:

1. **Store integrity** -- re-hash each blob, compare against its filename.
   Catches the historical bug above, plus bit-rot and partial writes.
2. **Row consistency** -- for each live row, confirm the blob exists and that
   ``size_bytes`` matches the file on disk. A blob can be internally
   consistent while the row describing it is stale, and vice versa.
3. **Orphans** -- blobs on disk that no row references at all. These are
   invisible to ``scripts/cleanup.py``, which works *from* ``files``: with no
   row to find, no sweep will ever reclaim them. They appear when a row
   vanishes by some route other than the sweep -- a database restored from a
   snapshot, a manual ``DELETE``, a crash between writing the blob and
   inserting the row -- and the disk stays consumed with nothing to explain it.

Exit code is 0 when everything checks out, 1 when anything does not.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.db import db  # noqa: E402

CHUNK = 1 << 20


def hash_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def audit_store() -> tuple[int, int, list[str]]:
    """Re-hash every blob and compare against its filename."""
    root = settings.blobs_dir
    checked = bad = 0
    problems: list[str] = []

    if not root.exists():
        return 0, 0, []

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        checked += 1
        try:
            digest, size = hash_file(path)
        except OSError as exc:
            bad += 1
            problems.append(f"unreadable: {path} ({exc})")
            continue

        if path.name != digest:
            bad += 1
            problems.append(
                f"digest mismatch: {path.relative_to(root)}"
                f"  filename={path.name[:16]}...  actual={digest[:16]}..."
                f"  size={size}"
            )

    return checked, bad, problems


def audit_rows() -> tuple[int, int, list[str]]:
    """Cross-check live rows against the files they reference."""
    checked = bad = 0
    problems: list[str] = []

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT file_id, sha256, size_bytes, orig_name FROM files"
            " WHERE deleted_at IS NULL"
        ).fetchall()

    for row in rows:
        checked += 1
        path = settings.blobs_dir / row["sha256"][:2] / row["sha256"]

        if not path.exists():
            bad += 1
            problems.append(
                f"missing blob: file_id={row['file_id']} name={row['orig_name']!r}"
                f"  sha256={row['sha256'][:16]}..."
            )
            continue

        actual_size = path.stat().st_size
        if actual_size != row["size_bytes"]:
            bad += 1
            problems.append(
                f"size mismatch: file_id={row['file_id']} name={row['orig_name']!r}"
                f"  db={row['size_bytes']}  disk={actual_size}"
                f"  (this is the signature of a post-commit rewrite)"
            )

    return checked, bad, problems


def audit_orphans() -> tuple[int, int, list[str]]:
    """Blobs on disk that no row references, live or deleted.

    Any row counts, including a soft-deleted one: its blob is still the
    sweep's responsibility until ``purge_hashes`` drops the row, so calling it
    an orphan early would produce false alarms during the grace period.

    These are the blobs the cleanup sweep structurally cannot reclaim, because
    ``find_orphan_blobs`` selects *from* ``files``. Nothing will ever notice
    them again unless this check does.
    """
    root = settings.blobs_dir
    problems: list[str] = []
    on_disk = 0

    if not root.exists():
        return 0, 0, []

    with db.connect() as conn:
        referenced = {
            row[0] for row in conn.execute("SELECT DISTINCT sha256 FROM files")
        }

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        on_disk += 1
        if path.name not in referenced:
            problems.append(
                f"orphaned blob: {path.relative_to(root)}"
                f"  size={path.stat().st_size}  no row references this hash"
            )

    return on_disk, len(problems), problems


def main() -> int:
    print("=" * 68)
    print("  Blob store audit")
    print("=" * 68)
    print(f"  blobs dir : {settings.blobs_dir}")
    print(f"  database  : {settings.db_path}")

    db.init()

    print()
    print("-- [1] store integrity (filename == sha256 of content) --")
    checked, bad, problems = audit_store()
    print(f"   blobs checked : {checked}")
    print(f"   mismatches    : {bad}")
    for line in problems[:20]:
        print(f"     ! {line}")
    if len(problems) > 20:
        print(f"     ... and {len(problems) - 20} more")

    print()
    print("-- [2] row consistency (live rows vs files on disk) --")
    checked2, bad2, problems2 = audit_rows()
    print(f"   live rows     : {checked2}")
    print(f"   inconsistent  : {bad2}")
    for line in problems2[:20]:
        print(f"     ! {line}")
    if len(problems2) > 20:
        print(f"     ... and {len(problems2) - 20} more")

    print()
    print("-- [3] orphans (blobs on disk that no row references) --")
    checked3, bad3, problems3 = audit_orphans()
    print(f"   blobs on disk : {checked3}")
    print(f"   orphans       : {bad3}")
    for line in problems3[:20]:
        print(f"     ! {line}")
    if len(problems3) > 20:
        print(f"     ... and {len(problems3) - 20} more")

    total_bad = bad + bad2 + bad3
    print()
    print("=" * 68)
    if bad3 and not (bad or bad2):
        print(f"  {total_bad} problem(s) found")
        print()
        print("  Only orphans: the metadata and the store each look fine, but")
        print("  these blobs have no row. scripts/cleanup.py cannot reclaim them")
        print("  -- it works from `files`, and there is no row to find -- so")
        print("  they must be removed by hand once you are sure they are not")
        print("  needed. A row usually vanishes this way when the database is")
        print("  restored from an older snapshot, or a row is deleted by hand.")
        print("=" * 68)
        return 1

    if total_bad:
        print(f"  {total_bad} problem(s) found")
        print()
        print("  If the mismatches are all JPEG/TIFF and their rows report a")
        print("  larger size_bytes than the file on disk, the instance ran a")
        print("  build where EXIF stripping happened after the blob was")
        print("  committed. Re-uploading those files fixes them; the orphaned")
        print("  blobs are reclaimed by scripts/cleanup.py.")
        print("=" * 68)
        return 1

    print("  store and rows are consistent")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
