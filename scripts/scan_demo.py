"""End-to-end demonstration of antivirus scanning.

    .venv\\Scripts\\python.exe -m scripts.scan_demo

Uses the stub backend, which matches on file *content*. No ClamAV install is
required, so this doubles as a check that the gating logic works before wiring
up a real scanner.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must be set before the app package is imported.
os.environ["AV_BACKEND"] = "stub"

# Also before the app import: keep this run out of the real data/ directory.
from scripts._isolate import banner, isolate  # noqa: E402

_ISOLATED_ROOT = isolate("host-scan-demo-")

from fastapi.testclient import TestClient  # noqa: E402

from app import scanservice  # noqa: E402
from app.db import db  # noqa: E402
from app.main import app  # noqa: E402
from app.scanner import StubScanner  # noqa: E402

MARKER = "MALWARE_MARKER"


def main() -> int:
    stub = StubScanner(verdicts={MARKER: "infected"})
    scanservice.get_scanner = lambda: stub
    scanservice.scanning_enabled = lambda: True

    print(f"  {banner(_ISOLATED_ROOT)}")
    db.init()
    _, key = db.create_api_key("scan-demo")
    h = {"Authorization": f"Bearer {key}"}

    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok = ok and cond
        print(f"    [{'PASS' if cond else 'FAIL'}] {label}")

    with TestClient(app) as c:
        print("=" * 64)
        print("  Antivirus scanning -- end-to-end (AV_BACKEND=stub)")
        print("=" * 64)

        print("\n[1] clean file")
        up = c.post(
            "/api/v1/files",
            files={"file": ("clean.txt", b"perfectly safe content", "text/plain")},
            headers=h,
        ).json()
        print(f"    scan_status={up['scan_status']}  servable={up['servable']}")
        check("clean file is servable", c.get(up["download_url"]).status_code == 200)

        print("\n[2] infected file")
        r = c.post(
            "/api/v1/files",
            files={
                "file": (
                    "bad.bin",
                    f"prefix {MARKER} suffix".encode(),
                    "application/octet-stream",
                )
            },
            headers=h,
        )
        up2 = r.json()
        print(f"    upload HTTP={r.status_code} (201 expected: the row is created)")
        print(f"    scan_status={up2['scan_status']}  detail={up2['scan_detail']}")
        print(f"    servable={up2['servable']}")
        check("upload still returns 201", r.status_code == 201)
        check("verdict is infected", up2["scan_status"] == "infected")
        check("not marked servable", up2["servable"] is False)

        dl = c.get(up2["download_url"])
        print(f"    GET download -> {dl.status_code} (403 expected)")
        print(f"    message: {dl.json()['error']['message']}")
        check("infected download blocked with 403", dl.status_code == 403)

        print("\n[3] pending file")
        fid = up["file_id"]
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (fid,)
            )
        dl = c.get(up["download_url"])
        print(f"    GET download -> {dl.status_code} (409 expected: retryable)")
        check("pending download blocked with 409", dl.status_code == 409)

        print("\n[4] metadata exposes scan fields")
        meta = c.get(f"/api/v1/files/{up2['file_id']}", headers=h).json()
        print(
            f"    scan_status={meta['scan_status']}  "
            f"scanned_at={meta['scanned_at']}  servable={meta['servable']}"
        )
        check("metadata carries scan fields", meta["scanned_at"] is not None)

        print("\n[5] stale pending is released by the sweeper")
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending', created_at=1 WHERE file_id=?",
                (fid,),
            )
        released = scanservice.release_stale_pending(grace_seconds=60)
        rec = db.get_file(fid)
        print(f"    released={released}  new status={rec.scan_status}")
        check("stale pending released to error", rec.scan_status == "error")

    print()
    print("=" * 64)
    print("  " + ("all checks passed" if ok else "FAILURES PRESENT"))
    print("=" * 64)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
