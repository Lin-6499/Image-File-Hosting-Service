"""Antivirus gate verification against a *live* server (AV_BACKEND=stub).

scan_demo.py exercises the gate through the in-process ASGI transport. This
script drives the same rules over real HTTP/TCP, and additionally verifies the
two properties that only a real deployment can show:

  * a scanner that is enabled actually changes the recorded status, and
  * a disabled scanner is reported honestly at startup rather than silently
    passing files through as if they had been inspected.

Usage:
    AV_BACKEND=stub uvicorn app.main:app --port 8023 &
    AV_BACKEND=stub python scripts/av_e2e.py http://127.0.0.1:8023
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8023"

# Must match the marker StubScanner is configured to flag. The stub matches on
# file *content*, so this has to be embedded in the uploaded bytes.
MALWARE_MARKER = b"MALWARE_MARKER"

PASS = 0
FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {label}" + (f" -- {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f" -- {detail}" if detail else ""))


def main() -> int:
    global PASS, FAIL

    print("=" * 64)
    print(f"  Antivirus gate over live HTTP -> {BASE}")
    print("=" * 64)

    from app.config import get_settings
    from app.db import Database

    settings = get_settings()
    db = Database(settings.db_path, journal_mode=settings.db_journal_mode)
    db.init()
    _, raw_key = db.create_api_key("av-e2e")
    auth = {"Authorization": f"Bearer {raw_key}"}

    def retarget(u: str | None) -> str:
        if not u:
            return u or ""
        _, _, rest = u.partition("://")
        _, _, path = rest.partition("/")
        return f"{BASE}/{path}"

    # trust_env=False: see the note in e2e_local.py. An ambient HTTP_PROXY with
    # no NO_PROXY sends loopback requests through a proxy, which flakes.
    with httpx.Client(base_url=BASE, timeout=20.0, trust_env=False) as c:
        print()
        print("-- backend posture --")
        r = c.get("/openapi.json")
        check("server reachable", r.status_code == 200, f"{r.status_code}")

        # ---------------------------------------------------- clean path
        print()
        print("-- [1] clean upload --")
        r = c.post("/api/v1/files",
                   files={"file": ("clean.txt", b"totally innocuous bytes", "text/plain")},
                   headers=auth)
        check("clean upload -> 201", r.status_code == 201, f"{r.status_code}")
        clean = r.json()
        check("status is clean", clean["scan_status"] == "clean", clean["scan_status"])
        check("servable true", clean["servable"] is True, str(clean["servable"]))
        check("not 'skipped' (scanner really ran)",
              clean["scan_status"] != "skipped", clean["scan_status"])
        r = c.get(retarget(clean["download_url"]))
        check("clean download -> 200", r.status_code == 200, f"{r.status_code}")
        check("bytes intact", r.content == b"totally innocuous bytes")

        # ------------------------------------------------- infected path
        print()
        print("-- [2] infected upload --")
        r = c.post("/api/v1/files",
                   files={"file": ("payload.bin",
                                   b"header" + MALWARE_MARKER + b"trailer",
                                   "application/octet-stream")},
                   headers=auth)
        # The row is created so the event is auditable; it is simply not served.
        check("infected upload -> 201 (row recorded for audit)",
              r.status_code == 201, f"{r.status_code}")
        bad = r.json()
        check("status is infected", bad["scan_status"] == "infected", bad["scan_status"])
        check("servable false", bad["servable"] is False, str(bad["servable"]))
        check("detail names the match",
              "MALWARE_MARKER" in (bad.get("scan_detail") or ""),
              repr(bad.get("scan_detail")))

        r = c.get(retarget(bad["download_url"]))
        check("infected download -> 403", r.status_code == 403, f"{r.status_code}")
        # The app renders errors as {"error": {"code", "message"}} rather than
        # FastAPI's default {"detail": ...}, so read the nested shape.
        payload = r.json()
        err = payload.get("error", payload)
        msg = err.get("message", "") or str(payload)
        check("403 message explains malware block", "malware" in msg.lower(), msg)
        check("403 code is forbidden", err.get("code") == "forbidden",
              str(err.get("code")))

        # An infected *image* must be blocked on the display route too, not
        # only on download -- a common gap when the two routes drift.
        r = c.get(f"/api/v1/files/{bad['file_id']}", headers=auth)
        check("infected metadata reflects status",
              r.json()["scan_status"] == "infected", r.json()["scan_status"])
        check("infected metadata not servable",
              r.json()["servable"] is False, str(r.json()["servable"]))

        # --------------------------------------------------- audit trail
        print()
        print("-- [3] audit trail --")
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT action, status FROM audit_log"
                " WHERE file_id = ? ORDER BY rowid DESC LIMIT 5",
                (bad["file_id"],),
            ).fetchall()
        actions = [dict(r) for r in rows]
        check("blocked download was audited",
              any(r["action"] == "download_blocked" for r in actions), str(actions))

        # --------------------------------------------------- listing gate
        print()
        print("-- [4] listing exposes scan state --")
        r = c.get("/api/v1/files", headers=auth)
        items = {i["file_id"]: i for i in r.json()["items"]}
        check("clean file listed as servable",
              items[clean["file_id"]]["servable"] is True)
        check("infected file listed as not servable",
              items[bad["file_id"]]["servable"] is False)
        check("scanned_at populated",
              items[bad["file_id"]]["scanned_at"] is not None,
              str(items[bad["file_id"]]["scanned_at"]))

    print()
    print("=" * 64)
    if FAIL:
        print(f"  {FAIL} FAILED / {PASS} passed")
        print("=" * 64)
        return 1
    print(f"  all {PASS} checks passed")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
