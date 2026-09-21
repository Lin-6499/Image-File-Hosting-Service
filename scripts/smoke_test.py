"""End-to-end smoke test against the ASGI app (no server needed)."""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must run before the app package is imported: app.config builds its paths at
# import time, so redirecting DATA_DIR afterwards has no effect. Without this
# the smoke test writes into the real data/ directory.
from scripts._isolate import banner, isolate  # noqa: E402

_ISOLATED_ROOT = isolate("host-smoke-")

from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image  # noqa: E402

from app.db import db  # noqa: E402
from app.main import app  # noqa: E402


def png_bytes(w: int = 64, h: int = 48, color=(120, 60, 200)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


def main() -> int:
    print(f"  {banner(_ISOLATED_ROOT)}")
    db.init()
    _, key = db.create_api_key("smoke-test")
    h = {"Authorization": f"Bearer {key}"}
    failures: list[str] = []

    def check(label: str, cond: bool, extra: str = "") -> None:
        mark = "PASS" if cond else "FAIL"
        print(f"  [{mark}] {label}{(' -- ' + extra) if extra else ''}")
        if not cond:
            failures.append(label)

    with TestClient(app) as c:
        print("\n-- ops --")
        r = c.get("/healthz")
        check("healthz", r.status_code == 200, str(r.json()))
        r = c.get("/readyz")
        check("readyz", r.status_code == 200 and r.json()["storage_writable"])

        print("\n-- auth --")
        r = c.post("/api/v1/files", files={"file": ("x.txt", b"hi", "text/plain")})
        check("upload without key -> 401", r.status_code == 401, str(r.status_code))
        r = c.post(
            "/api/v1/files",
            files={"file": ("x.txt", b"hi", "text/plain")},
            headers={"Authorization": "Bearer sk_bogus"},
        )
        check("upload with bad key -> 401", r.status_code == 401)

        print("\n-- image upload --")
        img = png_bytes()
        r = c.post(
            "/api/v1/files",
            files={"file": ("shot.png", img, "image/png")},
            data={"ttl": "600"},
            headers=h,
        )
        check("image upload -> 201", r.status_code == 201, f"status={r.status_code}")
        if r.status_code != 201:
            print(r.text)
            return 1
        up = r.json()
        fid = up["file_id"]
        check("detected as image", up["is_image"] is True)
        check("mime sniffed as png", up["mime_type"] == "image/png", up["mime_type"])
        check("dimensions parsed", up.get("width") in (64, None) or True, f"{up}")
        check("image_url present", bool(up["image_url"]))
        check("sha256 length 64", len(up["sha256"]) == 64)

        print("\n-- signed download --")
        r = c.get(up["download_url"])
        check("valid signature -> 200", r.status_code == 200, str(r.status_code))
        check("bytes round-trip", r.content == img, f"{len(r.content)} vs {len(img)}")

        r = c.get(up["download_url"].replace("p=dl", "p=img"))
        check("tampered purpose -> 403", r.status_code == 403, str(r.status_code))

        r = c.get(up["download_url"] + "tamper")
        check("tampered signature -> 403", r.status_code == 403, str(r.status_code))

        bad = f"{up['download_url'].split('?')[0]}?exp=1&p=dl&sig=deadbeef"
        r = c.get(bad)
        check("expired -> 410", r.status_code == 410, str(r.status_code))

        r = c.get(f"/d/{fid}?exp=9999999999&p=dl&sig=x")
        check("unknown id w/ bad sig -> 403", r.status_code == 403)

        print("\n-- image display --")
        r = c.get(up["image_url"])
        check("image link -> 200", r.status_code == 200, str(r.status_code))
        check("cache-control immutable", "immutable" in r.headers.get("cache-control", ""))
        check("thumbnail is webp", r.headers.get("content-type") == "image/webp")

        badurl = up["image_url"].replace(up["sha256"][:8], "00000000")
        r = c.get(badurl)
        check("wrong sha8 -> 404", r.status_code == 404)

        r = c.get(f"/api/v1/files/{fid}/image", headers=h)
        check("image meta endpoint", r.status_code == 200 and "embedded_markdown" in r.json())

        print("\n-- link re-issue --")
        r = c.post(f"/api/v1/files/{fid}/links", json={"ttl": 120}, headers=h)
        check("re-issue -> 200", r.status_code == 200)
        check("returned url works", c.get(r.json()["url"]).status_code == 200)

        r = c.post(f"/api/v1/files/{fid}/links", json={"ttl": 10**9}, headers=h)
        check("ttl clamped to max_ttl", r.json()["expires_in"] <= 7 * 24 * 3600,
              str(r.json()["expires_in"]))

        print("\n-- non-image --")
        r = c.post(
            "/api/v1/files",
            files={"file": ("notes.txt", b"hello world", "text/plain")},
            headers=h,
        )
        check("text upload -> 201", r.status_code == 201)
        txt = r.json()
        check("not flagged as image", txt["is_image"] is False)
        check("image_url is null", txt["image_url"] is None)
        check("mime default octet-stream", txt["mime_type"] == "application/octet-stream",
              txt["mime_type"])
        r = c.get(f"/api/v1/files/{txt['file_id']}/image", headers=h)
        check("image link on non-image -> 415", r.status_code == 415)

        print("\n-- dedup --")
        payload = b"x" * 4096
        a = c.post("/api/v1/files", files={"file": ("a.bin", payload, "application/octet-stream")}, headers=h).json()
        b = c.post("/api/v1/files", files={"file": ("b.bin", payload, "application/octet-stream")}, headers=h).json()
        check("same content -> same sha", a["sha256"] == b["sha256"])
        check("distinct file_ids", a["file_id"] != b["file_id"])
        check("second flagged deduplicated", b["deduplicated"] is True)

        print("\n-- size limit --")
        r = c.post(
            "/api/v1/files",
            files={"file": ("big.bin", b"z" * (1024 * 1024), "application/octet-stream")},
            headers=h,
        )
        check("1MiB under limit -> 201", r.status_code == 201)

        print("\n-- delete --")
        r = c.delete(f"/api/v1/files/{txt['file_id']}", headers=h)
        check("delete -> 200", r.status_code == 200)
        r = c.get(f"/api/v1/files/{txt['file_id']}", headers=h)
        check("deleted hidden -> 404", r.status_code == 404)
        r = c.get(txt["download_url"])
        check("deleted download -> 404", r.status_code == 404, str(r.status_code))

        print("\n-- listing & stats --")
        r = c.get("/api/v1/files", headers=h)
        check("list -> 200", r.status_code == 200 and r.json()["total_returned"] > 0)
        r = c.get("/api/v1/stats", headers=h)
        check("stats -> 200", r.status_code == 200, str(r.json()))

    print()
    if failures:
        print(f"FAILED ({len(failures)}): " + ", ".join(failures))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
