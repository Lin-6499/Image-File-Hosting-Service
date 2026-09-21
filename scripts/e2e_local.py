"""Local end-to-end verification against a real running uvicorn server.

Unlike smoke_test.py (in-process ASGI transport), this script talks to the
server over real HTTP/TCP, so it exercises the actual network stack, the real
request path, and the on-disk state.

Usage:
    python -m uvicorn app.main:app --port 8021 &
    python scripts/e2e_local.py http://127.0.0.1:8021

Exit code 0 = all checks passed, 1 = at least one failure.
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

import httpx
from PIL import Image

# Running `python scripts/e2e_local.py` puts scripts/ on sys.path[0], not the
# project root, so the `app` package would not resolve. Add the root explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8021"

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


def banner(text: str) -> None:
    print()
    print(f"-- {text} --")


def png_bytes(size=(120, 80), color=(30, 120, 200)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def jpeg_with_gps() -> bytes:
    """A JPEG carrying GPS tags, so we can prove they are stripped server-side."""
    from PIL import Image as I
    from PIL.TiffImagePlugin import IFDRational

    buf = io.BytesIO()
    im = I.new("RGB", (100, 100), (200, 60, 60))
    exif = im.getexif()
    gps = exif.get_ifd(0x8825)
    gps[1] = "N"
    gps[2] = (IFDRational(39, 1), IFDRational(54, 1), IFDRational(26, 1))
    im.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def has_gps(blob: bytes) -> bool:
    im = Image.open(io.BytesIO(blob))
    return dict(im.getexif().get_ifd(0x8825)) != {}


def main() -> int:
    global PASS, FAIL

    print("=" * 64)
    print(f"  Local end-to-end verification -> {BASE}")
    print("=" * 64)

    # Mint a fresh API key through the project's own DB API. The private key
    # lives in the server's data/host.db, so this works out of process.
    from app.config import get_settings
    from app.db import Database

    settings = get_settings()
    db = Database(settings.db_path, journal_mode=settings.db_journal_mode)
    db.init()
    key_id, raw_key = db.create_api_key("e2e-local")
    auth = {"Authorization": f"Bearer {raw_key}"}

    # trust_env=False matters: httpx otherwise honours HTTP_PROXY/HTTPS_PROXY
    # from the environment. Any machine that sets a proxy without also setting
    # NO_PROXY -- sandboxes and CI images routinely do -- will send these
    # loopback requests through it, and a proxy that hiccups returns an empty
    # body that surfaces here as a bogus JSONDecodeError on the first call.
    # Loopback traffic must never be proxied.
    with httpx.Client(base_url=BASE, timeout=20.0, trust_env=False) as c:
        # ---------------------------------------------------------- health
        banner("liveness & readiness")
        r = c.get("/healthz")
        check("GET /healthz -> 200", r.status_code == 200, f"{r.status_code}")
        check("health status ok", r.json().get("status") == "ok", r.text.strip())

        r = c.get("/readyz")
        check("GET /readyz -> 200", r.status_code == 200, f"{r.status_code}")
        check("storage writable", r.json().get("storage_writable") is True, r.text.strip())

        r = c.get("/docs")
        check("GET /docs -> 200", r.status_code == 200, f"{r.status_code}")

        r = c.get("/openapi.json")
        ops = sum(len(v) for v in r.json().get("paths", {}).values())
        check("openapi operations == 11", ops == 11, f"{ops}")

        # ------------------------------------------------------ auth gate
        banner("authentication gate")
        r = c.post("/api/v1/files", files={"file": ("a.txt", b"x")})
        check("no api key -> 401", r.status_code == 401, f"{r.status_code}")
        r = c.post("/api/v1/files",
                   files={"file": ("a.txt", b"x")},
                   headers={"Authorization": "Bearer definitely-not-valid"})
        check("bad api key -> 401", r.status_code == 401, f"{r.status_code}")
        r = c.post("/api/v1/files",
                   files={"file": ("a.txt", b"x")},
                   headers={"Authorization": raw_key})
        check("scheme-less header -> 401", r.status_code == 401, f"{r.status_code}")

        # --------------------------------------------------------- upload
        banner("upload + signed links (real HTTP)")
        r = c.post("/api/v1/files",
                   files={"file": ("photo.png", png_bytes(), "image/png")},
                   headers=auth)
        check("upload PNG -> 201", r.status_code == 201, f"{r.status_code}")
        body = r.json()
        file_id = body["file_id"]
        dl_url = body["download_url"]
        img_url = body["image_url"]
        check("download_url present", bool(dl_url))
        check("image_url present", bool(img_url))
        check("is_image true", body.get("is_image") is True, str(body.get("is_image")))

        # The returned URLs are absolute against BASE_URL (port 8000 in .env).
        # Rewrite the host so we hit the port this server actually listens on.
        def retarget(u: str) -> str:
            if not u:
                return u
            _, _, rest = u.partition("://")
            _, _, path = rest.partition("/")
            return f"{BASE}/{path}"

        r = c.get(retarget(dl_url))
        check("download link -> 200", r.status_code == 200, f"{r.status_code}")
        check("download bytes intact", r.content == png_bytes(), f"{len(r.content)} bytes")
        check("content-disposition attached",
              "attachment" in r.headers.get("content-disposition", ""),
              r.headers.get("content-disposition", ""))

        r = c.get(retarget(img_url))
        check("image link -> 200", r.status_code == 200, f"{r.status_code}")
        cache = r.headers.get("cache-control", "")
        check("immutable cache-control", "immutable" in cache, cache)

        # -------------------------------------------------- signature maths
        banner("signature tampering")
        parsed = httpx.URL(retarget(dl_url))
        params = dict(parsed.params)

        tampered = dict(params)
        tampered["p"] = "img"
        r = c.get(str(parsed.copy_with(query=None)), params=tampered)
        check("purpose swap -> 403", r.status_code == 403, f"{r.status_code}")

        tampered = dict(params)
        tampered["sig"] = tampered["sig"][:-1] + ("A" if tampered["sig"][-1] != "A" else "B")
        r = c.get(str(parsed.copy_with(query=None)), params=tampered)
        check("signature flip -> 403", r.status_code == 403, f"{r.status_code}")

        # Expiry is checked BEFORE the signature. Rewriting `exp` to the past
        # therefore yields 410 Gone regardless of whether the MAC is valid --
        # a deliberate order, so the server fails fast and never leaks whether
        # a supplied signature was genuine.
        tampered = dict(params)
        tampered["exp"] = str(int(time.time()) - 60)
        r = c.get(str(parsed.copy_with(query=None)), params=tampered)
        check("exp rewritten to past -> 410 (expiry checked first)",
              r.status_code == 410, f"{r.status_code}")

        from app.config import get_settings as _gs
        from app.signing import sign as _sign

        _secret = _gs().secret_key
        past = int(time.time()) - 60
        expired_sig = _sign(file_id, past, "dl", _secret)
        r = c.get(f"/d/{file_id}",
                  params={"exp": past, "p": "dl", "sig": expired_sig})
        check("properly signed but expired -> 410", r.status_code == 410, f"{r.status_code}")

        # A still-valid exp with a wrong signature must be 403, proving the
        # signature is genuinely verified rather than bypassed by the exp path.
        future = int(time.time()) + 600
        bogus = _sign(file_id, future, "img", _secret)
        r = c.get(f"/d/{file_id}", params={"exp": future, "p": "dl", "sig": bogus})
        check("valid exp but wrong-payload sig -> 403", r.status_code == 403,
              f"{r.status_code}")

        # ------------------------------------------------------ link reissue
        banner("link re-issue")
        r = c.post(f"/api/v1/files/{file_id}/links", json={"ttl": 120}, headers=auth)
        check("re-issue -> 200", r.status_code == 200, f"{r.status_code}")
        fresh = r.json()["url"]
        check("re-issue ttl honoured", r.json()["expires_in"] == 120,
              str(r.json()["expires_in"]))
        r = c.get(retarget(fresh))
        check("fresh link works", r.status_code == 200, f"{r.status_code}")

        r = c.post(f"/api/v1/files/{file_id}/links", json={"ttl": 10_000_000}, headers=auth)
        check("ttl clamped to max_ttl", r.json()["expires_in"] == settings.max_ttl,
              f"{r.json()['expires_in']} vs max {settings.max_ttl}")

        r = c.post(f"/api/v1/files/{file_id}/links", json={"purpose": "img"}, headers=auth)
        check("img purpose accepted", r.status_code == 200, f"{r.status_code}")
        check("img signature != dl signature", r.json()["url"] != fresh)

        # ------------------------------------------------------ EXIF privacy
        banner("EXIF stripping (privacy)")
        raw = jpeg_with_gps()
        check("fixture carries GPS", has_gps(raw), "precondition")
        r = c.post("/api/v1/files",
                   files={"file": ("geo.jpg", raw, "image/jpeg")},
                   headers=auth)
        check("upload geo JPEG -> 201", r.status_code == 201, f"{r.status_code}")
        stored = c.get(retarget(r.json()["download_url"])).content
        check("GPS removed server-side", not has_gps(stored))

        # -------------------------------------------------------- non-image
        banner("non-image handling")
        r = c.post("/api/v1/files",
                   files={"file": ("notes.txt", b"hello world", "text/plain")},
                   headers=auth)
        check("text upload -> 201", r.status_code == 201, f"{r.status_code}")
        nb = r.json()
        check("not flagged as image", nb.get("is_image") is False)
        check("image_url is null", nb.get("image_url") is None)
        r = c.get(retarget(nb["download_url"]))
        check("text download -> 200", r.status_code == 200, f"{r.status_code}")
        check("mime defaults octet-stream",
              r.headers.get("content-type", "").startswith("application/octet-stream"),
              r.headers.get("content-type", ""))

        # ---------------------------------------------------------- dedup
        banner("content dedup")
        payload = png_bytes(size=(64, 64), color=(9, 9, 9))
        r1 = c.post("/api/v1/files",
                    files={"file": ("dup1.png", payload, "image/png")}, headers=auth)
        r2 = c.post("/api/v1/files",
                    files={"file": ("dup2.png", payload, "image/png")}, headers=auth)
        check("same sha256 for identical content",
              r1.json()["sha256"] == r2.json()["sha256"])
        check("distinct file_ids", r1.json()["file_id"] != r2.json()["file_id"])
        check("second flagged deduplicated", r2.json().get("deduplicated") is True,
              str(r2.json().get("deduplicated")))

        # ----------------------------------------------------- delete flow
        banner("soft delete")
        r = c.delete(f"/api/v1/files/{file_id}", headers=auth)
        check("delete -> 200", r.status_code == 200, f"{r.status_code}")
        r = c.get(retarget(dl_url))
        check("deleted download -> 404", r.status_code == 404, f"{r.status_code}")
        r = c.get(f"/api/v1/files/{file_id}", headers=auth)
        check("deleted meta -> 404", r.status_code == 404, f"{r.status_code}")
        r = c.delete(f"/api/v1/files/{file_id}", headers=auth)
        check("second delete -> 404", r.status_code == 404, f"{r.status_code}")

        # -------------------------------------------------------- listing
        banner("listing & stats")
        r = c.get("/api/v1/files", headers=auth)
        check("list -> 200", r.status_code == 200, f"{r.status_code}")
        check("list has items", len(r.json().get("items", [])) > 0,
              f"{len(r.json().get('items', []))} items")
        r = c.get("/api/v1/stats", headers=auth)
        check("stats -> 200", r.status_code == 200, f"{r.status_code}")
        print(f"    stats: {r.json()}")

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
