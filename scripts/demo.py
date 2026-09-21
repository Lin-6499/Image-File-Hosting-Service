"""End-to-end demo: upload a generated image, fetch its links, download it.

    .venv\\Scripts\\python.exe -m scripts.demo
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import db  # noqa: E402

BASE = settings.base_url


def make_test_image() -> bytes:
    img = Image.new("RGB", (800, 480), (28, 30, 40))
    d = ImageDraw.Draw(img)
    for i in range(0, 800, 40):
        d.line([(i, 0), (i, 480)], fill=(50, 55, 70), width=1)
    for i in range(0, 480, 40):
        d.line([(0, i), (800, i)], fill=(50, 55, 70), width=1)
    d.rectangle([60, 60, 740, 420], outline=(120, 180, 255), width=4)
    d.text((100, 220), "hosting service demo", fill=(230, 235, 245))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main() -> int:
    db.init()
    _, key = db.create_api_key("demo")
    h = {"Authorization": f"Bearer {key}"}

    # trust_env=False: see the note in e2e_local.py. An ambient HTTP_PROXY with
    # no NO_PROXY sends loopback requests through a proxy, which flakes.
    with httpx.Client(base_url=BASE, timeout=30.0, trust_env=False) as c:
        print(f"[1] health  : {c.get('/healthz').json()}")

        payload = make_test_image()
        print(f"[2] upload  : POST /api/v1/files  ({len(payload)} bytes)")

        r = c.post(
            "/api/v1/files",
            files={"file": ("demo.png", payload, "image/png")},
            data={"ttl": "300"},
            headers=h,
        )
        r.raise_for_status()
        up = r.json()

        print(f"    file_id        : {up['file_id']}")
        print(f"    mime / size    : {up['mime_type']} / {up['size_bytes']}")
        print(f"    sha256         : {up['sha256'][:32]}...")
        print(f"    downloads in   : {up['download_expires_in']}s")
        print(f"    download_url   : {up['download_url'][:88]}...")
        print(f"    image_url      : {up['image_url']}")

        print("\n[3] signed download")
        r = c.get(up["download_url"])
        print(f"    GET download_url   -> {r.status_code}  ({len(r.content)} bytes)")

        r = c.get(up["download_url"].replace("p=dl", "p=img"))
        print(f"    purpose tampered   -> {r.status_code}  (expected 403)")

        r = c.get(f"/d/{up['file_id']}?exp=1&p=dl&sig=x")
        print(f"    forced expiry      -> {r.status_code}  (expected 410)")

        print("\n[4] image display")
        r = c.get(up["image_url"])
        print(f"    GET image_url      -> {r.status_code}  "
              f"{r.headers.get('content-type')}  cache={r.headers.get('cache-control')}")

        r = c.get(f"/api/v1/files/{up['file_id']}/image", headers=h)
        print(f"    markdown           : {r.json()['embedded_markdown']}")

        print("\n[5] re-issue link")
        r = c.post(f"/api/v1/files/{up['file_id']}/links", json={"ttl": 60}, headers=h)
        print(f"    POST /links        -> {r.status_code}  expires_in={r.json()['expires_in']}s")

        print("\n[6] stats")
        print(f"    {c.get('/api/v1/stats', headers=h).json()}")

    print("\nDemo complete. Open the image_url in a browser to view it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
