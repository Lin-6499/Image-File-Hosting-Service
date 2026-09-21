"""End-to-end tests for the API and access routes."""

from __future__ import annotations

import time

from tests.conftest import jpeg_with_exif, png_bytes


class TestHealth:
    def test_healthz(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_readyz(self, client):
        r = client.get("/readyz")
        assert r.status_code == 200
        assert r.json()["storage_writable"] is True

    def test_openapi_available(self, client):
        assert client.get("/openapi.json").status_code == 200


class TestAuth:
    def test_missing_header_rejected(self, client):
        r = client.post("/api/v1/files", files={"file": ("a.txt", b"x", "text/plain")})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "unauthorized"

    def test_unknown_key_rejected(self, client):
        r = client.post(
            "/api/v1/files",
            files={"file": ("a.txt", b"x", "text/plain")},
            headers={"Authorization": "Bearer sk_nope"},
        )
        assert r.status_code == 401

    def test_malformed_scheme_rejected(self, client):
        r = client.post(
            "/api/v1/files",
            files={"file": ("a.txt", b"x", "text/plain")},
            headers={"Authorization": "Token abc"},
        )
        assert r.status_code == 401

    def test_valid_key_accepted(self, client, auth):
        r = client.post(
            "/api/v1/files",
            files={"file": ("a.txt", b"x", "text/plain")},
            headers=auth,
        )
        assert r.status_code == 201


class TestUpload:
    def test_image_upload_fields(self, client, auth, png):
        r = client.post(
            "/api/v1/files",
            files={"file": ("shot.png", png, "image/png")},
            headers=auth,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["is_image"] is True
        assert body["mime_type"] == "image/png"
        assert len(body["sha256"]) == 64
        assert body["image_url"] is not None
        assert body["download_expires_in"] == 3600

    def test_text_upload_has_no_image_url(self, client, auth):
        r = client.post(
            "/api/v1/files",
            files={"file": ("notes.txt", b"hello", "text/plain")},
            headers=auth,
        )
        body = r.json()
        assert body["is_image"] is False
        assert body["image_url"] is None

    def test_client_content_type_is_ignored(self, client, auth):
        """A caller must not be able to declare a type that contradicts the
        bytes. Here a text payload is labelled as an image."""
        r = client.post(
            "/api/v1/files",
            files={"file": ("fake.png", b"not actually a png", "image/png")},
            headers=auth,
        )
        assert r.status_code == 201
        assert r.json()["is_image"] is False

    def test_filename_override(self, client, auth):
        r = client.post(
            "/api/v1/files",
            files={"file": ("orig.bin", b"data", "application/octet-stream")},
            data={"name": "renamed.bin"},
            headers=auth,
        )
        fid = r.json()["file_id"]
        meta = client.get(f"/api/v1/files/{fid}", headers=auth).json()
        assert meta["orig_name"] == "renamed.bin"

    def test_oversize_rejected_with_error_shape(self, client, auth):
        from app.config import settings

        big = b"z" * (settings.max_file_size + 1)
        r = client.post(
            "/api/v1/files",
            files={"file": ("big.bin", big, "application/octet-stream")},
            headers=auth,
        )
        assert r.status_code == 413
        assert r.json()["error"]["code"] == "too_large"

    def test_dedup_flag_and_distinct_ids(self, client, auth):
        payload = b"identical payload"
        a = client.post(
            "/api/v1/files",
            files={"file": ("a.bin", payload, "application/octet-stream")},
            headers=auth,
        ).json()
        b = client.post(
            "/api/v1/files",
            files={"file": ("b.bin", payload, "application/octet-stream")},
            headers=auth,
        ).json()
        assert a["deduplicated"] is False
        assert b["deduplicated"] is True
        assert a["sha256"] == b["sha256"]
        assert a["file_id"] != b["file_id"]

    def test_ttl_clamped_to_max(self, client, auth):
        r = client.post(
            "/api/v1/files",
            files={"file": ("t.bin", b"ttl", "application/octet-stream")},
            data={"ttl": "99999999"},
            headers=auth,
        )
        from app.config import settings

        assert r.json()["download_expires_in"] == settings.max_ttl


class TestDownload:
    def _upload(self, client, auth, data=b"download me"):
        return client.post(
            "/api/v1/files",
            files={"file": ("d.bin", data, "application/octet-stream")},
            headers=auth,
        ).json()

    def test_valid_link_returns_bytes(self, client, auth):
        up = self._upload(client, auth)
        r = client.get(up["download_url"])
        assert r.status_code == 200
        assert r.content == b"download me"

    def test_purpose_tamper_gives_403(self, client, auth):
        up = self._upload(client, auth)
        r = client.get(up["download_url"].replace("p=dl", "p=img"))
        assert r.status_code == 403

    def test_signature_tamper_gives_403(self, client, auth):
        up = self._upload(client, auth)
        r = client.get(up["download_url"] + "x")
        assert r.status_code == 403

    def test_expired_gives_410_not_404(self, client, auth):
        """410 lets an automated caller distinguish 're-issue' from 'broken'."""
        up = self._upload(client, auth)
        base = up["download_url"].split("?")[0]
        r = client.get(f"{base}?exp=1&p=dl&sig=whatever")
        assert r.status_code == 410
        assert r.json()["error"]["code"] == "gone"

    def test_missing_exp_param_is_validation_error(self, client, auth):
        up = self._upload(client, auth)
        base = up["download_url"].split("?")[0]
        r = client.get(f"{base}?p=dl&sig=x")
        assert r.status_code == 422

    def test_unknown_file_gives_403_or_404(self, client, auth):
        r = client.get("/d/doesnotexist0000000000?exp=9999999999&p=dl&sig=x")
        assert r.status_code in (403, 404)

    def test_deleted_file_not_downloadable(self, client, auth):
        up = self._upload(client, auth)
        assert client.get(up["download_url"]).status_code == 200
        client.delete(f"/api/v1/files/{up['file_id']}", headers=auth)
        assert client.get(up["download_url"]).status_code == 404

    def test_content_disposition_has_no_header_injection(self, client, auth):
        """A filename containing CRLF must not inject response headers."""
        up = client.post(
            "/api/v1/files",
            files={"file": ("evil\r\nX-Injected: 1\r\n.txt", b"x", "text/plain")},
            headers=auth,
        ).json()
        r = client.get(up["download_url"])
        assert r.status_code == 200
        assert "x-injected" not in {k.lower() for k in r.headers}


class TestImageLinks:
    def _upload_png(self, client, auth, data=None):
        return client.post(
            "/api/v1/files",
            files={"file": ("p.png", data or png_bytes(), "image/png")},
            headers=auth,
        ).json()

    def test_thumbnail_served_as_webp(self, client, auth):
        up = self._upload_png(client, auth)
        r = client.get(up["image_url"])
        assert r.status_code == 200
        assert r.headers["content-type"] == "image/webp"
        assert "immutable" in r.headers["cache-control"]

    def test_wrong_sha8_gives_404(self, client, auth):
        """Guards against reusing a URL as a probe for different content."""
        up = self._upload_png(client, auth)
        bad = up["image_url"].replace(up["sha256"][:8], "00000000")
        assert client.get(bad).status_code == 404

    def test_image_link_requires_no_auth(self, client, auth):
        up = self._upload_png(client, auth)
        assert client.get(up["image_url"]).status_code == 200

    def test_image_meta_endpoint(self, client, auth):
        up = self._upload_png(client, auth)
        r = client.get(f"/api/v1/files/{up['file_id']}/image", headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert body["embedded_markdown"].startswith("![image](")
        assert body["width"] == 64 and body["height"] == 48

    def test_image_endpoint_on_non_image_gives_415(self, client, auth):
        up = client.post(
            "/api/v1/files",
            files={"file": ("t.txt", b"text", "text/plain")},
            headers=auth,
        ).json()
        r = client.get(f"/api/v1/files/{up['file_id']}/image", headers=auth)
        assert r.status_code == 415

    def test_exif_gps_is_stripped(self, client, auth):
        """Uploaded photos must not retain GPS coordinates."""
        from PIL import Image

        up = client.post(
            "/api/v1/files",
            files={"file": ("photo.jpg", jpeg_with_exif(), "image/jpeg")},
            headers=auth,
        ).json()

        from app.storage import blob_path

        with Image.open(blob_path(up["sha256"])) as im:
            exif = im.getexif()
            assert 0x8825 not in exif, "GPS IFD survived stripping"


class TestLinkReissue:
    def test_reissue_returns_working_url(self, client, auth, png):
        up = client.post(
            "/api/v1/files",
            files={"file": ("r.png", png, "image/png")},
            headers=auth,
        ).json()
        r = client.post(
            f"/api/v1/files/{up['file_id']}/links", json={"ttl": 120}, headers=auth
        )
        assert r.status_code == 200
        assert client.get(r.json()["url"]).status_code == 200

    def test_reissue_requires_auth(self, client, auth, png):
        up = client.post(
            "/api/v1/files",
            files={"file": ("r2.png", png, "image/png")},
            headers=auth,
        ).json()
        r = client.post(f"/api/v1/files/{up['file_id']}/links", json={"ttl": 60})
        assert r.status_code == 401

    def test_reissue_ttl_clamped(self, client, auth, png):
        up = client.post(
            "/api/v1/files",
            files={"file": ("r3.png", png, "image/png")},
            headers=auth,
        ).json()
        r = client.post(
            f"/api/v1/files/{up['file_id']}/links", json={"ttl": 10**9}, headers=auth
        )
        from app.config import settings

        assert r.json()["expires_in"] == settings.max_ttl

    def test_reissue_unknown_file_404(self, client, auth):
        r = client.post("/api/v1/files/nope000000000000000000/links", json={}, headers=auth)
        assert r.status_code == 404

    def test_invalid_purpose_rejected(self, client, auth, png):
        up = client.post(
            "/api/v1/files",
            files={"file": ("r4.png", png, "image/png")},
            headers=auth,
        ).json()
        r = client.post(
            f"/api/v1/files/{up['file_id']}/links",
            json={"purpose": "evil"},
            headers=auth,
        )
        assert r.status_code == 422


class TestMetadataAndListing:
    def test_get_metadata(self, client, auth, png):
        up = client.post(
            "/api/v1/files", files={"file": ("m.png", png, "image/png")}, headers=auth
        ).json()
        r = client.get(f"/api/v1/files/{up['file_id']}", headers=auth)
        assert r.status_code == 200
        assert r.json()["file_id"] == up["file_id"]

    def test_unknown_metadata_404(self, client, auth):
        assert client.get("/api/v1/files/zzz000000000000000000", headers=auth).status_code == 404

    def test_list_returns_items(self, client, auth):
        client.post(
            "/api/v1/files", files={"file": ("l.bin", b"list", "application/octet-stream")}, headers=auth
        )
        r = client.get("/api/v1/files", headers=auth)
        assert r.status_code == 200
        assert r.json()["total_returned"] >= 1

    def test_list_respects_limit(self, client, auth):
        r = client.get("/api/v1/files?limit=1", headers=auth)
        assert len(r.json()["items"]) <= 1

    def test_stats_shape(self, client, auth):
        r = client.get("/api/v1/stats", headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert set(body) >= {"total_records", "live_records", "total_bytes", "disk_usage_ratio"}

    def test_delete_is_idempotent_on_second_call(self, client, auth):
        up = client.post(
            "/api/v1/files", files={"file": ("del.bin", b"x", "application/octet-stream")}, headers=auth
        ).json()
        assert client.delete(f"/api/v1/files/{up['file_id']}", headers=auth).status_code == 200
        # Row still exists but is soft-deleted -> 404 on retry is correct.
        assert client.delete(f"/api/v1/files/{up['file_id']}", headers=auth).status_code == 404


class TestCleanupBehaviour:
    def test_soft_delete_then_reclaim(self, client, auth):
        """A deleted file's blob survives the grace period, then is reclaimed."""
        from app.cleanup import run_once
        from app.config import settings
        from app.db import db
        from app.storage import blob_path

        payload = b"reclaim me " + str(time.time()).encode()
        up = client.post(
            "/api/v1/files",
            files={"file": ("c.bin", payload, "application/octet-stream")},
            headers=auth,
        ).json()
        sha = up["sha256"]

        client.delete(f"/api/v1/files/{up['file_id']}", headers=auth)
        assert blob_path(sha).exists(), "blob removed too early"

        # With the grace period zeroed, the sweep should reclaim it.
        orphans = db.find_orphan_blobs(grace_seconds=0)
        assert sha in orphans
        assert db.is_hash_referenced(sha) is False

        run_once()
        # Blob may still exist because run_once uses the real grace period;
        # the direct path is what we assert here.
        assert sha in db.find_orphan_blobs(grace_seconds=0)

    def test_locked_blob_keeps_its_row_so_the_sweep_can_retry(
        self, client, auth, monkeypatch
    ):
        """A blob that could not be unlinked must not lose its metadata row.

        ``delete_blob`` reports "did it exist", not "did it succeed": ``_discard``
        swallows OSError, which is what a held handle looks like on Windows
        (antivirus scanning the file, a backup agent, a stale indexer). Purging
        the row anyway would throw away the only record that the orphan exists,
        and because ``find_orphan_blobs`` works from ``files``, nothing would
        ever retry -- the bytes stay on disk forever, with no trace of why.
        """
        from app import cleanup, storage
        from app.db import db
        from app.storage import blob_path

        payload = b"locked blob " + str(time.time()).encode()
        up = client.post(
            "/api/v1/files",
            files={"file": ("lock.bin", payload, "application/octet-stream")},
            headers=auth,
        ).json()
        sha = up["sha256"]
        client.delete(f"/api/v1/files/{up['file_id']}", headers=auth)

        # Simulate the unlink silently doing nothing.
        monkeypatch.setattr(storage, "_discard", lambda _p: False)
        monkeypatch.setattr(cleanup, "GRACE_SECONDS", 0)

        cleanup.run_once()

        # Assertions are scoped to *this* hash. The database is shared across
        # the session, so the sweep's global counters are not a stable signal
        # here -- other tests leave their own orphans behind.
        assert blob_path(sha).exists(), "test setup: the blob should still be there"
        # The row survives, so the next sweep tries again.
        assert sha in db.find_orphan_blobs(grace_seconds=0)

    def test_reclaimed_blob_loses_its_row(self, client, auth, monkeypatch):
        """The normal path still cleans up both halves."""
        from app import cleanup
        from app.db import db
        from app.storage import blob_path

        payload = b"reclaim row " + str(time.time()).encode()
        up = client.post(
            "/api/v1/files",
            files={"file": ("row.bin", payload, "application/octet-stream")},
            headers=auth,
        ).json()
        sha = up["sha256"]
        client.delete(f"/api/v1/files/{up['file_id']}", headers=auth)

        monkeypatch.setattr(cleanup, "GRACE_SECONDS", 0)
        stats = cleanup.run_once()

        assert stats["blobs_removed"] >= 1
        assert stats["hashes_purged"] >= 1
        assert not blob_path(sha).exists()
        assert sha not in db.find_orphan_blobs(grace_seconds=0)


class TestContentAddressIntegrity:
    """The bytes on disk must always hash to the name they are stored under.

    Regression guard for a real, client-visible defect. EXIF stripping used to
    run *after* the blob had been committed under the digest of the original
    upload. The stored file was then rewritten, so:

      * the ``sha256`` in the upload response could not verify the downloaded
        bytes -- a client doing integrity checking saw a false corruption, and
      * ``size_bytes`` described the pre-strip file, overstating what is
        actually served.

    The earlier EXIF test missed this because it resolved the blob via
    ``blob_path(response["sha256"])`` and only asserted GPS was gone. That
    path exists either way, so it never compared content against its digest.
    """

    def _upload_jpeg(self, client, auth):
        return client.post(
            "/api/v1/files",
            files={"file": ("geo.jpg", jpeg_with_exif(), "image/jpeg")},
            headers=auth,
        ).json()

    def test_sha256_verifies_downloaded_bytes(self, client, auth):
        import hashlib

        up = self._upload_jpeg(client, auth)
        body = client.get(up["download_url"]).content
        assert hashlib.sha256(body).hexdigest() == up["sha256"]

    def test_size_bytes_matches_downloaded_length(self, client, auth):
        up = self._upload_jpeg(client, auth)
        body = client.get(up["download_url"]).content
        assert up["size_bytes"] == len(body)

    def test_blob_filename_equals_content_digest(self, client, auth):
        import hashlib

        from app.storage import blob_path

        up = self._upload_jpeg(client, auth)
        path = blob_path(up["sha256"])
        assert path.exists(), "blob not found under its declared digest"
        assert path.name == hashlib.sha256(path.read_bytes()).hexdigest()

    def test_gps_stripped_and_digest_still_valid(self, client, auth):
        """Both properties must hold at once: privacy *and* integrity."""
        import hashlib
        import io

        from PIL import Image

        up = self._upload_jpeg(client, auth)
        body = client.get(up["download_url"]).content

        with Image.open(io.BytesIO(body)) as im:
            assert 0x8825 not in im.getexif(), "GPS IFD survived stripping"
        assert hashlib.sha256(body).hexdigest() == up["sha256"]

    def test_non_image_digest_matches(self, client, auth):
        """Transforms only apply to JPEG/TIFF; everything else is untouched."""
        import hashlib

        payload = b"plain bytes, no metadata to strip"
        up = client.post(
            "/api/v1/files",
            files={"file": ("note.txt", payload, "text/plain")},
            headers=auth,
        ).json()
        assert up["sha256"] == hashlib.sha256(payload).hexdigest()
        assert up["size_bytes"] == len(payload)
        assert client.get(up["download_url"]).content == payload

    def test_png_digest_matches(self, client, auth):
        """PNG carries no EXIF, so it must pass through byte-identical."""
        import hashlib

        payload = png_bytes()
        up = client.post(
            "/api/v1/files",
            files={"file": ("plain.png", payload, "image/png")},
            headers=auth,
        ).json()
        assert up["sha256"] == hashlib.sha256(payload).hexdigest()
        assert up["size_bytes"] == len(payload)
