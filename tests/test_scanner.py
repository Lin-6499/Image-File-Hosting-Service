"""Tests for antivirus scanning and the pending/infected gates.

The stub scanner is used throughout so the suite runs without ClamAV. The
important properties under test are the *gating* rules -- that a file which has
not cleared scanning cannot be served -- rather than the ClamAV wire protocol.
"""

from __future__ import annotations

import time

import pytest

from app import scanservice
from app.scanner import (
    ClamdScanner,
    ClamscanScanner,
    ScanError,
    ScanResult,
    StubScanner,
    build_scanner,
)
from app.storage import blob_path
from tests.conftest import png_bytes


@pytest.fixture(autouse=True)
def clear_scanner_cache():
    """Each test starts with no cached scanner resolution."""
    scanservice.reset_scanner_cache()
    yield
    scanservice.reset_scanner_cache()


def force_stub(monkeypatch, verdicts=None, default="clean"):
    """Install a stub scanner and make scanning appear enabled."""
    stub = StubScanner(verdicts=verdicts, default=default)
    monkeypatch.setattr(scanservice, "get_scanner", lambda: stub)
    monkeypatch.setattr(scanservice, "scanning_enabled", lambda: True)
    return stub


def disable_scanning(monkeypatch):
    monkeypatch.setattr(scanservice, "get_scanner", lambda: None)
    monkeypatch.setattr(scanservice, "scanning_enabled", lambda: False)


class TestStubScanner:
    def test_default_clean(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"data")
        assert StubScanner().scan(f).status == "clean"

    def test_verdict_by_content(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"harmless EICAR_TEST payload")
        assert StubScanner({"EICAR_TEST": "infected"}).scan(f).status == "infected"

    def test_matches_content_not_filename(self, tmp_path):
        """Regression guard.

        Blobs are content-addressed, so the scanner only ever sees the hash as
        the filename. A stub keyed on the filename would never fire in
        production -- and worse, its tests would still pass. This asserts the
        content is what matters.
        """
        named_to_look_infected = tmp_path / "eicar.com"
        named_to_look_infected.write_bytes(b"totally benign")
        assert StubScanner({"eicar": "infected"}).scan(named_to_look_infected).status == "clean"

        innocuous_name = tmp_path / "abcdef0123456789"
        innocuous_name.write_bytes(b"contains eicar marker")
        assert StubScanner({"eicar": "infected"}).scan(innocuous_name).status == "infected"

    def test_records_calls(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"data")
        s = StubScanner()
        s.scan(f)
        assert s.calls == [f]

    def test_unreadable_file_raises(self, tmp_path):
        missing = tmp_path / "nope.bin"
        with pytest.raises(ScanError):
            StubScanner().scan(missing)


class TestBuildScanner:
    def test_none_backend_disables(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "av_backend", "none")
        assert build_scanner() is None

    def test_stub_backend_selectable(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "av_backend", "stub")
        s = build_scanner()
        assert s is not None and s.name == "stub"

    def test_unknown_backend_disables_not_crashes(self, monkeypatch):
        from app import config

        monkeypatch.setattr(config.settings, "av_backend", "nonsense")
        assert build_scanner() is None

    def test_unreachable_backend_disables_without_raising(self, monkeypatch):
        """A misconfigured deployment must still boot."""
        from app import config

        monkeypatch.setattr(config.settings, "av_backend", "clamd")
        monkeypatch.setattr(config.settings, "clamd_host", "127.0.0.1")
        monkeypatch.setattr(config.settings, "clamd_port", 1)  # nothing listens
        monkeypatch.setattr(config.settings, "clamd_socket", "")
        monkeypatch.setattr(config.settings, "av_timeout", 0.3)
        assert build_scanner() is None


class TestClamdScanner:
    def test_unreachable_raises_scan_error(self):
        s = ClamdScanner(host="127.0.0.1", port=1, timeout=0.3)
        with pytest.raises(ScanError):
            s.scan(__file__ and __import__("pathlib").Path(__file__))

    def test_available_false_when_unreachable(self):
        assert ClamdScanner(host="127.0.0.1", port=1, timeout=0.3).available() is False


class TestClamscanScanner:
    def test_missing_binary_raises(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"x")
        s = ClamscanScanner(binary="definitely-not-a-real-binary-xyz")
        assert s.available() is False
        with pytest.raises(ScanError):
            s.scan(f)


class TestStatusGating:
    """The core security property: unverified bytes must not be served."""

    def test_pending_file_not_downloadable(self, client, auth, monkeypatch):
        disable_scanning(monkeypatch)
        up = client.post(
            "/api/v1/files",
            files={"file": ("p.bin", b"pending content", "application/octet-stream")},
            headers=auth,
        ).json()
        assert client.get(up["download_url"]).status_code == 200

        # Force the record back to pending, as if scanning were in flight.
        from app.db import db

        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?",
                (up["file_id"],),
            )
        assert client.get(up["download_url"]).status_code == 409

    def test_infected_file_returns_403(self, client, auth, monkeypatch):
        up = client.post(
            "/api/v1/files",
            files={"file": ("v.bin", b"virus payload", "application/octet-stream")},
            headers=auth,
        ).json()

        from app.db import db

        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )
        db.set_scan_result(up["file_id"], "infected", "Eicar-Test-Signature")

        r = client.get(up["download_url"])
        assert r.status_code == 403
        assert "malware" in r.json()["error"]["message"].lower()

    def test_error_status_returns_409_not_403(self, client, auth):
        """A scanner error is transient, so the caller should retry."""
        up = client.post(
            "/api/v1/files",
            files={"file": ("e.bin", b"cannot scan", "application/octet-stream")},
            headers=auth,
        ).json()

        from app.db import db

        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )
        db.set_scan_result(up["file_id"], "error", "scanner unreachable")

        assert client.get(up["download_url"]).status_code == 409

    def test_infected_image_not_displayable(self, client, auth):
        from app.db import db

        up = client.post(
            "/api/v1/files",
            files={"file": ("bad.png", png_bytes(), "image/png")},
            headers=auth,
        ).json()
        assert client.get(up["image_url"]).status_code == 200

        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )
        db.set_scan_result(up["file_id"], "infected", "Png.Exploit")

        assert client.get(up["image_url"]).status_code == 404

    def test_clean_file_servable(self, client, auth):
        up = client.post(
            "/api/v1/files",
            files={"file": ("ok.bin", b"safe", "application/octet-stream")},
            headers=auth,
        ).json()
        assert up["servable"] is True
        assert client.get(up["download_url"]).status_code == 200

    def test_skipped_is_servable(self, client, auth):
        """With scanning off, files must behave exactly as before."""
        up = client.post(
            "/api/v1/files",
            files={"file": ("s.bin", b"unscanned", "application/octet-stream")},
            headers=auth,
        ).json()
        assert up["scan_status"] == "skipped"
        assert up["servable"] is True
        assert client.get(up["download_url"]).status_code == 200


class TestUploadIntegration:
    def test_scanning_enabled_marks_clean_and_serves(self, client, auth, monkeypatch):
        force_stub(monkeypatch, default="clean")
        up = client.post(
            "/api/v1/files",
            files={"file": ("good.bin", b"clean bytes", "application/octet-stream")},
            headers=auth,
        ).json()
        assert up["scan_status"] == "clean"
        assert up["servable"] is True
        assert client.get(up["download_url"]).status_code == 200

    def test_infected_upload_reported_and_blocked(self, client, auth, monkeypatch):
        force_stub(monkeypatch, verdicts={"MALWARE_MARKER": "infected"})
        up = client.post(
            "/api/v1/files",
            files={
                "file": ("evil.bin", b"prefix MALWARE_MARKER suffix", "application/octet-stream")
            },
            headers=auth,
        ).json()

        assert up["scan_status"] == "infected"
        assert up["servable"] is False
        assert up["scan_detail"] == "stub matched 'MALWARE_MARKER'"
        # The upload itself still succeeds: the caller needs the file_id to
        # know what happened, and the bytes never leave the server.
        assert client.get(up["download_url"]).status_code == 403

    def test_scanner_error_does_not_report_clean(self, client, auth, monkeypatch):
        """A broken scanner must never be recorded as a clean verdict."""
        stub = StubScanner()

        def boom(path):
            raise ScanError("daemon died")

        monkeypatch.setattr(stub, "scan", boom)
        monkeypatch.setattr(scanservice, "get_scanner", lambda: stub)
        monkeypatch.setattr(scanservice, "scanning_enabled", lambda: True)

        up = client.post(
            "/api/v1/files",
            files={"file": ("x.bin", b"whatever", "application/octet-stream")},
            headers=auth,
        ).json()

        assert up["scan_status"] == "error"
        assert up["scan_status"] != "clean"
        assert up["servable"] is False

    def test_metadata_exposes_scan_fields(self, client, auth, monkeypatch):
        force_stub(monkeypatch)
        up = client.post(
            "/api/v1/files",
            files={"file": ("meta.bin", b"data", "application/octet-stream")},
            headers=auth,
        ).json()
        meta = client.get(f"/api/v1/files/{up['file_id']}", headers=auth).json()
        assert meta["scan_status"] == "clean"
        assert meta["scanned_at"] is not None
        assert meta["servable"] is True


class TestScanService:
    def test_process_pending_scans_queued(self, client, auth, monkeypatch):
        from app.db import db

        stub = force_stub(monkeypatch)
        up = client.post(
            "/api/v1/files",
            files={"file": ("queued.bin", b"queue me", "application/octet-stream")},
            headers=auth,
        ).json()

        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )

        tally = scanservice.process_pending()
        assert tally["clean"] >= 1
        assert db.get_file(up["file_id"]).scan_status == "clean"

    def test_process_pending_releases_when_disabled(self, client, auth, monkeypatch):
        from app.db import db

        up = client.post(
            "/api/v1/files",
            files={"file": ("orphan.bin", b"x", "application/octet-stream")},
            headers=auth,
        ).json()
        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )

        disable_scanning(monkeypatch)
        tally = scanservice.process_pending()
        assert tally["skipped"] >= 1
        # Must not remain pending -- that would leave it unservable forever.
        assert db.get_file(up["file_id"]).scan_status == "skipped"

    def test_min_age_seconds_leaves_a_live_upload_alone(self, client, auth, monkeypatch):
        """A row younger than the grace must not be resolved.

        This is the race guard. The upload request inserts its row as
        ``pending`` and only scans *afterwards*, so a sweeper that resolves the
        row first can silently drop the request's own verdict -- and a
        transient ``error`` there is not servable.
        """
        from app.db import db

        force_stub(monkeypatch)
        up = client.post(
            "/api/v1/files",
            files={"file": ("inflight.bin", b"x", "application/octet-stream")},
            headers=auth,
        ).json()
        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )

        tally = scanservice.process_pending(min_age_seconds=3600)
        assert sum(tally.values()) == 0
        assert db.get_file(up["file_id"]).scan_status == "pending"

        # Once it ages past the window it is picked up normally.
        tally = scanservice.process_pending(min_age_seconds=0)
        assert tally["clean"] >= 1
        assert db.get_file(up["file_id"]).scan_status == "clean"

    def test_resolve_pending_reports_saturation(self, client, auth, monkeypatch):
        """`saturated` is what tells a caller not to act on the leftovers."""
        from app.db import db

        force_stub(monkeypatch)
        ids = []
        for i in range(3):
            up = client.post(
                "/api/v1/files",
                files={"file": (f"sat{i}.bin", b"x", "application/octet-stream")},
                headers=auth,
            ).json()
            db.set_scan_result(up["file_id"], "pending", None)
            with db.connect() as conn:
                conn.execute(
                    "UPDATE files SET scan_status='pending', created_at=? WHERE file_id=?",
                    (int(time.time()) - 100000 - (10 - i), up["file_id"]),
                )
            ids.append(up["file_id"])

        _tally, saturated = scanservice.resolve_pending(limit=2, min_age_seconds=0)
        assert saturated is True

        _tally, saturated = scanservice.resolve_pending(limit=1000, min_age_seconds=0)
        assert saturated is False
        for file_id in ids:
            assert db.get_file(file_id).scan_status != "pending"

    def test_release_stale_pending(self, client, auth, monkeypatch):
        from app.db import db

        up = client.post(
            "/api/v1/files",
            files={"file": ("stale.bin", b"x", "application/octet-stream")},
            headers=auth,
        ).json()
        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending', created_at=? WHERE file_id=?",
                (int(time.time()) - 100000, up["file_id"]),
            )

        released = scanservice.release_stale_pending(grace_seconds=60)
        assert released >= 1
        rec = db.get_file(up["file_id"])
        assert rec.scan_status == "error"
        assert "unresponsive" in rec.scan_detail

    def test_release_does_not_touch_recent_pending(self, client, auth):
        from app.db import db

        up = client.post(
            "/api/v1/files",
            files={"file": ("fresh.bin", b"x", "application/octet-stream")},
            headers=auth,
        ).json()
        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending' WHERE file_id=?", (up["file_id"],)
            )

        scanservice.release_stale_pending(grace_seconds=3600)
        assert db.get_file(up["file_id"]).scan_status == "pending"

    def test_scan_and_apply_converts_error(self, tmp_path, monkeypatch):
        from app.db import db

        stub = StubScanner()

        def boom(path):
            raise ScanError("nope")

        monkeypatch.setattr(stub, "scan", boom)
        monkeypatch.setattr(scanservice, "get_scanner", lambda: stub)

        rec, _ = db.insert_file(
            sha256="f" * 64,
            size_bytes=1,
            mime_type="text/plain",
            orig_name="f.txt",
            is_image=False,
            width=None,
            height=None,
            uploader="t",
            expires_at=None,
            scan_status="pending",
        )
        # Blob need not exist: the stub is patched to raise before reading.
        result = scanservice.scan_and_apply(rec.file_id, rec.sha256)
        assert result.status == "error"
        assert db.get_file(rec.file_id).scan_status == "error"


class TestScanPersistence:
    def test_set_scan_result_only_updates_pending(self, tmp_path):
        from app.db import Database

        d = Database(tmp_path / "s.db", journal_mode="TRUNCATE")
        d.init()
        rec, _ = d.insert_file(
            sha256="a" * 64, size_bytes=1, mime_type="t", orig_name="f",
            is_image=False, width=None, height=None, uploader="u",
            expires_at=None, scan_status="clean",
        )
        # Already clean -> a late 'infected' vote must not overwrite it.
        assert d.set_scan_result(rec.file_id, "infected", "late") is False
        assert d.get_file(rec.file_id).scan_status == "clean"

    def test_pending_scan_ids_ordering(self, tmp_path):
        from app.db import Database

        d = Database(tmp_path / "o.db", journal_mode="TRUNCATE")
        d.init()
        ids = []
        for i in range(3):
            rec, _ = d.insert_file(
                sha256=str(i) * 64, size_bytes=1, mime_type="t", orig_name="f",
                is_image=False, width=None, height=None, uploader="u",
                expires_at=None, scan_status="pending",
            )
            ids.append(rec.file_id)
        assert d.pending_scan_ids() == ids

    def test_scan_status_counts(self, tmp_path):
        from app.db import Database

        d = Database(tmp_path / "c.db", journal_mode="TRUNCATE")
        d.init()
        d.insert_file(
            sha256="a" * 64, size_bytes=1, mime_type="t", orig_name="f",
            is_image=False, width=None, height=None, uploader="u",
            expires_at=None, scan_status="clean",
        )
        d.insert_file(
            sha256="b" * 64, size_bytes=1, mime_type="t", orig_name="f",
            is_image=False, width=None, height=None, uploader="u",
            expires_at=None, scan_status="pending",
        )
        counts = d.scan_status_counts()
        assert counts.get("clean") == 1
        assert counts.get("pending") == 1

    def test_migration_adds_columns_to_legacy_db(self, tmp_path):
        """Upgrade path: a DB created before scan_status must keep working."""
        import sqlite3

        p = tmp_path / "legacy.db"
        c = sqlite3.connect(p)
        c.executescript(
            """
            CREATE TABLE files (
              file_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
              size_bytes INTEGER NOT NULL, mime_type TEXT NOT NULL,
              orig_name TEXT, is_image INTEGER NOT NULL DEFAULT 0,
              width INTEGER, height INTEGER, uploader TEXT,
              refcount INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL,
              expires_at INTEGER, deleted_at INTEGER);
            CREATE TABLE api_keys (key_id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,
              name TEXT, enabled INTEGER NOT NULL DEFAULT 1, quota_bytes INTEGER,
              used_bytes INTEGER NOT NULL DEFAULT 0, rate_limit INTEGER,
              created_at INTEGER NOT NULL);
            CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER NOT NULL, key_id TEXT, action TEXT NOT NULL,
              file_id TEXT, ip TEXT, status INTEGER);
            """
        )
        c.execute(
            "INSERT INTO files VALUES ('old1', ?, 10, 'text/plain', 'legacy.txt',"
            " 0, NULL, NULL, 'k', 1, 100, NULL, NULL)",
            ("a" * 64,),
        )
        c.commit()
        c.close()

        from app.db import Database

        d = Database(p, journal_mode="TRUNCATE")
        added = d.init()
        assert set(added) == {"scan_status", "scan_detail", "scanned_at"}

        rec = d.get_file("old1")
        assert rec is not None
        assert rec.scan_status == "clean"
        assert rec.is_servable is True
        assert rec.size_bytes == 10

        # Idempotent.
        assert d.init() == []

    def test_fresh_db_reports_no_migration(self, tmp_path):
        from app.db import Database

        d = Database(tmp_path / "fresh.db", journal_mode="TRUNCATE")
        assert d.init() == []


class TestCleanupIntegration:
    """`run_once` must give a queued file a real verdict, not a brick.

    The sweep used to only *release* pending rows -- marking them ``error``,
    which is not servable -- without ever asking the scanner. An upload
    interrupted between inserting its row and scanning it therefore left a
    clean file permanently undownloadable while a working scanner sat idle.
    """

    def _stale_pending(self, client, auth, name="stale2.bin", age=100000):
        """Upload a file, then rewind its row to a stuck ``pending`` state."""
        from app.db import db

        up = client.post(
            "/api/v1/files",
            files={"file": (name, b"x", "application/octet-stream")},
            headers=auth,
        ).json()
        db.set_scan_result(up["file_id"], "pending", None)
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET scan_status='pending', created_at=? WHERE file_id=?",
                (int(time.time()) - age, up["file_id"]),
            )
        return up["file_id"]

    def test_cleanup_resolves_stale_pending_instead_of_bricking_it(
        self, client, auth, monkeypatch
    ):
        """With scanning off the row lands on ``skipped``, which is servable.

        ``error`` would also stop it being pending, but it would make the file
        undownloadable forever -- the exact outcome this step exists to avoid.
        """
        from app.cleanup import run_once
        from app.db import db

        disable_scanning(monkeypatch)
        file_id = self._stale_pending(client, auth)

        stats = run_once()

        assert stats["scan_resolved"] >= 1
        rec = db.get_file(file_id)
        assert rec.scan_status == "skipped"
        assert rec.is_servable is True
        # Nothing was left over for the backstop, which is the whole point.
        assert stats["scan_released"] == 0

    def test_cleanup_survives_a_failing_scanner_and_still_reclaims(
        self, client, auth, monkeypatch
    ):
        """A scanner that explodes must not take the sweep down with it.

        The sweep's primary job is reclaiming disk. ``scan_and_apply`` converts
        :class:`ScanError` into an ``error`` verdict, but a lower-level failure
        (a socket error, say) escapes it -- and if that aborted ``run_once``,
        expired files would never be marked and blobs would never be deleted.
        """
        from app.cleanup import run_once
        from app.db import db

        # Build the fixtures first: the upload path scans too, so the stub has
        # to go in after the files exist.
        stuck = self._stale_pending(client, auth, name="boom.bin")
        expiring = self._stale_pending(client, auth, name="expiring.bin")
        with db.connect() as conn:
            conn.execute(
                "UPDATE files SET expires_at=? WHERE file_id=?",
                (int(time.time()) - 10, expiring),
            )

        def boom(_sha256):
            raise RuntimeError("clamd socket exploded")

        force_stub(monkeypatch)
        monkeypatch.setattr(scanservice, "scan_blob", boom)

        stats = run_once()

        # Step 0a failed, so it resolved nothing...
        assert stats["scan_resolved"] == 0
        # ...the backstop picked up the slack...
        assert stats["scan_released"] >= 1
        assert db.get_file(stuck).scan_status == "error"
        # ...and the rest of the sweep ran anyway.
        assert stats["marked"] >= 1

    def test_cleanup_defers_stale_release_when_the_batch_is_full(
        self, client, auth, monkeypatch
    ):
        """A full batch is not a failure, so nothing may be marked ``error``.

        Rows the batch never reached are not broken; bricking them would be
        silent corruption, and the next sweep continues where this one stopped.
        """
        from app import cleanup
        from app.db import db

        disable_scanning(monkeypatch)
        monkeypatch.setattr(cleanup, "SCAN_PICKUP_BATCH", 1)

        # Distinct ages so "oldest first" is a total order: equal timestamps
        # would leave which row is in the batch up to the query planner.
        older = self._stale_pending(client, auth, name="sat1.bin", age=100002)
        younger = self._stale_pending(client, auth, name="sat2.bin", age=100001)

        stats = cleanup.run_once()

        assert stats["scan_resolved"] == 1
        assert stats["scan_released"] == 0
        assert db.get_file(older).scan_status == "skipped"
        # Untouched, not bricked -- it is still queued for the next sweep.
        assert db.get_file(younger).scan_status == "pending"


class TestBuildScannerStubWiring:
    """`AV_BACKEND=stub` must actually be able to flag something.

    Regression guard. `build_scanner()` originally constructed
    `StubScanner()` with an empty verdict map, so it returned `default`
    ("clean") for every file. The gate *appeared* enabled while being
    indistinguishable from `AV_BACKEND=none` -- a silent no-op that would make
    any staging validation of the malware gate meaningless.
    """

    def _settings(self, monkeypatch, backend, markers):
        from app.config import settings

        monkeypatch.setattr(settings, "av_backend", backend, raising=False)
        monkeypatch.setattr(settings, "av_stub_markers", markers, raising=False)

    def test_stub_is_seeded_from_settings(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "MALWARE_MARKER")
        scanner = build_scanner()
        assert scanner is not None
        victim = tmp_path / "b.bin"
        victim.write_bytes(b"prefix MALWARE_MARKER suffix")
        assert scanner.scan(victim).status == "infected"

    def test_stub_reports_clean_for_unmarked_content(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "MALWARE_MARKER")
        scanner = build_scanner()
        victim = tmp_path / "c.bin"
        victim.write_bytes(b"nothing suspicious here")
        assert scanner.scan(victim).status == "clean"

    def test_multiple_markers_split_on_comma(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "ALPHA, BETA")
        scanner = build_scanner()
        for marker in ("ALPHA", "BETA"):
            victim = tmp_path / f"{marker}.bin"
            victim.write_bytes(b"x" + marker.encode() + b"y")
            assert scanner.scan(victim).status == "infected", marker

    def test_no_markers_still_yields_a_scanner(self, monkeypatch):
        """An empty marker list is a misconfiguration, but must not crash boot."""
        self._settings(monkeypatch, "stub", "")
        assert build_scanner() is not None

    def test_none_backend_returns_none(self, monkeypatch):
        self._settings(monkeypatch, "none", "MALWARE_MARKER")
        assert build_scanner() is None

    def test_unknown_backend_returns_none(self, monkeypatch):
        self._settings(monkeypatch, "definitely-not-real", "")
        assert build_scanner() is None


class TestBuildScannerStubWiring:
    """`AV_BACKEND=stub` must actually be able to flag something.

    Regression guard. `build_scanner()` originally constructed
    `StubScanner()` with an empty verdict map, so it returned `default`
    ("clean") for every file. The gate *appeared* enabled while being
    indistinguishable from `AV_BACKEND=none` -- a silent no-op that would make
    any staging validation of the malware gate meaningless.
    """

    def _settings(self, monkeypatch, backend, markers):
        from app.config import settings

        monkeypatch.setattr(settings, "av_backend", backend, raising=False)
        monkeypatch.setattr(settings, "av_stub_markers", markers, raising=False)

    def test_stub_is_seeded_from_settings(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "MALWARE_MARKER")
        scanner = build_scanner()
        assert scanner is not None
        victim = tmp_path / "b.bin"
        victim.write_bytes(b"prefix MALWARE_MARKER suffix")
        assert scanner.scan(victim).status == "infected"

    def test_stub_reports_clean_for_unmarked_content(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "MALWARE_MARKER")
        scanner = build_scanner()
        victim = tmp_path / "c.bin"
        victim.write_bytes(b"nothing suspicious here")
        assert scanner.scan(victim).status == "clean"

    def test_multiple_markers_split_on_comma(self, monkeypatch, tmp_path):
        self._settings(monkeypatch, "stub", "ALPHA, BETA")
        scanner = build_scanner()
        for marker in ("ALPHA", "BETA"):
            victim = tmp_path / f"{marker}.bin"
            victim.write_bytes(b"x" + marker.encode() + b"y")
            assert scanner.scan(victim).status == "infected", marker

    def test_no_markers_still_yields_a_scanner(self, monkeypatch):
        """An empty marker list is a misconfiguration, but must not crash boot."""
        self._settings(monkeypatch, "stub", "")
        assert build_scanner() is not None

    def test_none_backend_returns_none(self, monkeypatch):
        self._settings(monkeypatch, "none", "MALWARE_MARKER")
        assert build_scanner() is None

    def test_unknown_backend_returns_none(self, monkeypatch):
        self._settings(monkeypatch, "definitely-not-real", "")
        assert build_scanner() is None
