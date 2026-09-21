"""Tests for the storage layer.

Focus is on the two properties that are easy to get wrong and expensive to
debug: streaming size enforcement, and atomic commit via os.replace.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app import storage
from app.config import settings


class FakeUpload:
    """Minimal stand-in for Starlette's UploadFile.

    ``chunks`` lets a test control the read granularity, which is how the
    streaming behaviour gets exercised.
    """

    def __init__(self, data: bytes, chunk: int = 1024):
        self._data = data
        self._pos = 0
        self._chunk = chunk

    async def read(self, size: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        n = self._chunk if size < 0 else min(size, self._chunk)
        out = self._data[self._pos : self._pos + n]
        self._pos += len(out)
        return out


class TestStreamToBlob:
    @pytest.mark.asyncio
    async def test_stores_and_hashes(self):
        data = b"hello world"
        blob = await storage.stream_to_blob(FakeUpload(data))
        assert blob.size_bytes == len(data)
        assert blob.path.exists()
        assert blob.path.read_bytes() == data

    @pytest.mark.asyncio
    async def test_sha_matches_hashlib(self):
        import hashlib

        data = b"some content for hashing"
        blob = await storage.stream_to_blob(FakeUpload(data))
        assert blob.sha256 == hashlib.sha256(data).hexdigest()

    @pytest.mark.asyncio
    async def test_oversize_rejected_midstream(self):
        """The limit must trip during reading, not after buffering it all.

        Verified by checking that no complete blob was committed, and that the
        staging file was cleaned up.
        """
        big = b"x" * (settings.max_file_size + 1024)
        with pytest.raises(storage.FileTooLarge):
            await storage.stream_to_blob(FakeUpload(big, chunk=65536))

        leftovers = list(settings.tmp_dir.glob("up_*.part"))
        assert leftovers == [], f"staging files leaked: {leftovers}"

    @pytest.mark.asyncio
    async def test_exactly_at_limit_accepted(self):
        data = b"y" * 4096
        blob = await storage.stream_to_blob(FakeUpload(data), max_size=4096)
        assert blob.size_bytes == 4096

    @pytest.mark.asyncio
    async def test_one_byte_over_limit_rejected(self):
        data = b"y" * 4097
        with pytest.raises(storage.FileTooLarge):
            await storage.stream_to_blob(FakeUpload(data), max_size=4096)

    @pytest.mark.asyncio
    async def test_empty_file_rejected(self):
        with pytest.raises(storage.FileTooLarge):
            await storage.stream_to_blob(FakeUpload(b""))

    @pytest.mark.asyncio
    async def test_dedup_reuses_existing_blob(self):
        data = b"duplicate content here"
        first = await storage.stream_to_blob(FakeUpload(data))
        assert first.reused is False

        second = await storage.stream_to_blob(FakeUpload(data))
        assert second.reused is True
        assert second.sha256 == first.sha256

    @pytest.mark.asyncio
    async def test_tmp_staging_cleaned_on_success(self):
        await storage.stream_to_blob(FakeUpload(b"cleanup check"))
        assert list(settings.tmp_dir.glob("up_*.part")) == []


class TestSharding:
    def test_blob_path_uses_two_level_shard(self):
        sha = "abcdef1234567890" + "0" * 48
        p = storage.blob_path(sha)
        assert p.parent.name == "ab"
        assert p.name == sha

    def test_thumb_path_suffix(self):
        sha = "abcdef1234567890" + "0" * 48
        p = storage.thumb_path(sha)
        assert p.name.endswith("_512.webp")
        assert p.parent.name == "ab"

    def test_distinct_hashes_shard_apart(self):
        a = "aa" + "0" * 62
        b = "bb" + "0" * 62
        assert storage.blob_path(a).parent != storage.blob_path(b).parent


class TestDiskGuards:
    def test_disk_usage_ratio_in_range(self):
        r = storage.disk_usage_ratio()
        assert 0.0 <= r <= 1.0

    def test_check_capacity_passes_under_watermark(self):
        # The test environment is nowhere near 90% full.
        storage.check_capacity()

    def test_check_capacity_raises_when_full(self, monkeypatch):
        monkeypatch.setattr(storage, "disk_usage_ratio", lambda: 0.99)
        with pytest.raises(storage.StorageFull):
            storage.check_capacity()


class TestSweepTmp:
    def test_removes_stale_fragments(self):
        stale = settings.tmp_dir / "up_stale.part"
        stale.write_bytes(b"orphan")
        import os
        import time

        old = time.time() - 100000
        os.utime(stale, (old, old))

        removed = storage.sweep_tmp(max_age_seconds=3600)
        assert removed >= 1
        assert not stale.exists()

    def test_keeps_fresh_fragments(self):
        fresh = settings.tmp_dir / "up_fresh.part"
        fresh.write_bytes(b"in progress")
        storage.sweep_tmp(max_age_seconds=3600)
        assert fresh.exists()
        fresh.unlink()


class TestDeleteBlob:
    @pytest.mark.asyncio
    async def test_delete_removes_blob_and_thumb(self):
        blob = await storage.stream_to_blob(FakeUpload(b"to be deleted"))
        thumb = storage.thumb_path(blob.sha256)
        thumb.parent.mkdir(parents=True, exist_ok=True)
        thumb.write_bytes(b"fake thumb")

        assert storage.delete_blob(blob.sha256) is True
        assert not blob.path.exists()
        assert not thumb.exists()

    def test_delete_missing_returns_false(self):
        assert storage.delete_blob("0" * 64) is False


class TestDiscardNeverPropagates:
    """`_discard` is cleanup, and cleanup must never fail the request.

    A bare `unlink` is not safe here. Hosts routinely monkeypatch
    `pathlib.Path.unlink` to route deletions through a trash/recycle-bin shim,
    and such shims can raise `BaseException` subclasses (`SystemExit`,
    `KeyboardInterrupt`) that `except OSError` does not catch. Letting one
    escape turns a successful or usefully-failing upload into an opaque 500.
    """

    def test_swallows_system_exit(self, tmp_path, monkeypatch):
        victim = tmp_path / "victim.part"
        victim.write_bytes(b"x")

        def boom(self, *a, **kw):
            raise SystemExit(1)

        monkeypatch.setattr(Path, "unlink", boom)
        assert storage._discard(victim) is False
        assert victim.exists()

    def test_swallows_keyboard_interrupt(self, tmp_path, monkeypatch):
        victim = tmp_path / "victim.part"
        victim.write_bytes(b"x")
        monkeypatch.setattr(
            Path, "unlink", lambda self, *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt())
        )
        assert storage._discard(victim) is False

    def test_swallows_permission_error(self, tmp_path, monkeypatch):
        victim = tmp_path / "victim.part"
        victim.write_bytes(b"x")

        def boom(self, *a, **kw):
            raise PermissionError("held open by another process")

        monkeypatch.setattr(Path, "unlink", boom)
        assert storage._discard(victim) is False

    def test_returns_true_on_success(self, tmp_path):
        victim = tmp_path / "victim.part"
        victim.write_bytes(b"x")
        assert storage._discard(victim) is True
        assert not victim.exists()

    def test_missing_file_is_success(self, tmp_path):
        assert storage._discard(tmp_path / "never-existed") is True

    @pytest.mark.asyncio
    async def test_dedup_path_survives_cleanup_failure(self, monkeypatch):
        """A duplicate upload must still succeed when the temp file is undeletable."""
        data = b"duplicate payload for dedup cleanup test"
        first = await storage.stream_to_blob(FakeUpload(data))
        assert first.reused is False

        def boom(self, *a, **kw):
            raise SystemExit(1)

        monkeypatch.setattr(Path, "unlink", boom)
        second = await storage.stream_to_blob(FakeUpload(data))
        assert second.reused is True
        assert second.sha256 == first.sha256

    @pytest.mark.asyncio
    async def test_oversize_error_survives_cleanup_failure(self, monkeypatch):
        """The real error (FileTooLarge) must not be masked by a cleanup failure."""
        monkeypatch.setattr(storage.settings, "max_file_size", 10)

        def boom(self, *a, **kw):
            raise SystemExit(1)

        monkeypatch.setattr(Path, "unlink", boom)
        with pytest.raises(storage.FileTooLarge):
            await storage.stream_to_blob(FakeUpload(b"x" * 100))


class TestSanitizeRunsBeforeCommit:
    """The blob on disk must always hash to its own filename.

    Regression guard for a real defect: EXIF stripping used to run *after* the
    blob was committed. That left the stored file not hashing to its own name,
    so the `sha256` returned to the client could not verify the downloaded
    bytes and `size_bytes` was overstated. Content addressing is load-bearing
    here (dedup, integrity, unguessable paths), so any transform has to happen
    before the hash is taken.
    """

    @pytest.mark.asyncio
    async def test_sanitized_blob_hashes_to_its_filename(self):
        original = b"ORIGINAL-PAYLOAD-WITH-METADATA"
        shrunk = b"cleaned"

        def sanitize(path):
            path.write_bytes(shrunk)
            return True

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        on_disk = blob.path.read_bytes()

        assert on_disk == shrunk
        assert blob.path.name == hashlib.sha256(on_disk).hexdigest()
        assert blob.sha256 == hashlib.sha256(on_disk).hexdigest()
        assert blob.size_bytes == len(shrunk)

    @pytest.mark.asyncio
    async def test_size_bytes_reflects_sanitized_length(self):
        """size_bytes must describe what a client actually downloads."""
        def sanitize(path):
            path.write_bytes(b"x" * 7)
            return True

        blob = await storage.stream_to_blob(FakeUpload(b"y" * 5000), sanitize=sanitize)
        assert blob.size_bytes == 7

    @pytest.mark.asyncio
    async def test_sanitizer_returning_false_keeps_original_digest(self):
        original = b"unchanged bytes"

        def sanitize(path):
            return False

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        assert blob.sha256 == hashlib.sha256(original).hexdigest()
        assert blob.size_bytes == len(original)

    @pytest.mark.asyncio
    async def test_sanitizer_failure_does_not_lose_the_upload(self):
        """A broken sanitizer must degrade to storing the original."""
        original = b"payload that must survive"

        def sanitize(path):
            raise RuntimeError("decoder exploded")

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        assert blob.path.read_bytes() == original
        assert blob.sha256 == hashlib.sha256(original).hexdigest()

    @pytest.mark.asyncio
    async def test_dedup_uses_sanitized_content(self):
        """Two uploads differing only in metadata must collapse to one blob."""
        def sanitize(path):
            if b"METADATA" in path.read_bytes():
                path.write_bytes(b"same-core")
                return True
            return False

        a = await storage.stream_to_blob(FakeUpload(b"same-core" + b"METADATA"), sanitize=sanitize)
        b = await storage.stream_to_blob(FakeUpload(b"same-core"), sanitize=sanitize)
        assert a.sha256 == b.sha256
        assert b.reused is True


class TestSanitizeRunsBeforeCommit:
    """The blob on disk must always hash to its own filename.

    Regression guard for a real defect: EXIF stripping used to run *after* the
    blob was committed. That left the stored file not hashing to its own name,
    so the `sha256` returned to the client could not verify the downloaded
    bytes and `size_bytes` was overstated. Content addressing is load-bearing
    here (dedup, integrity, unguessable paths), so any transform has to happen
    before the hash is taken.
    """

    @pytest.mark.asyncio
    async def test_sanitized_blob_hashes_to_its_filename(self):
        original = b"ORIGINAL-PAYLOAD-WITH-METADATA"
        shrunk = b"cleaned"

        def sanitize(path):
            path.write_bytes(shrunk)
            return True

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        on_disk = blob.path.read_bytes()

        assert on_disk == shrunk
        assert blob.path.name == hashlib.sha256(on_disk).hexdigest()
        assert blob.sha256 == hashlib.sha256(on_disk).hexdigest()
        assert blob.size_bytes == len(shrunk)

    @pytest.mark.asyncio
    async def test_size_bytes_reflects_sanitized_length(self):
        """size_bytes must describe what a client actually downloads."""
        def sanitize(path):
            path.write_bytes(b"x" * 7)
            return True

        blob = await storage.stream_to_blob(FakeUpload(b"y" * 5000), sanitize=sanitize)
        assert blob.size_bytes == 7

    @pytest.mark.asyncio
    async def test_sanitizer_returning_false_keeps_original_digest(self):
        original = b"unchanged bytes"

        def sanitize(path):
            return False

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        assert blob.sha256 == hashlib.sha256(original).hexdigest()
        assert blob.size_bytes == len(original)

    @pytest.mark.asyncio
    async def test_sanitizer_failure_does_not_lose_the_upload(self):
        """A broken sanitizer must degrade to storing the original."""
        original = b"payload that must survive"

        def sanitize(path):
            raise RuntimeError("decoder exploded")

        blob = await storage.stream_to_blob(FakeUpload(original), sanitize=sanitize)
        assert blob.path.read_bytes() == original
        assert blob.sha256 == hashlib.sha256(original).hexdigest()

    @pytest.mark.asyncio
    async def test_dedup_uses_sanitized_content(self):
        """Two uploads differing only in metadata must collapse to one blob."""
        def sanitize(path):
            if b"METADATA" in path.read_bytes():
                path.write_bytes(b"same-core")
                return True
            return False

        a = await storage.stream_to_blob(FakeUpload(b"same-core" + b"METADATA"), sanitize=sanitize)
        b = await storage.stream_to_blob(FakeUpload(b"same-core"), sanitize=sanitize)
        assert a.sha256 == b.sha256
        assert b.reused is True
