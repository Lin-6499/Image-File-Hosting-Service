"""Tests for the persistence layer, with emphasis on reclamation safety."""

from __future__ import annotations

import time

import pytest

from app.db import Database, new_file_id


@pytest.fixture()
def dbase(tmp_path) -> Database:
    d = Database(tmp_path / "t.db", journal_mode="TRUNCATE")
    d.init()
    return d


def add(d: Database, sha: str, *, expires_at=None, is_image=False):
    """Insert a row, returning ``(record, deduplicated)``."""
    return d.insert_file(
        sha256=sha,
        size_bytes=10,
        mime_type="application/octet-stream",
        orig_name="f.bin",
        is_image=is_image,
        width=None,
        height=None,
        uploader="tester",
        expires_at=expires_at,
    )


def add_rec(d: Database, sha: str, **kw):
    """Insert a row, returning only the record -- the common case in tests."""
    return add(d, sha, **kw)[0]


class TestFileIds:
    def test_are_unique_and_unguessable_length(self):
        ids = {new_file_id() for _ in range(500)}
        assert len(ids) == 500
        assert all(len(i) == 22 for i in ids)

    def test_url_safe_alphabet(self):
        for _ in range(50):
            fid = new_file_id()
            assert all(c.isalnum() or c in "-_" for c in fid)


class TestInsertAndFetch:
    def test_roundtrip(self, dbase):
        rec = add_rec(dbase, "a" * 64)
        got = dbase.get_file(rec.file_id)
        assert got is not None
        assert got.sha256 == "a" * 64
        assert got.refcount == 1
        assert got.deleted_at is None

    def test_dedup_flag_on_second_insert(self, dbase):
        _, first_dup = add(dbase, "b" * 64)
        _, second_dup = add(dbase, "b" * 64)
        assert first_dup is False
        assert second_dup is True

    def test_same_content_gets_distinct_records(self, dbase):
        r1 = add_rec(dbase, "c" * 64)
        r2 = add_rec(dbase, "c" * 64)
        assert r1.file_id != r2.file_id

    def test_missing_returns_none(self, dbase):
        assert dbase.get_file("nope") is None

    def test_sha8_property(self, dbase):
        """``sha8`` is the 8-char prefix used in image URLs as a cache key."""
        rec = add_rec(dbase, "abcdef01" + "0" * 56)
        assert rec.sha8 == "abcdef01"
        assert len(rec.sha8) == 8


class TestSoftDelete:
    def test_marks_deleted(self, dbase):
        rec = add_rec(dbase, "d" * 64)
        assert dbase.soft_delete(rec.file_id) is True
        assert dbase.get_file(rec.file_id).deleted_at is not None

    def test_second_delete_returns_false(self, dbase):
        rec = add_rec(dbase, "e" * 64)
        dbase.soft_delete(rec.file_id)
        assert dbase.soft_delete(rec.file_id) is False

    def test_excluded_from_listing(self, dbase):
        rec = add_rec(dbase, "f" * 64)
        dbase.soft_delete(rec.file_id)
        assert all(r.file_id != rec.file_id for r in dbase.list_files())


class TestReclamation:
    def test_live_blob_not_orphaned(self, dbase):
        add_rec(dbase, "1" * 64)
        assert "1" * 64 not in dbase.find_orphan_blobs(grace_seconds=0)

    def test_deleted_blob_becomes_orphan(self, dbase):
        rec = add_rec(dbase, "2" * 64)
        dbase.soft_delete(rec.file_id)
        # deleted_at is "now", so a zero grace period makes it eligible.
        assert "2" * 64 in dbase.find_orphan_blobs(grace_seconds=0)

    def test_grace_period_defers_reclamation(self, dbase):
        rec = add_rec(dbase, "3" * 64)
        dbase.soft_delete(rec.file_id)
        assert "3" * 64 not in dbase.find_orphan_blobs(grace_seconds=3600)

    def test_shared_content_survives_one_deletion(self, dbase):
        """The key safety property: deleting one upload must not orphan a blob
        that another live upload still references."""
        r1 = add_rec(dbase, "4" * 64)
        add_rec(dbase, "4" * 64)  # second live reference

        dbase.soft_delete(r1.file_id)
        assert "4" * 64 not in dbase.find_orphan_blobs(grace_seconds=0)
        assert dbase.is_hash_referenced("4" * 64) is True

    def test_orphan_after_all_references_deleted(self, dbase):
        r1 = add_rec(dbase, "5" * 64)
        r2 = add_rec(dbase, "5" * 64)
        dbase.soft_delete(r1.file_id)
        assert dbase.is_hash_referenced("5" * 64) is True
        dbase.soft_delete(r2.file_id)
        assert dbase.is_hash_referenced("5" * 64) is False

    def test_is_hash_referenced_false_for_unknown(self, dbase):
        assert dbase.is_hash_referenced("9" * 64) is False

    def test_purge_removes_rows(self, dbase):
        rec = add_rec(dbase, "6" * 64)
        dbase.soft_delete(rec.file_id)
        removed = dbase.purge_hashes(["6" * 64])
        assert removed >= 1
        assert dbase.get_file(rec.file_id) is None

    def test_purge_skips_live_rows(self, dbase):
        add_rec(dbase, "7" * 64)
        assert dbase.purge_hashes(["7" * 64]) == 0


class TestExpiry:
    def test_finds_expired_only(self, dbase):
        past = add_rec(dbase, "8" * 64, expires_at=int(time.time()) - 10)
        add_rec(dbase, "9" * 64, expires_at=int(time.time()) + 10_000)
        add_rec(dbase, "a" * 64, expires_at=None)

        expired = dbase.expired_file_ids()
        assert past.file_id in expired
        assert len(expired) == 1

    def test_already_deleted_not_reselected(self, dbase):
        rec = add_rec(dbase, "b" * 64, expires_at=int(time.time()) - 10)
        dbase.soft_delete(rec.file_id)
        assert rec.file_id not in dbase.expired_file_ids()


class TestApiKeys:
    def test_create_and_lookup(self, dbase):
        key_id, plaintext = dbase.create_api_key("test")
        row = dbase.lookup_api_key(plaintext)
        assert row is not None and row["key_id"] == key_id

    def test_plaintext_stored_only_as_hash(self, dbase):
        _, plaintext = dbase.create_api_key("hashcheck")
        with dbase.connect() as conn:
            rows = conn.execute("SELECT key_hash FROM api_keys").fetchall()
        assert all(plaintext not in r["key_hash"] for r in rows)

    def test_unknown_key_returns_none(self, dbase):
        assert dbase.lookup_api_key("sk_bogus") is None

    def test_disabled_key_not_returned(self, dbase):
        key_id, plaintext = dbase.create_api_key("disable-me")
        with dbase.connect() as conn:
            conn.execute("UPDATE api_keys SET enabled = 0 WHERE key_id = ?", (key_id,))
        assert dbase.lookup_api_key(plaintext) is None

    def test_disable_is_immediate_and_reversible(self, dbase):
        """Revocation must take effect on the next lookup, not the next boot.

        That is the entire point of ``set_key_enabled``: a leaked key that
        keeps working until someone restarts the service is not revoked.
        """
        key_id, plaintext = dbase.create_api_key("revoke-me")
        assert dbase.lookup_api_key(plaintext) is not None

        assert dbase.set_key_enabled(key_id, False) is True
        assert dbase.lookup_api_key(plaintext) is None

        assert dbase.set_key_enabled(key_id, True) is True
        assert dbase.lookup_api_key(plaintext) is not None

    def test_disable_keeps_the_row_so_the_audit_trail_survives(self, dbase):
        """Deleting the row would orphan every audit entry pointing at it."""
        key_id, _ = dbase.create_api_key("keep-me")
        dbase.set_key_enabled(key_id, False)
        rows = {r["key_id"]: r for r in dbase.list_api_keys()}
        assert key_id in rows
        assert rows[key_id]["enabled"] == 0

    def test_disable_unknown_key_reports_failure(self, dbase):
        """A typo must not look like a successful revocation."""
        assert dbase.set_key_enabled("key_nope", False) is False

    def test_list_api_keys_is_newest_first_and_leaks_no_hash(self, dbase):
        first, _ = dbase.create_api_key("first")
        second, plaintext = dbase.create_api_key("second")
        rows = dbase.list_api_keys()
        # Same-second creation is the normal case, so this also pins the
        # rowid tie-breaker: ordering by created_at alone would be arbitrary.
        assert [r["key_id"] for r in rows] == [second, first]
        assert "key_hash" not in rows[0].keys()
        assert all(plaintext not in str(dict(r)) for r in rows)

    def test_list_api_keys_orders_same_second_creations(self, dbase):
        ids = [dbase.create_api_key(f"k{i}")[0] for i in range(5)]
        assert [r["key_id"] for r in dbase.list_api_keys()] == list(reversed(ids))

    def test_purge_deletes_a_key_that_was_never_used(self, dbase):
        """Typos and re-mints should not clutter the listing forever."""
        key_id, _ = dbase.create_api_key("typo")
        assert dbase.audit_rows_for_key(key_id) == 0
        assert dbase.delete_unused_key(key_id) is True
        assert key_id not in {r["key_id"] for r in dbase.list_api_keys()}

    def test_purge_refuses_a_key_with_audit_history(self, dbase):
        """Deleting a referenced key would orphan its own audit entries.

        audit_log stores key_id, not the label, so the entries would become
        unattributable -- they must stay resolvable.
        """
        key_id, _ = dbase.create_api_key("used")
        dbase.log(key_id=key_id, action="upload", file_id="f1", ip="1.2.3.4", status=201)
        assert dbase.audit_rows_for_key(key_id) == 1

        assert dbase.delete_unused_key(key_id) is False
        assert key_id in {r["key_id"] for r in dbase.list_api_keys()}

        # and the audit row is still attributable
        with dbase.connect() as conn:
            row = conn.execute(
                "SELECT key_id FROM audit_log WHERE key_id = ?", (key_id,)
            ).fetchone()
        assert row["key_id"] == key_id

    def test_purge_unknown_key_returns_false(self, dbase):
        assert dbase.delete_unused_key("key_nope") is False

    def test_purge_still_works_after_disabling(self, dbase):
        """Disabling first is the natural workflow; it must not block a purge."""
        key_id, _ = dbase.create_api_key("disable-then-purge")
        dbase.set_key_enabled(key_id, False)
        assert dbase.delete_unused_key(key_id) is True

    def test_audit_rows_for_key_is_scoped_to_that_key(self, dbase):
        a, _ = dbase.create_api_key("a")
        b, _ = dbase.create_api_key("b")
        dbase.log(key_id=a, action="upload", file_id="f1", ip=None, status=201)
        dbase.log(key_id=a, action="delete", file_id="f1", ip=None, status=200)
        assert dbase.audit_rows_for_key(a) == 2
        assert dbase.audit_rows_for_key(b) == 0

    def test_used_bytes_accumulate(self, dbase):
        key_id, _ = dbase.create_api_key("quota")
        dbase.add_used_bytes(key_id, 100)
        dbase.add_used_bytes(key_id, 250)
        with dbase.connect() as conn:
            row = conn.execute(
                "SELECT used_bytes FROM api_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        assert row["used_bytes"] == 350


class TestStatsAndAudit:
    def test_stats_counts(self, dbase):
        add_rec(dbase, "c" * 64)
        rec = add_rec(dbase, "d" * 64)
        dbase.soft_delete(rec.file_id)
        s = dbase.stats()
        assert s["total_records"] == 2
        assert s["live_records"] == 1

    def test_audit_log_written(self, dbase):
        dbase.log(key_id="k1", action="upload", file_id="f1", ip="1.2.3.4", status=201)
        with dbase.connect() as conn:
            row = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        assert row["action"] == "upload" and row["file_id"] == "f1"


class TestInit:
    def test_idempotent(self, tmp_path):
        d = Database(tmp_path / "x.db", journal_mode="TRUNCATE")
        d.init()
        d.init()
        assert d.stats()["total_records"] == 0

    def test_invalid_journal_mode_falls_back(self, tmp_path):
        d = Database(tmp_path / "y.db", journal_mode="NONSENSE")
        assert d.journal_mode == "TRUNCATE"

    def test_creates_parent_directory(self, tmp_path):
        nested = tmp_path / "a" / "b" / "z.db"
        Database(nested, journal_mode="TRUNCATE").init()
        assert nested.exists()
