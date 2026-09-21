"""SQLite persistence layer.

SQLite is chosen deliberately: the workload is many reads (link resolution)
against few writes (uploads). WAL mode makes readers non-blocking, which is
exactly the shape needed. Move to PostgreSQL only when multiple app instances
are required.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import settings

SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS files (
    file_id     TEXT PRIMARY KEY,
    sha256      TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL,
    mime_type   TEXT    NOT NULL,
    orig_name   TEXT,
    is_image    INTEGER NOT NULL DEFAULT 0,
    width       INTEGER,
    height      INTEGER,
    uploader    TEXT,
    refcount    INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    deleted_at  INTEGER,
    scan_status TEXT    NOT NULL DEFAULT 'clean',
    scan_detail TEXT,
    scanned_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_files_sha       ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_expires   ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_uploader  ON files(uploader, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_scan      ON files(scan_status);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    name        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    quota_bytes INTEGER,
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    rate_limit  INTEGER,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    key_id  TEXT,
    action  TEXT NOT NULL,
    file_id TEXT,
    ip      TEXT,
    status  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
"""

# Columns added after the initial release. ``CREATE TABLE IF NOT EXISTS`` does
# not alter an existing table, so databases created before a column existed
# need an explicit ADD COLUMN. Each entry is (column, definition); the
# migration is skipped when the column is already present.
MIGRATIONS: list[tuple[str, str]] = [
    ("scan_status", "TEXT NOT NULL DEFAULT 'clean'"),
    ("scan_detail", "TEXT"),
    ("scanned_at", "INTEGER"),
]

# NOTE on journal_mode:
#
# WAL is the better choice in production (readers never block the writer) and
# is the default on Linux. It is NOT the default here because WAL depends on a
# shared-memory mapping (the -shm file) that some Windows volumes do not
# support -- on such a volume sqlite3.connect() succeeds but conn.close()
# blocks forever, hanging application startup with no error. Observed on
# D:\ImageAndTextHosting in this environment; the same code works on C:.
#
# TRUNCATE keeps most of the write performance without the shared-memory
# requirement, so it is the safe default. Set DB_JOURNAL_MODE=WAL in .env when
# deploying to a Linux server where WAL is known to work.
_VALID_JOURNAL_MODES = {"WAL", "TRUNCATE", "PERSIST", "MEMORY", "DELETE", "OFF"}

# 22 chars of url-safe base64 -> 128 bits of entropy. Not guessable.
_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def new_file_id() -> str:
    raw = secrets.token_bytes(16)
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class FileRecord:
    file_id: str
    sha256: str
    size_bytes: int
    mime_type: str
    orig_name: str | None
    is_image: bool
    width: int | None
    height: int | None
    uploader: str | None
    refcount: int
    created_at: int
    expires_at: int | None
    deleted_at: int | None
    scan_status: str = "clean"
    scan_detail: str | None = None
    scanned_at: int | None = None

    @property
    def sha8(self) -> str:
        return self.sha256[:8]

    @property
    def is_servable(self) -> bool:
        """Whether the bytes may be handed to a download client.

        ``pending`` is not servable: the file is still queued for scanning and
        serving it would defeat the point of scanning at all. ``infected`` is
        never servable. ``clean`` and ``skipped`` are.
        """
        return self.scan_status in ("clean", "skipped")


class Database:
    # Explicit because sqlite3's default busy timeout is 5s but the pragma is
    # per-connection; keeping them in sync avoids confusion.
    busy_timeout_ms: int = 5000
    def __init__(self, path: Path, journal_mode: str | None = None) -> None:
        self.path = path
        mode = (journal_mode or settings.db_journal_mode).upper()
        self.journal_mode = mode if mode in _VALID_JOURNAL_MODES else "TRUNCATE"

    def _configure(self, conn: sqlite3.Connection) -> None:
        """Apply connection pragmas.

        Each PRAGMA is run through ``execute()``, never ``executescript()``.
        ``executescript()`` issues an implicit COMMIT and, in combination with
        a journal_mode switch, can leave the connection in a state where
        ``close()`` blocks indefinitely. Running them individually also lets
        the returned rows be consumed, which is what releases the statement.
        """
        for pragma in (
            f"PRAGMA journal_mode={self.journal_mode}",
            "PRAGMA synchronous=NORMAL",
            f"PRAGMA busy_timeout={self.busy_timeout_ms}",
            "PRAGMA foreign_keys=ON",
        ):
            try:
                conn.execute(pragma).fetchone()
            except sqlite3.DatabaseError:
                # A read-only medium or an unsupported pragma must not prevent
                # the service from starting.
                continue

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        self._configure(conn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> list[str]:
        """Create or upgrade the schema. Returns columns added by migration."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            self._configure(conn)

            # Migration MUST run before the schema script, not after. The
            # script contains `CREATE INDEX ... ON files(scan_status)`, and on
            # a database predating that column the index creation fails before
            # the ALTER would have had a chance to add it.
            added = self._migrate(conn)

            # DDL only -- no PRAGMA statements mixed in, so the implicit
            # COMMIT inside executescript() cannot interact with a journal
            # mode change.
            conn.executescript(SCHEMA_TABLES)
            conn.commit()
            return added
        finally:
            conn.close()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> list[str]:
        """Add columns introduced after the initial schema.

        ``CREATE TABLE IF NOT EXISTS`` silently does nothing on an existing
        table, so a database created before a column was added would be missing
        it and every query selecting that column would fail. Adding the column
        explicitly keeps upgrades in place without a separate migration tool.

        Returns the list of columns actually added.
        """
        tables = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "files" not in tables:
            # Fresh database: SCHEMA_TABLES creates everything already correct.
            return []

        existing = {row["name"] for row in conn.execute("PRAGMA table_info(files)")}
        added: list[str] = []
        for column, definition in MIGRATIONS:
            if column in existing:
                continue
            conn.execute(f"ALTER TABLE files ADD COLUMN {column} {definition}")
            added.append(column)
        return added

    # ---------------- files ----------------

    def insert_file(
        self,
        *,
        sha256: str,
        size_bytes: int,
        mime_type: str,
        orig_name: str | None,
        is_image: bool,
        width: int | None,
        height: int | None,
        uploader: str | None,
        expires_at: int | None,
        scan_status: str = "clean",
    ) -> tuple[FileRecord, bool]:
        """Insert a file row. Returns (record, deduplicated).

        Two different files can share content, so ``sha256`` is not unique:
        each upload gets its own ``file_id`` and its own refcount. That keeps
        per-upload lifecycle (expiry, ownership) independent while the blob
        on disk is stored once.

        ``scan_status`` defaults to ``clean`` so that callers which do not use
        antivirus scanning are unaffected. With scanning enabled the upload
        route passes ``pending``.
        """
        now = int(time.time())
        file_id = new_file_id()

        with self.connect() as conn:
            dup = conn.execute(
                "SELECT 1 FROM files WHERE sha256 = ? AND deleted_at IS NULL LIMIT 1",
                (sha256,),
            ).fetchone()
            deduplicated = dup is not None

            conn.execute(
                """
                INSERT INTO files (file_id, sha256, size_bytes, mime_type, orig_name,
                                   is_image, width, height, uploader, refcount,
                                   created_at, expires_at, deleted_at,
                                   scan_status, scan_detail, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?, NULL, NULL)
                """,
                (
                    file_id,
                    sha256,
                    size_bytes,
                    mime_type,
                    orig_name,
                    1 if is_image else 0,
                    width,
                    height,
                    uploader,
                    now,
                    expires_at,
                    scan_status,
                ),
            )

        rec = self.get_file(file_id)
        assert rec is not None
        return rec, deduplicated

    def set_scan_result(
        self, file_id: str, status: str, detail: str | None = None
    ) -> bool:
        """Record the outcome of a scan for one file record.

        Only updates rows still in ``pending``. A vote that arrives after the
        file was already resolved (or deleted) must not resurrect it.
        """
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE files SET scan_status = ?, scan_detail = ?, scanned_at = ? "
                "WHERE file_id = ? AND scan_status = 'pending'",
                (status, detail, int(time.time()), file_id),
            )
            return cur.rowcount > 0

    def pending_scan_ids(self, limit: int = 100) -> list[str]:
        """Oldest pending uploads, for the scanner worker to pick up."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT file_id FROM files WHERE scan_status = 'pending' "
                "AND deleted_at IS NULL ORDER BY created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [r["file_id"] for r in rows]

    def scan_status_counts(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT scan_status, COUNT(*) AS n FROM files "
                "WHERE deleted_at IS NULL GROUP BY scan_status"
            ).fetchall()
        return {r["scan_status"]: r["n"] for r in rows}

    def infected_ids(self, limit: int = 200) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT file_id FROM files WHERE scan_status = 'infected' "
                "AND deleted_at IS NULL LIMIT ?",
                (limit,),
            ).fetchall()
        return [r["file_id"] for r in rows]

    def get_file(self, file_id: str) -> FileRecord | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM files WHERE file_id = ?", (file_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def soft_delete(self, file_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE files SET deleted_at = ? WHERE file_id = ? AND deleted_at IS NULL",
                (int(time.time()), file_id),
            )
            return cur.rowcount > 0

    def list_files(
        self, *, uploader: str | None = None, limit: int = 50, offset: int = 0
    ) -> list[FileRecord]:
        sql = "SELECT * FROM files WHERE deleted_at IS NULL"
        params: list[object] = []
        if uploader:
            sql += " AND uploader = ?"
            params.append(uploader)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([min(limit, 200), offset])
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_record(r) for r in rows]

    # ---------------- maintenance ----------------

    def find_orphan_blobs(self, grace_seconds: int = 0) -> list[str]:
        """Hashes with no live reference, eligible for deletion.

        Uses a single grouped query rather than decrementing a counter, so a
        concurrent upload landing between the two steps cannot cause a blob to
        be deleted while a fresh row still points at it.

        The comparison is ``<=``, not ``<``. With ``<`` a blob deleted in the
        same second as the sweep is excluded, so ``grace_seconds=0`` would
        still impose a one-second delay and tests (and operators) reasoning
        about an immediate sweep would be misled. ``<=`` makes the contract
        exact: grace 0 means "eligible now".
        """
        cutoff = int(time.time()) - grace_seconds
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT sha256 FROM files
                GROUP BY sha256
                HAVING SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) = 0
                   AND MAX(COALESCE(deleted_at, 0)) <= ?
                """,
                (cutoff,),
            ).fetchall()
        return [r["sha256"] for r in rows]

    def is_hash_referenced(self, sha256: str) -> bool:
        """Re-check immediately before unlinking. Cheap insurance against
        deleting a blob that a concurrent upload just reused."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM files WHERE sha256 = ? AND deleted_at IS NULL LIMIT 1",
                (sha256,),
            ).fetchone()
        return row is not None

    def purge_hashes(self, hashes: list[str]) -> int:
        if not hashes:
            return 0
        marks = ",".join("?" * len(hashes))
        with self.connect() as conn:
            cur = conn.execute(
                f"DELETE FROM files WHERE sha256 IN ({marks}) AND deleted_at IS NOT NULL",
                hashes,
            )
            return cur.rowcount

    def expired_file_ids(self) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT file_id FROM files WHERE expires_at IS NOT NULL "
                "AND expires_at < ? AND deleted_at IS NULL",
                (int(time.time()),),
            ).fetchall()
        return [r["file_id"] for r in rows]

    def stats(self) -> dict[str, int]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(size_bytes), 0) AS bytes,
                       SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS live
                FROM files
                """
            ).fetchone()
        return {
            "total_records": row["total"],
            "live_records": row["live"] or 0,
            "total_bytes": row["bytes"],
        }

    # ---------------- api keys ----------------

    def create_api_key(
        self, name: str, *, quota_bytes: int | None = None, rate_limit: int | None = None
    ) -> tuple[str, str]:
        import hashlib

        key_id = "key_" + secrets.token_hex(6)
        plaintext = "sk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO api_keys (key_id, key_hash, name, enabled, quota_bytes,"
                " used_bytes, rate_limit, created_at) VALUES (?, ?, ?, 1, ?, 0, ?, ?)",
                (key_id, key_hash, name, quota_bytes, rate_limit, int(time.time())),
            )
        return key_id, plaintext

    def lookup_api_key(self, plaintext: str) -> sqlite3.Row | None:
        import hashlib

        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND enabled = 1",
                (key_hash,),
            ).fetchone()
        return row

    def add_used_bytes(self, key_id: str, delta: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE api_keys SET used_bytes = used_bytes + ? WHERE key_id = ?",
                (delta, key_id),
            )

    def list_api_keys(self) -> list[sqlite3.Row]:
        """Every key, newest first, without the hash.

        The plaintext is unrecoverable by design, so ``key_id`` and the label
        are the only handles an operator has. That is precisely why a label
        that is itself a key string is a problem -- see ``scripts/mintkey.py``.

        Ordered by ``rowid`` as a tie-breaker, not ``created_at`` alone:
        ``created_at`` has one-second resolution, and keys minted in the same
        second (easy to do by re-running a command) would otherwise come back
        in an arbitrary order.
        """
        with self.connect() as conn:
            return conn.execute(
                "SELECT key_id, name, enabled, quota_bytes, used_bytes,"
                " rate_limit, created_at FROM api_keys"
                " ORDER BY created_at DESC, rowid DESC"
            ).fetchall()

    def set_key_enabled(self, key_id: str, enabled: bool) -> bool:
        """Enable or disable a key. False when the id is unknown.

        This is the revocation primitive. ``lookup_api_key`` filters on
        ``enabled = 1``, so the change takes effect on the very next request --
        no restart. The row is deliberately kept rather than deleted, so the
        audit trail still resolves ``key_id`` to a label afterwards.
        """
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET enabled = ? WHERE key_id = ?",
                (1 if enabled else 0, key_id),
            )
            changed = cur.rowcount
        return changed > 0

    def audit_rows_for_key(self, key_id: str) -> int:
        """How many audit entries name this key.

        Non-zero means the key must not be deleted: ``audit_log`` stores
        ``key_id`` rather than the label, so removing the key would leave its
        own history unattributable.
        """
        with self.connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE key_id = ?", (key_id,)
            ).fetchone()[0]

    def delete_unused_key(self, key_id: str) -> bool:
        """Delete a key that no audit entry references. False otherwise.

        The guard lives in the SQL rather than in a preceding check, so there
        is no window between "is it referenced?" and "delete it".

        Disabling is the normal way to retire a key. This exists for keys that
        were never used -- typos, re-mints, test pollution -- which have no
        history worth preserving and would otherwise clutter the listing
        forever, with their plaintext unrecoverable anyway.
        """
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM api_keys WHERE key_id = ?"
                " AND NOT EXISTS (SELECT 1 FROM audit_log WHERE key_id = ?)",
                (key_id, key_id),
            )
            removed = cur.rowcount
        return removed > 0

    def log(self, *, key_id: str | None, action: str, file_id: str | None, ip: str | None, status: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, key_id, action, file_id, ip, status)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (int(time.time()), key_id, action, file_id, ip, status),
            )


def _row_to_record(row: sqlite3.Row) -> FileRecord:
    keys = row.keys()
    return FileRecord(
        file_id=row["file_id"],
        sha256=row["sha256"],
        size_bytes=row["size_bytes"],
        mime_type=row["mime_type"],
        orig_name=row["orig_name"],
        is_image=bool(row["is_image"]),
        width=row["width"],
        height=row["height"],
        uploader=row["uploader"],
        refcount=row["refcount"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        deleted_at=row["deleted_at"],
        # Guarded so the reader still works against a database opened before
        # the migration ran (e.g. during a rolling upgrade).
        scan_status=row["scan_status"] if "scan_status" in keys else "clean",
        scan_detail=row["scan_detail"] if "scan_detail" in keys else None,
        scanned_at=row["scanned_at"] if "scanned_at" in keys else None,
    )


db = Database(settings.db_path)
