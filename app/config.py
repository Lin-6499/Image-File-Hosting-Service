"""Application configuration, loaded from environment / .env."""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- server ----
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    base_url: str = "http://127.0.0.1:8000"

    # ---- secret ----
    # REQUIRED in production. When left empty a random key is generated at boot,
    # which invalidates all previously issued links on restart -- acceptable for
    # local development, never for production.
    secret_key: str = Field(default="")

    # Set by get_settings() when no SECRET_KEY was supplied, so startup can say
    # which of the two states this process is actually in. Not an environment
    # variable; it is derived, not configured.
    secret_key_ephemeral: bool = Field(default=False)

    # ---- storage ----
    data_dir: Path = PROJECT_ROOT / "data"
    # SQLite journal mode. WAL is faster in production but requires a
    # shared-memory mapping some Windows volumes lack -- on those, connections
    # hang forever at close(). TRUNCATE is the portable default; set WAL on
    # Linux servers. See the note in app/db.py.
    db_journal_mode: str = "TRUNCATE"
    max_file_size: int = 100 * 1024 * 1024  # 100 MiB
    max_ttl: int = 7 * 24 * 3600  # 7 days
    default_ttl: int = 3600  # 1 hour
    clock_skew: int = 5  # seconds of tolerated clock drift

    # ---- image ----
    thumb_size: int = 512
    thumb_quality: int = 82

    # ---- limits ----
    rate_limit_per_min: int = 300
    disk_high_watermark: float = 0.90  # refuse uploads above this usage ratio

    # ---- antivirus ----
    # none | clamd | clamscan | stub
    # "none" disables scanning entirely (uploads are marked 'skipped').
    # "stub" is for tests and dry runs only and provides NO real protection.
    av_backend: str = "none"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str = ""  # when set, overrides host/port (unix socket)
    clamscan_path: str = "clamscan"
    av_timeout: float = 30.0
    # How long a file may stay 'pending' before the sweeper flags it. Guards
    # against a scanner that silently stops working and leaves files
    # permanently unservable.
    av_pending_grace: int = 900  # 15 minutes

    # Comma-separated content substrings that the `stub` backend reports as
    # infected. Only meaningful with AV_BACKEND=stub; lets an operator exercise
    # the full upload -> scan -> gate path locally without installing ClamAV.
    av_stub_markers: str = "MALWARE_MARKER"

    # ---- features ----
    # When True, the app serves file bytes itself (dev on Windows).
    # Set to False behind nginx, which then uses X-Accel-Redirect internally.
    serve_files_directly: bool = True

    @field_validator("secret_key")
    @classmethod
    def _ensure_secret(cls, v: str) -> str:
        return v.strip()

    @property
    def blobs_dir(self) -> Path:
        return self.data_dir / "blobs"

    @property
    def thumbs_dir(self) -> Path:
        return self.data_dir / "thumbs"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "host.db"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.blobs_dir, self.thumbs_dir, self.tmp_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        # Deterministic dev fallback would let anyone forge links. Generate a
        # random key per boot instead: links die on restart, which is the safer
        # failure mode and is loud enough to be noticed during development.
        s.secret_key = secrets.token_urlsafe(48)
        s.secret_key_ephemeral = True
    s.ensure_dirs()
    return s


settings = get_settings()
