"""Shared pytest fixtures.

Isolation is the whole point of this file. The application reads its data
directory from a module-level singleton (``app.config.settings``) and builds
the :class:`Database` and blob paths from it at import time. Tests must
therefore redirect that configuration to a temporary directory *before* the
app modules are imported, otherwise the suite would write into the real
``data/`` folder and destroy developer state.

``pytest_configure`` runs early enough to do that rebinding.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# A single session-scoped temp directory owns every test artifact.
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="host-tests-"))
os.environ["DATA_DIR"] = str(_TMP_ROOT / "data")
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["DEBUG"] = "false"
# WAL is unavailable on some Windows volumes; TRUNCATE keeps the suite
# portable. See the journal-mode note in app/db.py.
os.environ["DB_JOURNAL_MODE"] = "TRUNCATE"
os.environ["MAX_FILE_SIZE"] = str(2 * 1024 * 1024)  # 2 MiB
os.environ["DEFAULT_TTL"] = "3600"
os.environ["MAX_TTL"] = "86400"  # 1 day, so clamping is testable


@pytest.fixture(scope="session")
def app_module():
    """Import the FastAPI app once, after env redirection."""
    from app.main import app

    return app


@pytest.fixture(scope="session")
def tmp_root() -> Path:
    return _TMP_ROOT


@pytest.fixture()
def client(app_module):
    """A TestClient with the app lifespan executed (runs db.init)."""
    from fastapi.testclient import TestClient

    with TestClient(app_module) as c:
        yield c


_key_counter = {"n": 0}


@pytest.fixture()
def api_key(app_module) -> str:
    """A distinct API key per test.

    Each test needs its own key so quota and rate-limit accounting cannot leak
    between tests.
    """
    from app.db import db

    _key_counter["n"] += 1
    _, plaintext = db.create_api_key(f"test-key-{_key_counter['n']}")
    return plaintext


@pytest.fixture()
def auth(api_key) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def png_bytes(width: int = 64, height: int = 48, color=(120, 60, 200)) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (width, height), color).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture()
def png() -> bytes:
    return png_bytes()


def jpeg_with_exif() -> bytes:
    """A JPEG carrying GPS EXIF, used to prove metadata is stripped.

    Rational values are written as ``IFDRational``. Passing nested integer
    tuples makes Pillow's writer raise ``TypeError: bad operand type for
    abs(): 'tuple'``, so the conversion is explicit here.
    """
    from PIL import Image
    from PIL.TiffImagePlugin import IFDRational

    img = Image.new("RGB", (40, 30), (10, 200, 90))
    exif = Image.Exif()
    exif[0x8825] = {
        1: "N",
        2: IFDRational(51, 1),
        3: "E",
        4: IFDRational(7, 1),
    }
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()
