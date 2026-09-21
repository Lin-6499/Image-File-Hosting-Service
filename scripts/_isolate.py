"""Redirect the app's runtime data directory to a temporary location.

Import this **before** any ``app.*`` module. ``app.config.settings`` is a
module-level singleton built at import time, so the environment has to be
rewritten first -- importing ``app.db`` or ``app.main`` before calling
:func:`isolate` binds the paths to the real ``data/`` folder and the redirect
silently does nothing.

The in-process scripts (``smoke_test.py``, ``scan_demo.py``) are tests: they
create uploads, delete them, and assert on counts. Without isolation they
scribble into the developer's runtime store, so a manual verification run
afterwards sees a listing full of test artifacts rather than its own files.
``pytest`` already isolates via ``tests/conftest.py``; this brings the scripts
in line.

Not used by ``demo.py``, ``e2e_local.py`` or ``av_e2e.py``: those talk to a
running server over HTTP, and the server legitimately owns the real data
directory.

Set ``HOST_SCRIPT_NO_ISOLATE=1`` to opt out and target the real ``data/``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

ISOLATED = False


def isolate(prefix: str = "host-script-") -> Path | None:
    """Point the app at a throwaway data directory.

    Returns the temp root, or None when isolation was skipped.
    """
    global ISOLATED

    if os.environ.get("HOST_SCRIPT_NO_ISOLATE") == "1":
        return None

    root = Path(tempfile.mkdtemp(prefix=prefix))
    os.environ["DATA_DIR"] = str(root / "data")
    os.environ.setdefault("SECRET_KEY", "script-secret-key-not-for-production")
    os.environ.setdefault("DEBUG", "false")
    # WAL is unavailable on some Windows volumes; TRUNCATE keeps scripts
    # portable. See the journal-mode note in app/db.py.
    os.environ["DB_JOURNAL_MODE"] = "TRUNCATE"
    ISOLATED = True
    return root


def banner(root: Path | None) -> str:
    """One-line description of where this run will write."""
    if root is None:
        return "data dir : REAL data/ (isolation disabled)"
    return f"data dir : {root} (isolated; deleted with the temp dir)"
