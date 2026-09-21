"""Start the development server with autoreload.

    .venv\\Scripts\\python.exe -m scripts.dev
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import db  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def reload_excludes() -> list[str]:
    """Absolute paths of directories the reloader should ignore.

    Two traps here, both confirmed against uvicorn's implementation rather
    than assumed:

    1. **Bare names do not work.** ``FileFilter`` keeps directory entries as
       given and tests them with ``exclude_dir in path.parents``. A relative
       ``Path("data")`` never equals the absolute parents of a watched file, so
       the exclusion silently does nothing. Only absolute paths match.
    2. **An absolute path to a directory that does not exist crashes startup.**
       ``resolve_reload_patterns`` falls through to ``Path.cwd().glob(<abs>)``,
       which raises ``NotImplementedError: Non-relative patterns are
       unsupported``. Hence the ``is_dir()`` filter -- ``.pytest_cache`` and
       friends do not exist until something has run.

    This is a convenience, not a correctness fix. uvicorn only reacts to
    ``*.py``, and ``data/`` holds no Python files, so uploads never triggered
    restarts anyway. What this buys is keeping the watcher off the thousands of
    ``.py`` files in ``site-packages`` when packages are installed while the
    server is running.
    """
    wanted = [".venv", "data", "scratch", ".pytest_cache", ".mypy_cache", ".ruff_cache"]
    return [str(PROJECT_ROOT / name) for name in wanted if (PROJECT_ROOT / name).is_dir()]


def main() -> int:
    settings.ensure_dirs()
    db.init()

    print("=" * 68)
    print("  Image & Text Hosting Service -- development server")
    print("=" * 68)
    print(f"  Base URL : {settings.base_url}")
    print(f"  Docs     : {settings.base_url}/docs")
    print(f"  Data dir : {settings.data_dir}")
    print(f"  DB       : {settings.db_path}")
    print("=" * 68)
    print("  No API key yet? Run:  .venv\\Scripts\\python.exe -m scripts.mintkey dev")
    print("=" * 68)
    print()

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        reload_excludes=reload_excludes(),
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
