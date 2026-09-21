"""Run the cleanup sweep. Intended for cron / Task Scheduler.

    .venv\\Scripts\\python.exe -m scripts.cleanup
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.cleanup import run_once  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

if __name__ == "__main__":
    stats = run_once()
    print(
        "cleanup: "
        f"scan_resolved={stats['scan_resolved']} "
        f"scan_released={stats['scan_released']} "
        f"marked={stats['marked']} "
        f"blobs_removed={stats['blobs_removed']} "
        f"hashes_purged={stats['hashes_purged']} "
        f"tmp_removed={stats['tmp_removed']}"
    )
