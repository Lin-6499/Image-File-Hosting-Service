"""Create an API key. Run from the project root:

    .venv\\Scripts\\python.exe -m scripts.mintkey "my-codex" --quota-gb 10
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import db  # noqa: E402

# The label is a name for your own bookkeeping -- nothing else. Passing a key
# string here is a natural misreading (the argument sits right next to the
# "api key:" line in the output), and it is silently useless: it mints yet
# another key merely *labelled* with that string, and does not import, recover
# or re-activate anything. Observed in practice, three times in a row, from
# someone following the README. So refuse it rather than let it happen quietly.
KEY_PREFIX = "sk_"


def main() -> int:
    ap = argparse.ArgumentParser(description="Mint an API key")
    ap.add_argument("name", help="human-readable label (a name, not a key)")
    ap.add_argument("--quota-gb", type=float, default=None, help="storage quota in GB")
    ap.add_argument("--rate-limit", type=int, default=None, help="requests per minute")
    ap.add_argument(
        "--force",
        action="store_true",
        help=f"allow a label starting with {KEY_PREFIX!r} (almost always a mistake)",
    )
    args = ap.parse_args()

    if args.name.startswith(KEY_PREFIX) and not args.force:
        print(
            f"refusing to use {args.name[:12]}... as a label: that looks like an\n"
            f"API key, not a name.\n\n"
            f"The argument is a LABEL -- a name you choose for your own\n"
            f"bookkeeping. Minting does not import or recover an existing key:\n"
            f"it always creates a new one, and the plaintext is shown once.\n\n"
            f"To use an existing key, skip this step and paste it into the\n"
            f"Authorize dialog at http://127.0.0.1:8000/docs.\n"
            f"To mint a new one:  python -m scripts.mintkey dev\n\n"
            f"Pass --force if you really do want a label that starts with "
            f"{KEY_PREFIX!r}.",
            file=sys.stderr,
        )
        return 2

    db.init()

    quota = None if args.quota_gb is None else int(args.quota_gb * 1024**3)
    key_id, plaintext = db.create_api_key(
        args.name, quota_bytes=quota, rate_limit=args.rate_limit
    )

    print("=" * 68)
    print(f"  key_id : {key_id}")
    print(f"  api key: {plaintext}")
    print("=" * 68)
    print("The plaintext key is shown once and stored only as a SHA-256 hash.")
    print("Store it now; it cannot be recovered later.")
    print("Retire it later with:  python -m scripts.keys disable " + key_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
