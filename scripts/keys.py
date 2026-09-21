"""Inspect, revoke and purge API keys.

    .venv\\Scripts\\python.exe -m scripts.keys                       # list
    .venv\\Scripts\\python.exe -m scripts.keys disable key_abc123    # revoke
    .venv\\Scripts\\python.exe -m scripts.keys enable  key_abc123
    .venv\\Scripts\\python.exe -m scripts.keys disable --label "old laptop"
    .venv\\Scripts\\python.exe -m scripts.keys purge   key_abc123    # only if unused

Why this exists: minting a key has always been one command, but revoking one
had no entry point at all -- so the only way to retire a leaked key was to open
sqlite3 by hand. A credential you cannot revoke is not really rotatable, and
"rotate it later" quietly becomes "never".

Two different removals, deliberately kept apart:

* ``disable`` is the revocation primitive. The row survives, so the audit log
  still resolves ``key_id`` to a label.
* ``purge`` deletes outright, and only for keys that **no audit entry
  references**. That covers the keys nobody ever used -- a typo, a re-mint, or
  a ``sk_``-as-label mistake -- which have no history to preserve and would
  otherwise clutter the listing forever. Anything with history is refused, not
  silently skipped.

The plaintext is unrecoverable either way -- it is stored only as a SHA-256
hash -- so disabling and purging differ in what they do to the *audit trail*,
not in whether the credential can be recovered.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import db  # noqa: E402

HEADER = f"{'key_id':<20} {'on':<3} {'label':<34} {'created':<17} {'used':>10}"


def _fmt_bytes(n: int | None) -> str:
    if not n:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return "-"


def _created(ts: int | None) -> str:
    return "-" if not ts else time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _clip(text: str, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def cmd_list(_args: argparse.Namespace) -> int:
    rows = db.list_api_keys()
    if not rows:
        print("no API keys yet -- mint one with: python -m scripts.mintkey <label>")
        return 0
    print(HEADER)
    print("-" * len(HEADER))
    for r in rows:
        print(
            f"{r['key_id']:<20} "
            f"{'yes' if r['enabled'] else 'NO':<3} "
            f"{_clip(r['name'], 34):<34} "
            f"{_created(r['created_at']):<17} "
            f"{_fmt_bytes(r['used_bytes']):>10}"
        )
    off = sum(1 for r in rows if not r["enabled"])
    print(f"\n{len(rows)} key(s), {off} disabled.")
    return 0


def _resolve(args: argparse.Namespace) -> list[str]:
    """Turn the selector into a list of key_ids."""
    if args.label is not None:
        matches = [r["key_id"] for r in db.list_api_keys() if r["name"] == args.label]
        if not matches:
            print(f"no key labelled {args.label!r}", file=sys.stderr)
        return matches
    return list(args.key_ids)


def _apply(enable: bool, ids: list[str]) -> int:
    if not ids:
        print("nothing to do: pass one or more key_id values, or --label",
              file=sys.stderr)
        return 2
    verb = "enabled" if enable else "disabled"
    failures = 0
    for key_id in ids:
        if db.set_key_enabled(key_id, enable):
            print(f"  {verb}: {key_id}")
        else:
            print(f"  NOT FOUND: {key_id}", file=sys.stderr)
            failures += 1
    if not enable and len(ids) > failures:
        print("\nThe change applies to the next request; no restart needed.")
    return 1 if failures else 0


def cmd_purge(ids: list[str]) -> int:
    """Delete keys that no audit entry references.

    A key with history is refused loudly rather than skipped quietly: the whole
    value of the guard is that you find out you cannot delete it, and why.
    """
    if not ids:
        print(
            "nothing to do: pass one or more key_id values, or --label",
            file=sys.stderr,
        )
        return 2
    failures = 0
    for key_id in ids:
        used = db.audit_rows_for_key(key_id)
        if used:
            print(
                f"  kept:      {key_id}  ({used} audit row(s) reference it"
                f" -- disable it instead)"
            )
            continue
        if db.delete_unused_key(key_id):
            print(f"  purged:    {key_id}")
        else:
            print(f"  NOT FOUND: {key_id}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="List, revoke or purge API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "disable keeps the row so the audit log still resolves key_id to a\n"
            "label. purge deletes outright, but only keys that no audit entry\n"
            "references -- anything with history is refused.\n"
            "Neither recovers the plaintext: that is gone."
        ),
    )
    ap.add_argument(
        "action",
        choices=("list", "disable", "enable", "purge"),
        nargs="?",
        default="list",
    )
    ap.add_argument("key_ids", nargs="*", help="one or more key_id values")
    ap.add_argument(
        "--label",
        default=None,
        help="select by label instead of key_id (affects every key with that label)",
    )
    args = ap.parse_args()

    db.init()

    if args.action == "list":
        return cmd_list(args)
    if args.action == "purge":
        return cmd_purge(_resolve(args))
    return _apply(args.action == "enable", _resolve(args))


if __name__ == "__main__":
    raise SystemExit(main())
