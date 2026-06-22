#!/usr/bin/env python3
"""
ci_gate.py — scan a file or stdin; exit nonzero if unsafe.

For pre-commit hooks, CI pipelines, and shell pipelines.

Usage:
    # scan a specific file
    python3 examples/ci_gate.py path/to/file.txt

    # scan stdin
    echo "some model output" | python3 examples/ci_gate.py

    # raise threshold (only block high/critical)
    python3 examples/ci_gate.py --block-at high path/to/file.txt

    # quiet mode — no output, just exit code
    python3 examples/ci_gate.py --quiet path/to/file.txt

Exit codes:
    0   safe_to_ship — text passed all checks at the given threshold
    1   blocked — one or more dimensions exceeded the threshold
    2   usage or I/O error
"""
from __future__ import annotations
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard import guard


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="ci_gate.py",
        description="σ-gate: scan a file or stdin and exit nonzero if unsafe.",
    )
    p.add_argument(
        "file",
        nargs="?",
        help="file to scan; omit to read from stdin",
    )
    p.add_argument(
        "--block-at",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="severity threshold to block at (default: medium)",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="suppress output; rely on exit code only",
    )
    p.add_argument(
        "--json", "-j",
        action="store_true",
        dest="json_out",
        help="emit full JSON verdict to stdout",
    )
    return p.parse_args(argv)


def _read_text(filepath):
    """Read from file path or stdin. Returns (text, source_label)."""
    if filepath:
        path = Path(filepath)
        if not path.exists():
            print(f"ci_gate: file not found: {filepath}", file=sys.stderr)
            sys.exit(2)
        return path.read_text(encoding="utf-8", errors="replace"), str(path)
    if sys.stdin.isatty():
        print("ci_gate: no file given and stdin is a tty — pipe text in or pass a filename.", file=sys.stderr)
        sys.exit(2)
    return sys.stdin.read(), "<stdin>"


def main(argv=None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    text, source = _read_text(args.file)

    if not text.strip():
        if not args.quiet:
            print(f"ci_gate: {source}: empty — nothing to scan", file=sys.stderr)
        return 0

    result = guard(text, block_at=args.block_at)

    if args.json_out:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["safe_to_ship"] else 1

    if args.quiet:
        return 0 if result["safe_to_ship"] else 1

    if result["safe_to_ship"]:
        print(f"ci_gate: {source}: PASS [{result['severity']}]")
        return 0

    print(f"ci_gate: {source}: BLOCK [{result['severity']}]", file=sys.stderr)
    for reason in result["block_reasons"]:
        print(f"  - {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
