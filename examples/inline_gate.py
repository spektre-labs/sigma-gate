#!/usr/bin/env python3
"""
inline_gate.py — gate a function's output; raise on unsafe.

Pattern: wrap any producer function so its output passes through guard()
before it can be returned. Unsafe output raises UnsafeOutputError with
a full reason list. Clean output is returned unchanged.

Run:
    python3 examples/inline_gate.py
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard import guard


class UnsafeOutputError(ValueError):
    """Raised when guard() blocks a function's return value."""

    def __init__(self, reasons: list, result: dict) -> None:
        self.reasons = reasons
        self.result = result
        super().__init__(f"output blocked: {reasons}")


def gated(fn=None, *, block_at: str = "medium"):
    """
    Decorator that runs guard() on a function's string return value.

    @gated
    def produce() -> str: ...

    @gated(block_at="high")
    def produce() -> str: ...
    """
    def _decorator(f):
        def _wrapper(*args, **kwargs):
            output = f(*args, **kwargs)
            if not isinstance(output, str):
                return output  # only gate strings
            result = guard(output, block_at=block_at)
            if not result["safe_to_ship"]:
                raise UnsafeOutputError(result["block_reasons"], result)
            return output
        _wrapper.__name__ = f.__name__
        return _wrapper

    if fn is not None:
        # called as @gated without parens
        return _decorator(fn)
    return _decorator


# ── demo ──────────────────────────────────────────────────────────────────────

@gated
def clean_summary() -> str:
    return "Revenue grew 12% in the EU segment this quarter."


@gated
def leaky_fn() -> str:
    # simulates a model that accidentally echoes a secret
    return "Here is the key: ghp_16C7e42F292c6912E7710c838347Ae178B4a"


@gated(block_at="high")
def pii_at_high() -> str:
    # medium PII (email alone) passes at block_at=high
    return "Contact us at support@example.com for help."


def main() -> None:
    print("=== inline_gate.py ===\n")

    # 1. Clean output passes through untouched.
    text = clean_summary()
    print(f"[PASS] clean_summary returned: {text!r}\n")

    # 2. Leaky function raises.
    try:
        leaky_fn()
        print("[FAIL] expected UnsafeOutputError")
    except UnsafeOutputError as e:
        print(f"[BLOCK] leaky_fn raised UnsafeOutputError")
        print(f"        reasons: {e.reasons}\n")

    # 3. PII email at block_at=high — medium severity does NOT block.
    text = pii_at_high()
    print(f"[PASS] pii_at_high(block_at=high) returned: {text!r}")
    print("       (email alone is medium severity; high threshold passes it)\n")

    print("All inline_gate demos ran correctly.")


if __name__ == "__main__":
    main()
