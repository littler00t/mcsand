"""PreToolUse Read gate — ``security-read-precheck.sh`` analogue (§5.2)."""

from __future__ import annotations

import sys

from . import lib
from ._pathgate import path_checks

__all__ = ["CHECKS", "evaluate", "main"]

CHECKS = path_checks("read")


def evaluate(data: lib.JSONDict, home: str) -> str | None:
    """Block reads of well-known secret files (§5.2), else ``None``."""
    file_path = lib.tool_input(data).get("file_path") or ""
    if not file_path:
        return None
    file_path = lib.expand_home(file_path, home)
    basename = file_path.rsplit("/", 1)[-1]
    for check in CHECKS:
        reason = check(file_path, basename)
        if reason:
            return reason
    return None


def main() -> int:
    return lib.run_gate(evaluate, tool_name="Read")


if __name__ == "__main__":
    sys.exit(main())
