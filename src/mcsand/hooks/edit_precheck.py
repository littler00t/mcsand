"""PreToolUse Edit gate — ``security-edit-precheck.sh`` analogue (§5.4).

Mirrors Read with the whole-``~/.ssh`` broadening (check 3) and the check-11
self-protection rule. Kept in lockstep with Write via the shared builder.
"""

from __future__ import annotations

import sys

from . import lib
from ._pathgate import path_checks

__all__ = ["CHECKS", "evaluate", "main"]

CHECKS = path_checks("edit")


def evaluate(data: lib.JSONDict, home: str) -> str | None:
    """Block edits to secret files / Claude's own security config (§5.4)."""
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
    return lib.run_gate(evaluate, tool_name="Edit")


if __name__ == "__main__":
    sys.exit(main())
