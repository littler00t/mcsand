"""UserPromptSubmit gate — ``security-sandbox-precheck.sh`` analogue (§7.2).

Drains and ignores stdin; the decision is purely environmental: block every
prompt unless ``CLAUDE_SANDBOX`` is set (the marker the sandbox wrapper exports),
forcing Claude to be launched through ``mcsand``. The marker is trivially
spoofable (§10) — this guards against *accidental* direct invocation, not a
hostile local user.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

from . import lib

__all__ = ["decide", "main"]


def decide(env: Mapping[str, str]) -> str | None:
    """Return a block reason unless ``CLAUDE_SANDBOX`` is set."""
    if env.get("CLAUDE_SANDBOX"):
        return None
    return "Claude Code must be launched via the mcsand sandbox (CLAUDE_SANDBOX is not set)."


def main() -> int:
    # parse=False: the payload is intentionally ignored, so a malformed body must
    # not fail-closed-block; the decision comes from the environment only.
    return lib.run_gate(
        lambda _data, _home: decide(os.environ),
        tool_name="UserPromptSubmit",
        parse=False,
    )


if __name__ == "__main__":
    sys.exit(main())
