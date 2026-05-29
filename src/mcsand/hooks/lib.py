"""Shared library for the security hooks (claude-hooks-design.md §3-§4).

Pure matching helpers plus the stdin→stdout protocol runner. The protocol:

* Input arrives as a JSON object on stdin (the tool call).
* **Block** = print ``{"decision":"block","reason":"…"}`` to stdout.
* **Allow** = print nothing.
* Every gate **exits 0** regardless.

This implementation is **fail-closed** (a deliberate deviation from the reference,
which is fail-open): a clean "no rule matched" allows, but an unexpected
exception or a malformed (non-empty, non-JSON) payload emits ``block``. Empty
stdin still allows — it is a valid empty call, not garbage.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from typing import Any, TextIO

__all__ = [
    "Evaluator",
    "JSONDict",
    "block_json",
    "expand_home",
    "log",
    "run_gate",
    "tool_input",
]

JSONDict = dict[str, Any]

# An evaluator inspects the parsed tool call + ``$HOME`` and returns a block
# reason, or ``None`` to allow.
Evaluator = Callable[[JSONDict, str], "str | None"]

_LOG_MAX_BYTES = 5 * 1024 * 1024  # rotate at 5 MB (§4)
_LOG_GENERATIONS = 5  # keep .1 … .5 (§4)


def tool_input(data: JSONDict) -> JSONDict:
    """Return the ``tool_input`` object, tolerating a missing/non-dict field."""
    ti = data.get("tool_input")
    return ti if isinstance(ti, dict) else {}


def expand_home(path: str, home: str) -> str:
    """Normalise a leading ``~`` to ``$HOME`` (§5). Only the leading ``~`` form."""
    if not home:
        return path
    if path == "~":
        return home
    if path.startswith("~/"):
        return home + path[1:]
    return path


def block_json(reason: str) -> str:
    """Render the block decision Claude Code expects on stdout."""
    return json.dumps({"decision": "block", "reason": reason})


def _rotate_log(path: str) -> None:
    """Shift ``.1`` … ``.5`` and rename current → ``.1`` when ≥ 5 MB (§4)."""
    try:
        if os.path.getsize(path) < _LOG_MAX_BYTES:
            return
    except OSError:
        return
    oldest = f"{path}.{_LOG_GENERATIONS}"
    if os.path.exists(oldest):
        os.remove(oldest)
    for gen in range(_LOG_GENERATIONS - 1, 0, -1):
        src = f"{path}.{gen}"
        if os.path.exists(src):
            os.replace(src, f"{path}.{gen + 1}")
    os.replace(path, f"{path}.1")


def log(home: str, message: str) -> None:
    """Append a UTC-stamped line to ``~/.claude/security.log`` (§4, §9).

    Best-effort: logging must never break a gate, so all errors are swallowed.
    """
    if not home:
        return
    try:
        import datetime

        log_dir = os.path.join(home, ".claude")
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "security.log")
        _rotate_log(path)
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


def _notify(reason: str) -> None:
    """Fire a desktop notification on block (macOS ``osascript``; no-op else)."""
    if sys.platform != "darwin":
        return
    try:
        import subprocess

        script = f'display notification {json.dumps(reason)} with title "Claude Security"'
        subprocess.run(
            ["osascript", "-e", script],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        pass


def run_gate(
    evaluate: Evaluator,
    *,
    tool_name: str,
    parse: bool = True,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    home: str | None = None,
) -> int:
    """Run one gate end-to-end and return the process exit code (always 0).

    ``parse=False`` is for the env-only UserPromptSubmit gate, which ignores the
    payload entirely (so a malformed body must not fail-closed-block it).
    """
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    home = home if home is not None else os.environ.get("HOME", "")

    try:
        raw = stdin.read()
        data: JSONDict = {}
        if parse and raw.strip():
            loaded = json.loads(raw)
            if not isinstance(loaded, dict):
                raise ValueError("hook payload is not a JSON object")
            data = loaded
        reason = evaluate(data, home)
    except Exception as exc:
        reason = f"mcsand hook internal error (fail-closed): {exc}"

    if reason:
        stdout.write(block_json(reason) + "\n")
        log(home, f"BLOCKED [{tool_name}] reason={reason}")
        _notify(reason)
    else:
        log(home, f"ALLOW [{tool_name}]")
    return 0
