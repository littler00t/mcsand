"""PreToolUse Bash gate — ``security-precheck.sh`` analogue (§5.1).

Seven checks against the whole command string; checks 3, 5 and 7 are compound
*AND* (both regexes must match) to cut false positives. All case-sensitive (the
doc marks none "ci"). Regexes are transcribed verbatim from §5.1 (POSIX ERE →
Python ``re``), including the documented gaps (e.g. ``. .env`` is not caught
because ``\b\\.`` cannot match a leading ``. ``).
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable

from . import lib

__all__ = ["CHECKS", "evaluate", "main"]

Check = Callable[[str], "str | None"]


def _re(pattern: str, reason: str, flags: int = 0) -> Check:
    rx = re.compile(pattern, flags)
    return lambda command: reason if rx.search(command) else None


def _and(pattern_a: str, pattern_b: str, reason: str, flags: int = 0) -> Check:
    a = re.compile(pattern_a, flags)
    b = re.compile(pattern_b, flags)
    return lambda command: reason if (a.search(command) and b.search(command)) else None


CHECKS: list[Check] = [
    # 1. Dangerous / safety-off flags.
    _re(
        r"(--dangerously-skip-permissions|--no-verify|--force)",
        "dangerous flag (permissions/verify/force bypass)",
    ),
    # 2. Pipe-to-shell (curl … | bash, … | sudo sh).
    _re(
        r"\|\s*(sudo\s+)?(bash|sh|zsh|fish|dash|ksh|csh|tcsh)\b",
        "pipe-to-shell (download piped into an interpreter)",
    ),
    # 3. Sensitive recursive delete (AND): rm -rf + a sensitive path.
    _and(
        r"\brm\b.*-[a-zA-Z]*[rR][a-zA-Z]*[fF]|-[a-zA-Z]*[fF][a-zA-Z]*[rR]",
        r"(\s|=)(/\s|/\"|/$|~/|~\"|~\s|~$|\$HOME|\.claude|\.ssh|\.gnupg)",
        "recursive delete of a sensitive path",
    ),
    # 4. World-writable chmod.
    _re(
        r"\bchmod\b.*(777|0777|a\+rwx|ugo\+rwx)",
        "world-writable chmod (777 / a+rwx)",
    ),
    # 5. Credential exfiltration (AND): network tool + secret keyword.
    _and(
        r"\b(curl|wget|nc|ncat|netcat)\b",
        r"\b(API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY)\b",
        "credential exfiltration (network tool + secret keyword)",
    ),
    # 6. Sensitive env-var expansion.
    _re(
        r"\$\{?(API_KEY|TOKEN|PASSWORD|PASSWD|SECRET|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY"
        r"|DB_PASS|DB_PASSWORD|DATABASE_URL|DATABASE_PASSWORD)\b",
        "sensitive environment-variable expansion",
    ),
    # 7. Env-file read via a shell reader (AND): reader command + env-file name.
    _and(
        r"\b(cat|less|more|head|tail|tee|bat|source|\.|nano|vim|vi|nvim|emacs|code|subl)\b",
        r"\.env(rc|\.local|\.production|\.staging|\.development|\.test)?(\s|\"|'|$)",
        "reading an env file via a shell command",
    ),
]


def evaluate(data: lib.JSONDict, home: str) -> str | None:
    """Return a block reason for a dangerous Bash command, else ``None``."""
    command = lib.tool_input(data).get("command") or ""
    if not command:
        return None
    for check in CHECKS:
        reason = check(command)
        if reason:
            return reason
    return None


def main() -> int:
    return lib.run_gate(evaluate, tool_name="Bash")


if __name__ == "__main__":
    sys.exit(main())
