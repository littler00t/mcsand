"""PostToolUse scan — ``security-scan.sh`` analogue (§7.1).

Runs after every Bash command; if the command fetched or installed code, scans
the likely landing directory with ClamAV. It **cannot block** (the bytes are
already on disk) — it only warns to stderr and logs. The command→target
classification is pure and unit-tested; the ``clamscan`` invocation is the only
side effect. Targets are resolved **without** ``eval`` (the reference's
``eval echo`` on attacker-influenced text is an injection smell — §7.1).
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from collections.abc import Mapping

from . import lib

__all__ = ["classify", "main", "resolve_target"]

# Trigger regexes (on the command) → a classification kind.
_TRIGGERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(curl|wget)\b"), "download"),
    (re.compile(r"\bgit\s+clone\b"), "clone"),
    (re.compile(r"\b(pip|pip3)\s+install\b"), "pip"),
    (re.compile(r"\bnpm\s+(install|ci)\b"), "npm"),
    (re.compile(r"\bcargo\s+(add|install|fetch|build)\b"), "cargo"),
    (re.compile(r"\bgo\s+(get|install|mod\s+download)\b"), "go"),
]


def classify(command: str) -> tuple[str, str] | None:
    """Classify a Bash command, returning ``(kind, raw_target)`` or ``None``.

    ``raw_target`` is a command-derived hint (an output path or clone dir);
    empty for kinds whose target is a fixed cache dir. Pure — no filesystem.
    """
    if not command:
        return None
    for pattern, kind in _TRIGGERS:
        if pattern.search(command):
            return kind, _raw_target(kind, command)
    return None


def _raw_target(kind: str, command: str) -> str:
    """Extract a command-line target hint via :mod:`shlex` (no shell evaluation)."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    if kind == "download":
        for i, tok in enumerate(tokens):
            if tok in ("-o", "--output") and i + 1 < len(tokens):
                return tokens[i + 1]
        for i, tok in enumerate(tokens):
            if tok == "-O" and i + 1 < len(tokens):
                return tokens[i + 1]
        return ""
    if kind == "clone":
        # Last non-flag token after `clone` (skip the URL by taking the final arg).
        non_flags = [t for t in tokens if not t.startswith("-")]
        # tokens[:2] are `git clone`; a trailing dir arg, if any, is last.
        if len(non_flags) >= 4:  # git, clone, <url>, <dir>
            return non_flags[-1]
        return ""
    return ""


def resolve_target(
    kind: str, raw: str, home: str, env: Mapping[str, str], user_site: str | None = None
) -> str:
    """Resolve ``(kind, raw)`` to a directory to scan (§7.1)."""
    if kind == "download":
        return lib.expand_home(raw, home) if raw else f"{home}/Downloads"
    if kind == "clone":
        return lib.expand_home(raw, home) if raw else "."
    if kind == "pip":
        return user_site or os.path.join(home, ".local", "lib")
    if kind == "npm":
        return "node_modules"
    if kind == "cargo":
        cargo_home = env.get("CARGO_HOME") or f"{home}/.cargo"
        return f"{cargo_home}/registry/src"
    if kind == "go":
        gopath = env.get("GOPATH") or f"{home}/go"
        return f"{gopath}/pkg/mod/cache"
    return "."


def _user_site() -> str | None:
    try:
        import site

        return site.getusersitepackages()
    except Exception:
        return None


def main() -> int:
    """Detect-only ClamAV scan. Never blocks; warns to stderr and logs (§7.1)."""
    import json

    home = os.environ.get("HOME", "")
    try:
        raw_in = sys.stdin.read()
        data = json.loads(raw_in) if raw_in.strip() else {}
        command = lib.tool_input(data).get("command") or "" if isinstance(data, dict) else ""
    except (ValueError, OSError):
        return 0  # PostToolUse can never block; a bad payload is just a no-op.

    classified = classify(command)
    if classified is None:
        return 0
    kind, raw = classified
    target = resolve_target(kind, raw, home, os.environ, _user_site())

    import shutil

    clamscan = shutil.which("clamscan")
    if not clamscan or not os.path.exists(target):
        have = "no" if not clamscan else "yes"
        lib.log(home, f"SCAN [skipped] kind={kind} target={target} clamscan={have}")
        return 0

    import subprocess

    cmd = [clamscan, "--recursive", "--max-dir-recursion=5", "--no-summary", "--infected", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"[SECURITY] ClamAV scan timed out for {target}\n")
        lib.log(home, f"WARN scan timeout target={target}")
        return 0
    except OSError:
        return 0

    if result.returncode == 1:
        for line in (result.stdout or "").splitlines():
            if line.strip():
                sys.stderr.write(f"[SECURITY] {line}\n")
        sys.stderr.write(f"[SECURITY] ClamAV found infected files under {target}; remove them.\n")
        lib.log(home, f"WARN infected target={target}")
    elif result.returncode == 0:
        lib.log(home, f"SCAN [clean] target={target}")
    else:
        sys.stderr.write(f"[SECURITY] ClamAV scan error (exit {result.returncode}) for {target}\n")
        lib.log(home, f"WARN scan error rc={result.returncode} target={target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
