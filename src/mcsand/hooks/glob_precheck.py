"""PreToolUse Glob gate — ``security-glob-precheck.sh`` analogue (§5.3).

Directory checks test the **effective root** ``"${path%/}/${pattern}"`` (so a
sensitive dir hidden in the ``path`` argument is still caught); file-extension
checks test the pattern alone. Both inputs normalise a leading ``~`` to ``$HOME``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable

from . import lib

__all__ = ["CHECKS", "evaluate", "main"]

# (effective_root, pattern) -> block reason | None
GlobCheck = Callable[[str, str], "str | None"]


def _eff(pattern: str, reason: str, flags: int = 0) -> GlobCheck:
    rx = re.compile(pattern, flags)
    return lambda effective, pat: reason if rx.search(effective) else None


def _pat(pattern: str, reason: str, flags: int = 0) -> GlobCheck:
    rx = re.compile(pattern, flags)
    return lambda effective, pat: reason if rx.search(pat) else None


CHECKS: list[GlobCheck] = [
    # 1-3. Sensitive directories (tested against the effective root).
    _eff(r"(^|/)\.ssh(/|$)", "glob into ~/.ssh"),
    _eff(r"(^|/)\.aws(/|$)", "glob into ~/.aws"),
    _eff(r"(^|/)\.gnupg(/|$)", "glob into ~/.gnupg"),
    # 4. Env files (pattern).
    _pat(r"(^|/)\.env(rc|\.[^/]*|\*)?$", "glob for env files"),
    # 5. TLS/PKI (pattern, ci).
    _pat(r"\.(pem|key|p12|pfx|crt|cer|der)(\*)?$", "glob for TLS/PKI files", re.IGNORECASE),
    # 6. GPG/PGP files (pattern, ci).
    _pat(r"\.(gpg|pgp|asc)(\*)?$", "glob for GPG/PGP files", re.IGNORECASE),
    # 7. System credential files (effective root).
    _eff(r"^/etc/(shadow|gshadow|passwd|group|sudoers)($|/)", "glob for /etc credential files"),
    # 8. netrc (pattern).
    _pat(r"(^|/)\.netrc$", "glob for .netrc"),
    # 9. Generic secret file names (pattern, ci).
    _pat(
        r"(^|[/*?])(secret|secrets|credential|credentials|password|passwords|passwd|token|tokens"
        r"|api[_-]?key)(s)?\.(json|yaml|yml|toml|ini|txt|conf|cfg|env)$",
        "glob for generic secret files",
        re.IGNORECASE,
    ),
    # 10. Password-manager databases (pattern, ci).
    _pat(
        r"\.(kdbx|kdb|1pif|agilekeychain|opvault)(\*)?$",
        "glob for password-manager databases",
        re.IGNORECASE,
    ),
]


def evaluate(data: lib.JSONDict, home: str) -> str | None:
    """Block globs that target sensitive dirs / secret-file patterns (§5.3)."""
    ti = lib.tool_input(data)
    pattern = ti.get("pattern") or ""
    if not pattern:
        return None
    pattern = lib.expand_home(pattern, home)
    search_path = ti.get("path") or ""
    if search_path:
        search_path = lib.expand_home(search_path, home)
        effective = f"{search_path.rstrip('/')}/{pattern}"
    else:
        effective = pattern
    for check in CHECKS:
        reason = check(effective, pattern)
        if reason:
            return reason
    return None


def main() -> int:
    return lib.run_gate(evaluate, tool_name="Glob")


if __name__ == "__main__":
    sys.exit(main())
