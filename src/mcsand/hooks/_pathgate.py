"""Shared path-gate check builder for the Read / Edit / Write gates (§5.2-§5.5).

A single source of truth so Edit and Write stay in lockstep with Read. The three
gates differ only in three places:

* **Read**: check 3 matches specific SSH key/config names; check 6 matches the
  specific ``/etc`` credential files; no self-protection.
* **Edit**: check 3 broadens to the whole ``~/.ssh`` tree; adds check 11
  (Claude's own ``hooks/`` + ``settings.json``).
* **Write**: as Edit, but check 6 broadens to all of ``/etc``.

Checks operate on ``(file_path, basename)``; both are case-sensitive unless the
§5 table marks a check "ci" (then :data:`re.IGNORECASE`).
"""

from __future__ import annotations

import re
from collections.abc import Callable

__all__ = ["PathCheck", "path_checks"]

# (file_path, basename) -> block reason | None
PathCheck = Callable[[str, str], "str | None"]


def _fp(pattern: str, reason: str, flags: int = 0) -> PathCheck:
    rx = re.compile(pattern, flags)
    return lambda fp, base: reason if rx.search(fp) else None


def _base(pattern: str, reason: str, flags: int = 0) -> PathCheck:
    rx = re.compile(pattern, flags)
    return lambda fp, base: reason if rx.search(base) else None


def _either(*checks: PathCheck) -> PathCheck:
    def check(fp: str, base: str) -> str | None:
        for ch in checks:
            reason = ch(fp, base)
            if reason:
                return reason
        return None

    return check


def path_checks(mode: str) -> list[PathCheck]:
    """Build the ordered check list for ``mode`` in ``{"read", "edit", "write"}``."""
    checks: list[PathCheck] = [
        # 1. Env files.
        _base(r"^\.env(rc|\..*)?$", "env file"),
        # 2. AWS credentials.
        _fp(r"(^|/)\.aws/(credentials|config)$", "AWS credentials"),
    ]

    # 3. SSH — specific names for reads, whole dir for edit/write.
    if mode == "read":
        checks.append(
            _fp(
                r"(^|/)\.ssh/(id_[a-zA-Z0-9_-]+|authorized_keys|known_hosts|config)$",
                "SSH key / config file",
            )
        )
    else:
        checks.append(_fp(r"(^|/)\.ssh/", "write into ~/.ssh"))

    checks += [
        # 4. GPG/PGP (dir OR file extension).
        _either(
            _fp(r"(^|/)\.gnupg/", "GPG keyring directory"),
            _base(r"\.(gpg|pgp|asc)$", "GPG/PGP file"),
        ),
        # 5. TLS/PKI (ci).
        _base(r"\.(pem|key|p12|pfx|crt|cer|der)$", "TLS/PKI key or certificate", re.IGNORECASE),
    ]

    # 6. System credential files — specific for read/edit, all of /etc for write.
    if mode == "write":
        checks.append(_fp(r"^/etc/", "write under /etc"))
    else:
        checks.append(
            _fp(r"^/etc/(shadow|gshadow|passwd|group|sudoers)$", "system credential file")
        )

    checks += [
        # 7. netrc.
        _base(r"^\.netrc$", "netrc"),
        # 8. macOS Keychain (ci).
        _base(r"\.(keychain|keychain-db)$", "macOS keychain", re.IGNORECASE),
        # 9. Generic secret file names (ci).
        _base(
            r"^(secret|secrets|credential|credentials|password|passwords|passwd|token|tokens"
            r"|api[_-]?key)(s)?\.(json|yaml|yml|toml|ini|txt|conf|cfg|env)$",
            "generic secret file name",
            re.IGNORECASE,
        ),
        # 10. Password-manager databases (ci).
        _base(
            r"\.(kdbx|kdb|1pif|agilekeychain|opvault)$",
            "password-manager database",
            re.IGNORECASE,
        ),
    ]

    # 11. Self-protection (edit/write only): Claude's own hooks + settings.json.
    if mode in ("edit", "write"):
        checks.append(
            _fp(
                r"(^|/)\.claude/(hooks/|settings\.json$)",
                "Claude security config (hooks / settings.json)",
            )
        )
    return checks
