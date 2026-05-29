"""Path-canonicalization helpers (design doc §6).

Seatbelt matches rules against the **kernel-canonical** path. Any non-canonical
component (``/./``, ``/../``, ``//``, a trailing slash, or an unresolved symlink)
makes a ``subpath``/``literal`` rule *silently* fail to match — and a deny that
does not match protects nothing. Every path that enters the profile must be
canonicalized first.

These helpers reproduce the contracts in §6 exactly. They are written to be
**pure** wherever possible: ``home`` and ``cwd`` are always passed in as
parameters (never read from ``os.environ``/``os.getcwd``), so the lexical
behaviour can be unit-tested identically on Linux CI and on the macOS target.
The only filesystem touches are isolated to single branches in :func:`abspath`
(``os.path.realpath`` on existing dirs) and :func:`resolve1` (``os.readlink``).
"""

from __future__ import annotations

import os

__all__ = [
    "abspath",
    "add_ancestors",
    "normalize",
    "resolve1",
    "sbpl_escape",
]

# Prefixes the macOS kernel reports under ``/private`` (§6.1).
_PRIVATE_PREFIXES = ("/var", "/tmp", "/etc")


def normalize(path: str) -> str:
    """Map ``/var``, ``/tmp``, ``/etc`` under ``/private`` (§6.1).

    The kernel reports these three trees under ``/private`` and Seatbelt tests
    rules against that resolved form, so a rule on ``/tmp/...`` would never
    match. This is the *only* OS-divergent transform in the codebase, and it is
    deliberately a pure string operation with no filesystem dependency.

    Idempotent: a path already under ``/private/`` is returned unchanged, so it
    is safe to call after :func:`abspath` (whose ``realpath`` branch already
    yields ``/private/...`` on macOS).
    """
    if not path or path.startswith("/private/") or path == "/private":
        return path
    for prefix in _PRIVATE_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return "/private" + path
    return path


def _lexical_clean(path: str) -> str:
    """Collapse ``//``, drop ``.`` segments, resolve ``..`` — without touching the FS.

    Used as the fallback in :func:`abspath` for paths that do not exist as a
    directory. Implemented explicitly (rather than leaning on
    ``os.path.normpath``) so the behaviour is unambiguous and matches the §6.2
    contract: a relative naive expansion such as ``$PWD/./secrets`` is what once
    caused a deny rule to silently no-op (§10), so collapsing ``/./`` etc. here
    is correctness-critical.
    """
    is_abs = path.startswith("/")
    out: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not is_abs:
                out.append("..")
            # For absolute paths, ".." above root is discarded.
            continue
        out.append(segment)
    cleaned = "/".join(out)
    return "/" + cleaned if is_abs else cleaned


def abspath(path: str, *, cwd: str) -> str:
    """Canonicalize a user-supplied dir-list entry (§6.2).

    * Empty -> empty.
    * Relative -> resolved against ``cwd``.
    * **Exists as a directory** -> canonical absolute form via
      ``os.path.realpath`` (the Python equivalent of ``cd <path> && pwd -P``:
      resolves ``.``/``..``/symlinks/trailing slashes — i.e. what the kernel
      would report). This is the only filesystem access.
    * **Does not exist** -> lexical cleanup via :func:`_lexical_clean`.

    Caveat (§6.2): for a non-existent path the lexical result may diverge from
    the eventual kernel-canonical path if a symlinked ancestor is later created.
    Accepted edge case.
    """
    if not path:
        return ""
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    if os.path.isdir(path):
        return os.path.realpath(path)
    return _lexical_clean(path)


def resolve1(path: str) -> str:
    """Resolve a single level of symlink (§6.3).

    If ``path`` is a symlink, return its target as an absolute path (a relative
    target is resolved against the link's directory); otherwise return it
    unchanged. **One level only, by design** — the installer can symlink the
    hook scripts and ``settings.json`` out of a git checkout, and the read-allow
    / tamper-deny rules must cover the real file. A multi-hop chain is not fully
    followed (§10 caveat).
    """
    if not path or not os.path.islink(path):
        return path
    target = os.readlink(path)
    if not target.startswith("/"):
        target = os.path.join(os.path.dirname(path), target)
    return target


def sbpl_escape(s: str) -> str:
    """Escape a string for safe inclusion inside an SBPL ``"..."`` literal (§6.4).

    Backslashes are escaped first, then double-quotes — order matters, otherwise
    the backslash introduced for a quote would itself be doubled.
    """
    return s.replace("\\", "\\\\").replace('"', '\\"')


def add_ancestors(path: str, *, home: str, into: list[str]) -> None:
    """Collect a path's ``$HOME``-internal ancestor directories (§6.5).

    If ``path`` is under ``home``, walk from its parent up to **and including**
    ``home``, appending each directory once (insertion-order dedup into the
    caller-owned ``into`` list). Paths not under ``home`` contribute nothing.

    Feeds the ``file-read-metadata`` ancestor list (§4.4): the ``$HOME`` read
    blackout otherwise denies even ``lstat`` on the components leading to the
    workdir / allowlisted dirs, which breaks realpath-resolving tools. The list
    is accumulated across calls (workdir + every in-``$HOME`` allowlisted dir)
    so dedup is global and order-stable, matching the §4.8 example exactly.
    """
    home = home.rstrip("/")
    if not path.startswith(home + "/"):
        return
    cur = os.path.dirname(path)
    while True:
        if cur not in into:
            into.append(cur)
        if cur == home:
            break
        parent = os.path.dirname(cur)
        if parent == cur:  # reached filesystem root — safety guard
            break
        cur = parent
