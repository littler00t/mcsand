"""SBPL profile renderer (design doc §3-§5) — the core deliverable.

:func:`render_profile` is a **pure** function: it takes a fully-resolved
:class:`PolicyConfig` (every path already canonicalized by the caller) and emits
the Seatbelt profile text. It performs no filesystem access and no path
resolution, which makes the golden tests and the §13 "no non-canonical
component" regression test trivially runnable on Linux CI.

Two properties from §3 are load-bearing and encoded here:

* **Order is policy.** The seven sections are emitted top-to-bottom and Seatbelt
  uses *last-match-wins*, so the deny/re-allow and allow/deny-override structure
  depends on this exact ordering. Do not reorder.
* **Two rules for memory isolation.** ``process-info*`` does not cover Mach task
  ports, so both it and ``mach-task-read``/``mach-task-name`` are denied.

Reads are **deny-by-default** (v2 §4.3): a single ``(deny file-read*)`` blacks
out the whole filesystem, then a fail-closed allowlist re-grants exactly what
Claude needs — the macOS system roots that hold the dynamic linker / dyld shared
cache and frameworks (``SYSTEM_READ_SUBPATHS``), the ``/`` ``/etc`` ``/tmp``
``/var`` literals dyld reads/readlinks at launch (``SYSTEM_READ_LITERALS``), the
resolved ``claude`` binary dir, and the in-policy set. That in-policy set is
*composed* here from the structured allowlists: every read-write / read-only
entry that is **not already covered by a system read root** (workdir,
``~/.claude``, ``.claude.json``, ``.gitconfig`` …) — so ``/private/tmp`` and
``/dev/*`` are dropped (the roots cover them) while a ``--rw /data`` dir outside
``$HOME`` is re-listed (nothing else would make it readable). A
``(deny file-read* (subpath "/System/Volumes/Data"))`` is then layered on top to
close the APFS firmlink alias for denied ``$HOME`` files (v2 §10).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .paths import sbpl_escape

__all__ = [
    "FIRMLINK_DENY",
    "SYSTEM_READ_LITERALS",
    "SYSTEM_READ_SUBPATHS",
    "Allowlist",
    "PolicyConfig",
    "render_profile",
]

# v2 §4.3 / §5.5: the stable system read-roots re-allowed after the global
# read-deny. /System + /private cover every dyld-shared-cache location Apple has
# shipped (incl. Cryptexes); the rest hold system binaries/libraries/frameworks.
SYSTEM_READ_SUBPATHS = (
    "/System",
    "/private",
    "/usr",
    "/bin",
    "/sbin",
    "/Library",
    "/dev",
    "/opt",
)
# Root-level literals dyld touches at launch: file-read-data on "/" (omit it and
# every process SIGABRTs) and readlink on the /etc /tmp /var symlinks into
# /private (omit them and interactive Claude hangs on $TMPDIR). v2 §5.5, §10.
SYSTEM_READ_LITERALS = ("/", "/etc", "/tmp", "/var")
# APFS firmlink: ~/file is also reachable as /System/Volumes/Data/Users/...,
# which the /System read-allow would otherwise expose. Denied after the allow.
FIRMLINK_DENY = "/System/Volumes/Data"


@dataclass(frozen=True)
class Allowlist:
    """An ordered set of path matchers for one access level."""

    subpaths: tuple[str, ...] = ()
    literals: tuple[str, ...] = ()
    regexes: tuple[str, ...] = ()  # raw regex source, e.g. "^/dev/ttys"


@dataclass(frozen=True)
class PolicyConfig:
    """Everything :func:`render_profile` needs, fully pre-canonicalized.

    Assembled by :mod:`mcsand.context` from a :class:`~mcsand.config.LaunchConfig`
    plus resolved opt-ins. Held as plain tuples so rendering is deterministic.
    """

    home: str
    workdir: str  # resolved project dir (also rw.subpaths[0]); used by the launcher
    rw: Allowlist  # §5.1 full read-write set, in emission order
    ro: Allowlist  # §5.2 read-only-in-$HOME set (subpaths + .gitconfig literal)
    claude_read_dir: str | None = None  # resolved `claude` binary dir (v2 §5.5)
    ancestors: tuple[str, ...] = ()  # §5.3 file-read-metadata literals
    tamper_subpaths: tuple[str, ...] = ()  # §5.4 hook dirs
    tamper_literals: tuple[str, ...] = ()  # §5.4 settings.json (seen + symlink target)
    blocked_dirs: tuple[str, ...] = field(default=())  # §4.6 opt-in hard deny


def _subpath(path: str) -> str:
    return f'(subpath "{sbpl_escape(path)}")'


def _literal(path: str) -> str:
    return f'(literal "{sbpl_escape(path)}")'


def _regex(source: str) -> str:
    # Regex sources here are fixed internal constants (e.g. "^/dev/ttys"), not
    # user paths, so they are embedded verbatim rather than string-escaped.
    return f'(regex #"{source}")'


def _block(head: str, matchers: list[str]) -> str:
    """Render a multi-matcher rule with one matcher per indented line.

    The closing paren of the rule is appended to the final matcher, matching the
    style in §4.8 (e.g. ``  (regex #"^/dev/fd/"))``).
    """
    lines = [f"({head}"]
    for i, matcher in enumerate(matchers):
        suffix = ")" if i == len(matchers) - 1 else ""
        lines.append(f"  {matcher}{suffix}")
    return "\n".join(lines)


def _under_system_root(path: str) -> bool:
    """True if ``path`` is already covered by a system read-root (v2 §5.5).

    Such paths (``/private/tmp``, ``/dev/null`` …) are readable via the coarse
    ``SYSTEM_READ_SUBPATHS`` / ``SYSTEM_READ_LITERALS`` grants and so must NOT be
    re-listed in the composed in-policy read-allow set — matching the v2 §4.8
    example, which omits them.
    """
    if path in SYSTEM_READ_LITERALS:
        return True
    return any(path == root or path.startswith(root + "/") for root in SYSTEM_READ_SUBPATHS)


def _needs_read_allow(path: str) -> bool:
    """A read-write / read-only entry needs an explicit read grant iff it is not
    already covered by a system read-root (so workdir, ``~/.claude``, a
    ``--rw /data`` dir qualify; ``/private/tmp`` and ``/dev/*`` do not)."""
    return not _under_system_root(path)


def _rw_matchers(rw: Allowlist) -> list[str]:
    return (
        [_subpath(p) for p in rw.subpaths]
        + [_literal(p) for p in rw.literals]
        + [_regex(r) for r in rw.regexes]
    )


def _read_matchers(cfg: PolicyConfig) -> list[str]:
    """Compose the read-allow set (v2 §4.3): system roots + ``/`` etc. literals +
    the resolved claude dir + every read-write/read-only entry not already
    covered by a system root."""
    matchers: list[str] = [_subpath(p) for p in SYSTEM_READ_SUBPATHS]
    matchers += [_literal(p) for p in SYSTEM_READ_LITERALS]
    if cfg.claude_read_dir:
        matchers.append(_subpath(cfg.claude_read_dir))

    subpaths = [p for p in cfg.rw.subpaths if _needs_read_allow(p)] + [
        p for p in cfg.ro.subpaths if _needs_read_allow(p)
    ]
    literals = [p for p in cfg.rw.literals if _needs_read_allow(p)] + [
        p for p in cfg.ro.literals if _needs_read_allow(p)
    ]
    matchers += [_subpath(p) for p in subpaths] + [_literal(p) for p in literals]
    return matchers


def render_profile(cfg: PolicyConfig) -> str:
    """Render the full Seatbelt profile for ``cfg`` (§4, emission order per §12.5)."""
    sections: list[str] = []

    # 1. Header + allow-by-default base (§4.1).
    sections.append("(version 1)\n(allow default)")

    # 2. Writes: deny everything, then re-allow the explicit set (§4.2 / §5.1).
    sections.append(
        ";; Writes: deny everything, then re-allow a specific set\n"
        "(deny file-write*)\n" + _block("allow file-write*", _rw_matchers(cfg.rw))
    )

    # 3. Reads: deny by default, then re-allow system roots + the in-policy set
    # (v2 §4.3 / §5.5), then re-deny the /System/Volumes/Data firmlink alias.
    sections.append(
        ";; Reads: deny by default, then re-allow system roots + the in-$HOME set\n"
        "(deny file-read*)\n"
        + _block("allow file-read*", _read_matchers(cfg))
        + "\n;; Firmlink guard: deny the /System/Volumes/Data alias for $HOME files\n"
        + f'(deny file-read* (subpath "{sbpl_escape(FIRMLINK_DENY)}"))'
    )

    # 4. Metadata-only (lstat) on workdir & allowlist ancestors (§4.4 / §5.3).
    if cfg.ancestors:
        sections.append(
            ";; Metadata-only (lstat) on workdir & allowlist ancestors\n"
            + _block("allow file-read-metadata", [_literal(p) for p in cfg.ancestors])
        )

    # 5. Tamper-proofing: Claude must not rewrite its own security config (§4.5).
    tamper = [_subpath(p) for p in cfg.tamper_subpaths] + [_literal(p) for p in cfg.tamper_literals]
    if tamper:
        sections.append(
            ";; Tamper-proofing: Claude must not rewrite its own security config\n"
            + _block("deny file-write*", tamper)
        )

    # 6. Blocked dirs: opt-in hard deny, overrides every allow (§4.6).
    if cfg.blocked_dirs:
        sections.append(
            ";; Blocked dirs: hard deny (overrides allows)\n"
            + _block("deny file-read* file-write*", [_subpath(p) for p in cfg.blocked_dirs])
        )

    # 7. Process isolation — BOTH rules required (§4.7 / §13).
    sections.append(
        ";; Process isolation: block inspecting other processes\n"
        "(deny process-info* (target others))\n"
        "(deny mach-task-read mach-task-name (target others))"
    )

    return "\n\n".join(sections) + "\n"
