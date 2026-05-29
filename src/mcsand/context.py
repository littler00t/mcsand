"""Launch-context resolution — assemble a :class:`~mcsand.profile.PolicyConfig`.

This is the seam where the pure renderer meets the real filesystem (§2, §5). It
decides the workdir (a fresh ``mktemp -d`` when launched from ``$HOME`` so the
whole home tree is never the project root — §2), resolves the hook/``settings``
symlink targets (§4.5, §6.3), enumerates the ``$HOME``-internal ancestors for
the metadata allowance (§4.4), and composes the structured read-write / read-only
allowlists (§5.1 and §5.2).

Filesystem operations are injected (``mkdtemp``, ``resolve_link``) so the whole
assembly is unit-testable; the defaults use the real filesystem.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable

from .cleanup import CleanupRegistry
from .config import LaunchConfig
from .optins import OptIns
from .paths import add_ancestors, normalize, resolve1
from .profile import Allowlist, PolicyConfig

__all__ = ["FIXED_RO_SUFFIXES", "FIXED_RW_IN_HOME", "build_policy"]

# System scratch trees, written in canonical /private form (§5.1).
_RW_SYSTEM_SUBPATHS = ("/private/tmp", "/private/var/folders", "/private/var/tmp")
# Standard device files for normal process I/O and interactive terminals (§5.1).
_RW_DEV_LITERALS = (
    "/dev/null",
    "/dev/zero",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
)
_RW_DEV_REGEXES = ("^/dev/ttys", "^/dev/fd/")  # PTY slaves; fd devices (§5.1)

# In-$HOME read-write dirs beyond the workdir and Claude config dir (§5.1).
# (home-relative suffixes; the Claude config dir is handled separately.)
FIXED_RW_IN_HOME = (
    ".cache",
    "Library/Caches/claude-cli-nodejs",
    "Library/Keychains",
)
# In-$HOME read-only reference dirs (§5.2).
FIXED_RO_SUFFIXES = (
    ".config/git",
    ".config/ccstatusline",
    ".local/bin",
    ".local/share/uv",
    ".npm",
)


def _default_mkdtemp() -> str:
    return tempfile.mkdtemp(prefix="mcsand-work-")


def _default_which(name: str) -> str | None:
    return shutil.which(name)


def _resolve_binary_read_dir(
    binary: str,
    which: Callable[[str], str | None],
    resolve_link: Callable[[str], str],
) -> str | None:
    """Resolve the directory of the launched ``binary`` for the read-allow set (v2 §5.5).

    Covers installs outside the system roots (e.g. ``claude`` under a node version
    manager such as ``~/.nvm``, or a shell under ``/opt/homebrew``). ``binary`` may
    be a bare name (resolved on ``PATH``) or an absolute path. Returns ``None`` when
    it cannot be located; the launcher reports a missing binary separately.
    """
    found = which(binary)
    if not found:
        return None
    return normalize(os.path.dirname(resolve_link(found)))


def build_policy(
    cfg: LaunchConfig,
    opts: OptIns,
    *,
    registry: CleanupRegistry,
    binary: str = "claude",
    mkdtemp: Callable[[], str] = _default_mkdtemp,
    resolve_link: Callable[[str], str] = resolve1,
    which: Callable[[str], str | None] = _default_which,
) -> PolicyConfig:
    """Resolve ``cfg`` + ``opts`` into a fully-canonicalized :class:`PolicyConfig`.

    ``binary`` is the program that will run under the sandbox (default ``claude``);
    its resolved directory is read-allowed so it stays executable under
    deny-by-default reads. ``mcsand run``/``shell`` pass other binaries.
    """
    home = cfg.home

    # --- Workdir (§2): mktemp -d when launched from $HOME, else $PWD (no remap).
    if cfg.cwd == home:
        workdir = normalize(mkdtemp())
        registry.add_dir(workdir)
    else:
        workdir = normalize(cfg.cwd)

    # --- Hook dirs & settings.json (§4.5, §6.3): always cover the in-~/.claude
    # path; in symlink-install mode also cover the resolved real target.
    hooks_seen = f"{cfg.claude_dir}/hooks"
    hooks_resolved = normalize(resolve_link(hooks_seen))
    extra_hook_dirs = [hooks_resolved] if hooks_resolved != hooks_seen else []

    settings_seen = f"{cfg.claude_dir}/settings.json"
    settings_real = normalize(resolve_link(settings_seen))
    settings_extra = settings_real if settings_real != settings_seen else None

    # --- Read-write allowlist (§5.1), in emission order. The Docker socket needs
    # read+write (it is added to the read set below too — v2 §8.1).
    rw_subpaths: list[str] = [workdir, cfg.claude_dir]
    rw_subpaths += [f"{home}/{suffix}" for suffix in FIXED_RW_IN_HOME]
    rw_subpaths += _RW_SYSTEM_SUBPATHS
    rw_subpaths += cfg.additional_rw

    rw_literals: list[str] = [f"{home}/.claude.json", f"{home}/.claude.json.backup"]
    rw_literals += _RW_DEV_LITERALS
    if cfg.ssh_auth_sock:
        rw_literals.append(cfg.ssh_auth_sock)
    if opts.docker:
        rw_literals.append(opts.docker.socket)

    rw = Allowlist(
        subpaths=tuple(rw_subpaths),
        literals=tuple(rw_literals),
        regexes=_RW_DEV_REGEXES,
    )

    # --- Read-only allowlist (§5.2). Under deny-by-default reads the renderer
    # unions this with the read-write entries not already covered by a system
    # root to form the read-allow rule. ~/.docker is read-only (v2 §5.2) and the
    # Docker socket also needs an explicit read grant (v2 §8.1).
    ro_subpaths: list[str] = [f"{home}/{suffix}" for suffix in FIXED_RO_SUFFIXES]
    ro_subpaths += extra_hook_dirs
    ro_subpaths += cfg.additional_ro
    if opts.docker:
        ro_subpaths.append(opts.docker.docker_dir)

    ro_literals: list[str] = [f"{home}/.gitconfig"]
    if settings_extra:
        ro_literals.append(settings_extra)
    if opts.k8s:
        ro_literals.append(opts.k8s.kubeconfig_path)
    if opts.docker:
        ro_literals.append(opts.docker.socket)

    ro = Allowlist(subpaths=tuple(ro_subpaths), literals=tuple(ro_literals))

    # --- Resolve the launched binary's dir for the read-allow set (v2 §5.5).
    binary_read_dir = _resolve_binary_read_dir(binary, which, resolve_link)

    # --- Ancestor metadata (§4.4 / §6.5): the parent of $HOME (e.g. /Users) so
    # realpath walks can traverse it under deny-by-default reads (v2 §4.8), then
    # workdir + fixed in-$HOME allowlist + opt-ins + user mounts/hooks, deduped
    # in insertion order.
    ancestors: list[str] = []
    home_parent = os.path.dirname(home)
    if home_parent and home_parent != home:
        ancestors.append(home_parent)
    add_ancestors(workdir, home=home, into=ancestors)
    for path in (
        cfg.claude_dir,
        *(f"{home}/{s}" for s in FIXED_RW_IN_HOME),
        *(f"{home}/{s}" for s in FIXED_RO_SUFFIXES),
    ):
        add_ancestors(path, home=home, into=ancestors)
    if binary_read_dir:
        add_ancestors(binary_read_dir, home=home, into=ancestors)  # e.g. ~/.nvm install
    if opts.docker:
        add_ancestors(opts.docker.docker_dir, home=home, into=ancestors)
    if opts.k8s:
        add_ancestors(opts.k8s.kubeconfig_path, home=home, into=ancestors)  # defensive
    for path in (*cfg.additional_rw, *cfg.additional_ro, *extra_hook_dirs):
        add_ancestors(path, home=home, into=ancestors)

    # --- Tamper-proofing (§4.5): both the seen path and the symlink target.
    tamper_subpaths: list[str] = [hooks_seen, *extra_hook_dirs]
    tamper_literals: list[str] = [settings_seen]
    if settings_extra:
        tamper_literals.append(settings_extra)

    return PolicyConfig(
        home=home,
        workdir=workdir,
        rw=rw,
        ro=ro,
        binary_read_dir=binary_read_dir,
        ancestors=tuple(ancestors),
        tamper_subpaths=tuple(tamper_subpaths),
        tamper_literals=tuple(tamper_literals),
        blocked_dirs=cfg.blocked_dirs,
    )
