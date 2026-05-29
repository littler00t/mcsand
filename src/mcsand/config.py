"""Launch configuration parsed from the environment (design doc §9).

Pure: :func:`parse_config` takes an injected environment ``Mapping`` (never
reads ``os.environ`` itself), so the §9 knobs can be exercised deterministically
in tests. Every user-supplied directory is routed through
:func:`mcsand.paths.abspath` then :func:`mcsand.paths.normalize` — this is the
fix for the demonstrated ``./secrets`` canonicalization bypass (§10): a
non-canonical component would make a later deny rule silently no-op.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .paths import abspath, normalize

__all__ = ["LaunchConfig", "parse_config", "parse_dir_list", "parse_name_list"]

# Values treated as "false" for CLAUDE_SANDBOX_K8S_CLUSTER_WIDE; anything else set
# (including the empty string) counts as truthy ⇒ cluster-wide scope (v2 §9).
_FALSEY = frozenset({"", "0", "false", "no", "off"})


def _parse_truthy(value: str) -> bool:
    """Interpret an env-var string as a boolean (v2 §9 scope/skip semantics)."""
    return value.strip().lower() not in _FALSEY


@dataclass(frozen=True)
class LaunchConfig:
    """Fully-parsed, canonicalized launch inputs (still pre-resolution).

    All directory tuples are already ``abspath``+``normalize``'d. Filesystem
    resolution that needs the real FS (workdir decision, symlink following,
    ancestor enumeration) happens later in :mod:`mcsand.context`.
    """

    home: str
    cwd: str
    claude_dir: str
    additional_rw: tuple[str, ...]
    additional_ro: tuple[str, ...]
    blocked_dirs: tuple[str, ...]
    k8s_sa: str | None
    k8s_impersonate: str | None
    k8s_role: str | None
    k8s_namespace: str | None
    k8s_cluster_wide: bool | None
    k8s_token_lifetime: str | None
    sensitive_vars: tuple[str, ...]  # user-added names, additive to the built-in default
    ssh_auth_sock: str | None
    tmpdir: str | None


def parse_name_list(value: str | None) -> tuple[str, ...]:
    """Parse a colon-separated list of bare names (e.g. env-var names).

    Unlike :func:`parse_dir_list` these are not paths, so they are only trimmed —
    never ``abspath``/``normalize``'d. Empty entries are dropped.
    """
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(":") if item.strip())


def parse_dir_list(value: str | None, *, cwd: str) -> tuple[str, ...]:
    """Parse a colon-separated dir list (``ALLOWED_DIRS`` / ``ALLOWED_RO_DIRS`` /
    ``BLOCKED_DIRS``).

    Empty entries are dropped; each remaining entry is canonicalized with
    :func:`~mcsand.paths.abspath` (``$PWD``-relative entries allowed) then mapped
    under ``/private`` with :func:`~mcsand.paths.normalize`.
    """
    if not value:
        return ()
    out: list[str] = []
    for raw in value.split(":"):
        if not raw:
            continue
        resolved = normalize(abspath(raw, cwd=cwd))
        if resolved:
            out.append(resolved)
    return tuple(out)


def parse_config(env: Mapping[str, str], *, cwd: str) -> LaunchConfig:
    """Build a :class:`LaunchConfig` from an environment mapping and ``cwd``."""
    home = env["HOME"].rstrip("/")
    claude_dir_raw = env.get("CLAUDE_CONFIG_DIR")
    if claude_dir_raw:
        claude_dir = normalize(abspath(claude_dir_raw, cwd=cwd))
    else:
        claude_dir = f"{home}/.claude"

    ssh_sock = env.get("SSH_AUTH_SOCK")

    cluster_wide_raw = env.get("CLAUDE_SANDBOX_K8S_CLUSTER_WIDE")
    cluster_wide = _parse_truthy(cluster_wide_raw) if cluster_wide_raw is not None else None

    return LaunchConfig(
        home=home,
        cwd=cwd,
        claude_dir=claude_dir,
        additional_rw=parse_dir_list(env.get("CLAUDE_SANDBOX_ALLOWED_DIRS"), cwd=cwd),
        additional_ro=parse_dir_list(env.get("CLAUDE_SANDBOX_ALLOWED_RO_DIRS"), cwd=cwd),
        blocked_dirs=parse_dir_list(env.get("CLAUDE_SANDBOX_BLOCKED_DIRS"), cwd=cwd),
        k8s_sa=env.get("CLAUDE_SANDBOX_K8S_SA"),
        k8s_impersonate=env.get("CLAUDE_SANDBOX_K8S_IMPERSONATE"),
        k8s_role=env.get("CLAUDE_SANDBOX_K8S_ROLE"),
        k8s_namespace=env.get("CLAUDE_SANDBOX_K8S_NAMESPACE"),
        k8s_cluster_wide=cluster_wide,
        k8s_token_lifetime=env.get("CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME"),
        sensitive_vars=parse_name_list(env.get("CLAUDE_SANDBOX_SENSITIVE_VARS")),
        ssh_auth_sock=normalize(ssh_sock) if ssh_sock else None,
        tmpdir=env.get("TMPDIR"),
    )
