"""Opt-in resources prompted at startup (design doc §8).

Two optional capabilities, each gated behind a ``[y/N]`` prompt and each
**degrading gracefully** — any failure returns ``None`` and the launch proceeds
without the resource rather than aborting (§8.2).

All side effects (prompts, ``kubectl`` invocations, temp-file writes) are
injected as callables ("seams"), so the entire decision tree — including every
failure-degrades-to-``None`` path — is unit-testable on Linux with fakes.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from .config import LaunchConfig
from .paths import normalize, resolve1

__all__ = [
    "DockerPaths",
    "K8sResult",
    "OptIns",
    "maybe_docker",
    "maybe_k8s",
]

DOCKER_SOCKET = "/var/run/docker.sock"

# Built-in Kubernetes ClusterRoles offered at the role prompt (v2 §8.2).
BUILTIN_ROLES = ("view", "edit", "admin", "cluster-admin")

# Seam type aliases.
YesNo = Callable[[str], bool]
Ask = Callable[[str, str], str]
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
WriteKubeconfig = Callable[[str], str]
Exists = Callable[[str], bool]
Emit = Callable[[str], None]


@dataclass(frozen=True)
class DockerPaths:
    """Resolved Docker paths to expose when the user opts in (§8.1).

    The socket needs read+write; ``~/.docker`` is read-only (v2 §5.2). Both go
    into the read-allow set, but only the socket into the write-allow set —
    categorization happens in :mod:`mcsand.context`.
    """

    socket: str  # normalized + single-level-symlink-resolved
    docker_dir: str  # ~/.docker (read-only)


@dataclass(frozen=True)
class K8sResult:
    """A minted, self-contained temp kubeconfig (§8.2). Read-only to the sandbox."""

    kubeconfig_path: str


@dataclass(frozen=True)
class OptIns:
    """Resolved opt-in results, passed to :func:`mcsand.context.build_policy`."""

    docker: DockerPaths | None = None
    k8s: K8sResult | None = None


def maybe_docker(cfg: LaunchConfig, *, exists: Exists, prompt: YesNo) -> DockerPaths | None:
    """Offer the Docker socket if it exists (§8.1).

    Accepting Docker is effectively host-root (§10) — the prompt makes that the
    user's explicit choice. Returns ``None`` if the socket is absent or declined.
    """
    if not exists(DOCKER_SOCKET):
        return None
    if not prompt(f"Expose the Docker socket ({DOCKER_SOCKET})? This grants host-root access."):
        return None
    return DockerPaths(
        socket=normalize(resolve1(DOCKER_SOCKET)),
        docker_dir=f"{cfg.home}/.docker",
    )


def _sanitize_username(name: str) -> str:
    """Reduce a username to ``[a-z0-9-]`` for a Kubernetes resource name (§8.2)."""
    cleaned = re.sub(r"[^a-z0-9-]", "-", name.lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned or "user"


def _kubectl(args: list[str], impersonate: str | None) -> list[str]:
    cmd = ["kubectl", *args]
    if impersonate:
        cmd += ["--as", impersonate]
    return cmd


def _run_out(run: Runner, cmd: list[str]) -> str | None:
    """Run a command, returning stripped stdout on success else ``None``."""
    try:
        result = run(cmd)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip()


def _render_kubeconfig(server: str, ca_data: str | None, token: str) -> str:
    """Render a minimal, self-contained kubeconfig (cluster + CA + token only)."""
    cluster_lines = [
        "- name: sandbox",
        "  cluster:",
        f"    server: {server}",
    ]
    if ca_data:
        cluster_lines.append(f"    certificate-authority-data: {ca_data}")
    return "\n".join(
        [
            "apiVersion: v1",
            "kind: Config",
            "clusters:",
            *cluster_lines,
            "contexts:",
            "- name: sandbox",
            "  context:",
            "    cluster: sandbox",
            "    user: sandbox",
            "current-context: sandbox",
            "users:",
            "- name: sandbox",
            "  user:",
            f"    token: {token}",
            "",
        ]
    )


def _current_namespace(run: Runner) -> str:
    """The current context's namespace, defaulting to ``default`` (v2 §8.2)."""
    return (
        _run_out(
            run,
            [
                "kubectl",
                "config",
                "view",
                "--minify",
                "-o",
                "jsonpath={.contexts[0].context.namespace}",
            ],
        )
        or "default"
    )


def _explicit_sa(cfg: LaunchConfig, run: Runner) -> tuple[str, str]:
    """Resolve an explicit ``CLAUDE_SANDBOX_K8S_SA`` to ``(namespace, name)`` (v2 §8.2).

    The user owns the SA's RBAC, so no provisioning happens — just a token mint.
    """
    assert cfg.k8s_sa is not None
    if "/" in cfg.k8s_sa:
        namespace, name = cfg.k8s_sa.split("/", 1)
        return namespace, name
    return _current_namespace(run), cfg.k8s_sa


def _auto_provision(
    cfg: LaunchConfig,
    env_user: str,
    *,
    prompt: YesNo,
    ask: Ask,
    run: Runner,
    emit: Emit,
    exports: list[tuple[str, str]],
) -> tuple[str, str] | None:
    """Provision a per-user ``claude-code-<user>`` SA with a least-privilege binding (v2 §8.2).

    Scope (namespace ``RoleBinding`` by default, opt-in cluster-wide
    ``ClusterRoleBinding``) and role (default ``view``) are prompted unless their
    env vars are set; a set ``CLAUDE_SANDBOX_K8S_NAMESPACE`` also implies
    namespace scope. Bindings are recreated delete-then-create because
    ``roleRef`` is immutable. Choices not supplied via env are appended to
    ``exports`` for the caller to echo. Returns ``(namespace, name)``.
    """
    impersonate = cfg.k8s_impersonate
    whoami = _run_out(
        run,
        _kubectl(["auth", "whoami", "-o", "jsonpath={.status.userInfo.username}"], impersonate),
    )
    name = f"claude-code-{_sanitize_username(whoami or env_user or 'user')}"

    # --- Scope (asked first); least-privilege default is a namespace RoleBinding.
    if cfg.k8s_namespace is not None:
        cluster_wide, namespace = False, cfg.k8s_namespace
        emit(f"→ namespace-scoped in {namespace} (from CLAUDE_SANDBOX_K8S_NAMESPACE)")
    elif cfg.k8s_cluster_wide is not None:
        cluster_wide = cfg.k8s_cluster_wide
        emit(
            f"→ {'cluster-wide' if cluster_wide else 'namespace-scoped'} "
            "(from CLAUDE_SANDBOX_K8S_CLUSTER_WIDE)"
        )
        namespace = _ns_for_scope(cluster_wide, cfg, ask, run, exports)
    else:
        cluster_wide = prompt(
            "Bind cluster-wide (ClusterRoleBinding)? Default is a single-namespace RoleBinding."
        )
        exports.append(("CLAUDE_SANDBOX_K8S_CLUSTER_WIDE", "1" if cluster_wide else "0"))
        namespace = _ns_for_scope(cluster_wide, cfg, ask, run, exports)

    # --- ClusterRole to bind; default view (read-only).
    if cfg.k8s_role is not None:
        role = cfg.k8s_role
        emit(f"→ role {role} (from CLAUDE_SANDBOX_K8S_ROLE)")
    else:
        role = ask(f"ClusterRole to bind ({'/'.join(BUILTIN_ROLES)})", "view") or "view"
        exports.append(("CLAUDE_SANDBOX_K8S_ROLE", role))

    _run_out(run, _kubectl(["create", "serviceaccount", name, "-n", namespace], impersonate))

    # --- Binding: delete-then-create (roleRef is immutable, so a role change on a
    # later launch could not be applied in place — v2 §8.2).
    sa_ref = f"--serviceaccount={namespace}:{name}"
    if cluster_wide:
        _run_out(
            run,
            _kubectl(["delete", "clusterrolebinding", name, "--ignore-not-found"], impersonate),
        )
        _run_out(
            run,
            _kubectl(
                ["create", "clusterrolebinding", name, f"--clusterrole={role}", sa_ref],
                impersonate,
            ),
        )
    else:
        _run_out(
            run,
            _kubectl(
                ["delete", "rolebinding", name, "-n", namespace, "--ignore-not-found"],
                impersonate,
            ),
        )
        _run_out(
            run,
            _kubectl(
                ["create", "rolebinding", name, "-n", namespace, f"--clusterrole={role}", sa_ref],
                impersonate,
            ),
        )
    return namespace, name


def _ns_for_scope(
    cluster_wide: bool,
    cfg: LaunchConfig,
    ask: Ask,
    run: Runner,
    exports: list[tuple[str, str]],
) -> str:
    """Pick the namespace: ``kube-system`` for cluster-wide, else the env value or
    a prompt defaulting to the current context's namespace (v2 §8.2)."""
    if cluster_wide:
        return "kube-system"
    if cfg.k8s_namespace is not None:
        return cfg.k8s_namespace
    namespace = ask("Namespace for the RoleBinding", _current_namespace(run)) or "default"
    exports.append(("CLAUDE_SANDBOX_K8S_NAMESPACE", namespace))
    return namespace


def maybe_k8s(
    cfg: LaunchConfig,
    env: dict[str, str] | None = None,
    *,
    kubectl_path: str | None,
    prompt: YesNo,
    ask: Ask,
    run: Runner,
    write_kubeconfig: WriteKubeconfig,
    emit: Emit = lambda _msg: None,
) -> K8sResult | None:
    """Mint a short-lived token-only kubeconfig (v2 §8.2). Degrades to ``None``.

    Fires only when ``KUBECONFIG`` is set and ``kubectl`` is on ``PATH``. Runs
    entirely **outside** the sandbox so the user's auth helpers work normally.
    A set ``CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME`` counts as opting in (skips the
    ``[y/N]`` gate). On success, ``export`` lines for the choices **not** supplied
    via env are echoed through ``emit`` so the user can persist them. Any failure
    (no token, no server URL, subprocess error) returns ``None`` and the launch
    proceeds without Kubernetes.
    """
    env = env or {}
    if not env.get("KUBECONFIG") or not kubectl_path:
        return None

    lifetime_from_env = cfg.k8s_token_lifetime is not None
    if not lifetime_from_env and not prompt(
        "Mint a short-lived Kubernetes session token for the sandbox?"
    ):
        return None

    lifetime = (cfg.k8s_token_lifetime or ask("Token lifetime", "8h") or "8h").strip() or "8h"
    impersonate = cfg.k8s_impersonate

    # Settings decided this run that did NOT come from env, echoed on success.
    exports: list[tuple[str, str]] = []
    if not lifetime_from_env:
        exports.append(("CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME", lifetime))

    if cfg.k8s_sa:
        namespace, name = _explicit_sa(cfg, run)
    else:
        sa = _auto_provision(
            cfg,
            env.get("USER", "user"),
            prompt=prompt,
            ask=ask,
            run=run,
            emit=emit,
            exports=exports,
        )
        if sa is None:
            return None
        namespace, name = sa

    token = _run_out(
        run,
        _kubectl(
            ["create", "token", name, "-n", namespace, "--duration", lifetime],
            impersonate,
        ),
    )
    if not token:
        return None

    server = _run_out(
        run,
        [
            "kubectl",
            "config",
            "view",
            "--minify",
            "--flatten",
            "-o",
            "jsonpath={.clusters[0].cluster.server}",
        ],
    )
    if not server:
        return None
    ca_data = _run_out(
        run,
        [
            "kubectl",
            "config",
            "view",
            "--minify",
            "--flatten",
            "-o",
            "jsonpath={.clusters[0].cluster.certificate-authority-data}",
        ],
    )

    content = _render_kubeconfig(server, ca_data or None, token)
    try:
        path = write_kubeconfig(content)
    except OSError:
        return None

    # Persist-this-run hint: echo only the settings not already from env (v2 §8.2).
    if exports:
        emit("# mcsand: persist these to skip the prompts next launch:")
        for var, value in exports:
            emit(f"export {var}={value}")

    return K8sResult(kubeconfig_path=normalize(path))
