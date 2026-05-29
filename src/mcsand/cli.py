"""Command-line interface and orchestration (design doc §2, §12).

Env vars (§9) are the canonical configuration; the flags here are convenience
sugar that override them. Three surfaces:

    mcsand [opts] [-- CLAUDE_ARGS…]   launch claude under the sandbox (default)
    mcsand print-profile [opts]        render the SBPL profile to stdout, no launch
    mcsand doctor                      preflight checks, no launch
    mcsand install-hooks [--dry-run]   register the security hooks in settings.json

``print-profile`` and ``doctor`` run the full pure pipeline and therefore work on
any platform (including Linux CI) — they are the primary trust/debugging tools.
Actually launching requires macOS; on other platforms ``launch`` refuses unless
``--dry-run`` is given.
"""

from __future__ import annotations

import argparse
import atexit
import dataclasses
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Sequence

from .cleanup import CleanupRegistry
from .config import LaunchConfig, parse_config
from .context import build_policy
from .environment import build_clean_env, sensitive_vars_present
from .launcher import build_argv, find_claude, launch, require_sandbox_exec
from .optins import Ask, OptIns, YesNo, maybe_docker, maybe_k8s
from .paths import abspath, normalize
from .profile import render_profile

__all__ = ["main"]


def _id_un() -> str:
    """Best-effort ``id -un`` for the USER fallback (§7)."""
    try:
        result = subprocess.run(["id", "-un"], capture_output=True, text=True, check=False)
        name = result.stdout.strip()
        if name:
            return name
    except (OSError, subprocess.SubprocessError):
        pass
    return os.environ.get("USER") or "user"


def _build_option_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        add_help=True,
        description="Run Claude Code under the macOS Seatbelt sandbox.",
    )
    parser.add_argument(
        "--rw",
        action="append",
        default=[],
        metavar="DIR",
        help="Add a read-write dir (repeatable; sugar for CLAUDE_SANDBOX_ALLOWED_DIRS).",
    )
    parser.add_argument(
        "--ro",
        action="append",
        default=[],
        metavar="DIR",
        help="Add a read-only dir (repeatable; sugar for CLAUDE_SANDBOX_ALLOWED_RO_DIRS).",
    )
    parser.add_argument(
        "--block",
        action="append",
        default=[],
        metavar="DIR",
        help="Hard-deny a dir, read+write (repeatable; sugar for BLOCKED_DIRS).",
    )
    parser.add_argument(
        "--workdir", metavar="DIR", help="Override the working directory (default: $PWD)."
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Auto-accept all opt-in prompts (Docker, K8s, sensitive vars).",
    )
    parser.add_argument("--no-docker", action="store_true", help="Never offer the Docker socket.")
    parser.add_argument("--no-k8s", action="store_true", help="Never mint a Kubernetes token.")
    parser.add_argument(
        "--k8s-role",
        metavar="ROLE",
        help="ClusterRole to bind the auto-provisioned SA (sugar for CLAUDE_SANDBOX_K8S_ROLE).",
    )
    parser.add_argument(
        "--k8s-namespace",
        metavar="NS",
        help="Namespace for the RoleBinding (sugar for CLAUDE_SANDBOX_K8S_NAMESPACE).",
    )
    parser.add_argument(
        "--cluster-wide",
        action="store_true",
        default=None,
        help="Bind the SA cluster-wide (sugar for CLAUDE_SANDBOX_K8S_CLUSTER_WIDE).",
    )
    parser.add_argument(
        "--k8s-lifetime",
        metavar="DUR",
        help="K8s token lifetime, e.g. 8h (sugar for CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and print the sandbox-exec command, but do not launch.",
    )
    return parser


def _split_args(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split into (our options, claude passthrough args) on the first ``--``.

    Without an explicit ``--``, unknown leading args are treated as claude args.
    """
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def _merge_flag_overrides(cfg: LaunchConfig, ns: argparse.Namespace, *, cwd: str) -> LaunchConfig:
    """Layer CLI flag values on top of the env-derived config (§9: flags win)."""

    def canon(entries: list[str]) -> tuple[str, ...]:
        return tuple(normalize(abspath(e, cwd=cwd)) for e in entries)

    new_cwd = normalize(abspath(ns.workdir, cwd=cwd)) if ns.workdir else cfg.cwd
    return dataclasses.replace(
        cfg,
        cwd=new_cwd,
        additional_rw=cfg.additional_rw + canon(ns.rw),
        additional_ro=cfg.additional_ro + canon(ns.ro),
        blocked_dirs=cfg.blocked_dirs + canon(ns.block),
        k8s_role=ns.k8s_role if ns.k8s_role is not None else cfg.k8s_role,
        k8s_namespace=ns.k8s_namespace if ns.k8s_namespace is not None else cfg.k8s_namespace,
        k8s_cluster_wide=True if ns.cluster_wide else cfg.k8s_cluster_wide,
        k8s_token_lifetime=(
            ns.k8s_lifetime if ns.k8s_lifetime is not None else cfg.k8s_token_lifetime
        ),
    )


def _make_prompts(*, assume_yes: bool, interactive: bool) -> tuple[YesNo, Ask]:
    """Return (yes_no, ask) prompt callables honoring --yes / non-interactive."""

    def yes_no(question: str) -> bool:
        if assume_yes:
            return True
        if not interactive:
            return False
        try:
            answer = input(f"{question} [y/N] ").strip().lower()
        except EOFError:
            return False
        return answer in ("y", "yes")

    def ask(question: str, default: str) -> str:
        if assume_yes or not interactive:
            return default
        try:
            answer = input(f"{question} [{default}] ").strip()
        except EOFError:
            return default
        return answer or default

    return yes_no, ask


def _resolve_optins(
    cfg: LaunchConfig,
    env: dict[str, str],
    ns: argparse.Namespace,
    registry: CleanupRegistry,
    *,
    yes_no: YesNo,
    ask: Ask,
    allow_k8s: bool = True,
) -> OptIns:
    """Resolve Docker + Kubernetes opt-ins (both degrade gracefully).

    ``allow_k8s`` is ``False`` for ``print-profile``, which must stay
    side-effect-free (minting a token runs ``kubectl`` against a live cluster).
    """
    import shutil

    docker = None
    if not ns.no_docker:
        docker = maybe_docker(cfg, exists=os.path.exists, prompt=yes_no)

    k8s = None
    if allow_k8s and not ns.no_k8s:

        def run_kubectl(cmd: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(cmd, capture_output=True, text=True, check=False)

        def write_kubeconfig(content: str) -> str:
            fd, path = tempfile.mkstemp(prefix="mcsand-kubeconfig-", suffix=".yaml")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(content)
            registry.add_file(path)
            return path

        def emit(msg: str) -> None:
            sys.stderr.write(msg + "\n")

        k8s = maybe_k8s(
            cfg,
            env,
            kubectl_path=shutil.which("kubectl"),
            prompt=yes_no,
            ask=ask,
            run=run_kubectl,
            write_kubeconfig=write_kubeconfig,
            emit=emit,
        )

    return OptIns(docker=docker, k8s=k8s)


def _write_profile(text: str, registry: CleanupRegistry) -> str:
    """Write the SBPL profile to a ``chmod 600`` temp file, registered for cleanup (§2)."""
    fd, path = tempfile.mkstemp(prefix="mcsand-profile-", suffix=".sb")
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    registry.add_file(path)
    return path


def _install_cleanup(registry: CleanupRegistry) -> None:
    """Wire the triple safety net: atexit + SIGINT/SIGTERM (§7)."""
    atexit.register(registry.run)

    def handler(signum: int, frame: object) -> None:
        registry.run()
        # Re-raise the default disposition so the exit status reflects the signal.
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def _resolve_for_render(
    argv: list[str], *, prog: str
) -> tuple[argparse.Namespace, LaunchConfig, dict[str, str], str]:
    """Shared resolution for launch/print-profile (parse opts + build config)."""
    parser = _build_option_parser(prog)
    ns = parser.parse_args(argv)
    env = dict(os.environ)
    cwd = os.getcwd()
    cfg = _merge_flag_overrides(parse_config(env, cwd=cwd), ns, cwd=cwd)
    return ns, cfg, env, cwd


def cmd_print_profile(argv: list[str]) -> int:
    ns, cfg, env, _ = _resolve_for_render(argv, prog="mcsand print-profile")
    registry = CleanupRegistry()  # not installed: print-profile creates no temps to keep
    yes_no, ask = _make_prompts(assume_yes=ns.yes, interactive=False)
    opts = _resolve_optins(cfg, env, ns, registry, yes_no=yes_no, ask=ask, allow_k8s=False)
    policy = build_policy(cfg, opts, registry=registry)
    sys.stdout.write(render_profile(policy))
    registry.run()
    return 0


def cmd_doctor(argv: list[str]) -> int:
    _ns, cfg, env, _ = _resolve_for_render(argv, prog="mcsand doctor")
    import shutil

    out = sys.stdout
    out.write("mcsand doctor\n")
    out.write(f"  platform           : {sys.platform}")
    out.write("" if sys.platform == "darwin" else "  (sandbox launch is macOS-only)")
    out.write("\n")
    sb = require_sandbox_exec()
    out.write(f"  sandbox-exec       : {sb or 'NOT FOUND (required to launch)'}\n")
    out.write(f"  claude             : {find_claude() or 'NOT FOUND (required to launch)'}\n")
    out.write(f"  CLAUDE config dir  : {cfg.claude_dir}\n")
    out.write(f"  working directory  : {cfg.cwd}\n")
    out.write(f"  ssh-agent socket   : {cfg.ssh_auth_sock or '(none)'}\n")
    docker_state = "present" if os.path.exists("/var/run/docker.sock") else "absent"
    out.write(f"  docker socket      : {docker_state}\n")
    out.write(f"  kubectl            : {shutil.which('kubectl') or '(none)'}\n")
    out.write(f"  KUBECONFIG set     : {'yes' if env.get('KUBECONFIG') else 'no'}\n")
    if cfg.k8s_sa:
        out.write(f"  k8s SA             : {cfg.k8s_sa}\n")
    if cfg.k8s_role:
        out.write(f"  k8s role           : {cfg.k8s_role}\n")
    if cfg.k8s_namespace:
        out.write(f"  k8s namespace      : {cfg.k8s_namespace}\n")
    if cfg.k8s_cluster_wide is not None:
        out.write(f"  k8s cluster-wide   : {'yes' if cfg.k8s_cluster_wide else 'no'}\n")
    if cfg.k8s_token_lifetime:
        out.write(f"  k8s token lifetime : {cfg.k8s_token_lifetime}\n")
    if cfg.additional_rw:
        out.write(f"  extra RW dirs      : {', '.join(cfg.additional_rw)}\n")
    if cfg.additional_ro:
        out.write(f"  extra RO dirs      : {', '.join(cfg.additional_ro)}\n")
    if cfg.blocked_dirs:
        out.write(f"  blocked dirs       : {', '.join(cfg.blocked_dirs)}\n")
    present = sensitive_vars_present(env)
    out.write(f"  sensitive vars set : {', '.join(present) if present else '(none)'}\n")
    out.write(f"  security hooks     : {_hooks_status(cfg.claude_dir)}\n")
    return 0


def _hooks_status(claude_dir: str) -> str:
    """Best-effort report of whether the mcsand security hooks are registered."""
    settings = os.path.join(claude_dir, "settings.json")
    try:
        import json

        with open(settings, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return "not installed (run `mcsand install-hooks`)"
    hooks = data.get("hooks", {})
    text = json.dumps(hooks)
    return "installed" if "mcsand.hooks" in text else "not installed (run `mcsand install-hooks`)"


def cmd_launch(argv: list[str]) -> int:
    opts_args, claude_args = _split_args(argv)
    ns, cfg, env, _ = _resolve_for_render(opts_args, prog="mcsand")

    if sys.platform != "darwin" and not ns.dry_run:
        sys.stderr.write(
            "mcsand: the Seatbelt sandbox is macOS-only. "
            "Use `print-profile`/`doctor` here, or `--dry-run` to preview the command.\n"
        )
        return 2

    sandbox_exec = require_sandbox_exec()
    claude_bin = find_claude()
    if not ns.dry_run:
        if not sandbox_exec:
            sys.stderr.write("mcsand: sandbox-exec not found on PATH (built into macOS).\n")
            return 2
        if not claude_bin:
            sys.stderr.write("mcsand: claude binary not found on PATH.\n")
            return 2

    registry = CleanupRegistry()
    _install_cleanup(registry)

    interactive = sys.stdin.isatty()
    yes_no, ask = _make_prompts(assume_yes=ns.yes, interactive=interactive)

    opts = _resolve_optins(cfg, env, ns, registry, yes_no=yes_no, ask=ask)
    policy = build_policy(cfg, opts, registry=registry)

    approved: set[str] = set()
    for name in sensitive_vars_present(env):
        if yes_no(f"Forward sensitive variable {name} into the sandbox?"):
            approved.add(name)

    clean_env = build_clean_env(
        env,
        approved_sensitive=approved,
        kubeconfig=opts.k8s.kubeconfig_path if opts.k8s else None,
        user_fallback=_id_un(),
    )

    profile_text = render_profile(policy)
    profile_path = _write_profile(profile_text, registry)

    if ns.dry_run:
        argv_preview = build_argv(profile_path, clean_env, claude_bin or "claude", claude_args)
        sys.stdout.write("# mcsand --dry-run: would execute\n")
        sys.stdout.write(" ".join(argv_preview) + "\n")
        registry.run()
        return 0

    try:
        return launch(
            profile_path,
            clean_env,
            claude_bin or "claude",
            claude_args,
            workdir=policy.workdir,
        )
    finally:
        registry.run()


def cmd_install_hooks(argv: list[str]) -> int:
    """Install/merge the security-hooks registration into Claude's settings.json."""
    from .hooks.install import install_hooks

    parser = argparse.ArgumentParser(prog="mcsand install-hooks")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the merged settings.json instead of writing it.",
    )
    ns = parser.parse_args(argv)
    env = dict(os.environ)
    cfg = parse_config(env, cwd=os.getcwd())
    return install_hooks(cfg.claude_dir, dry_run=ns.dry_run, out=sys.stdout)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "doctor":
        return cmd_doctor(args[1:])
    if args and args[0] == "print-profile":
        return cmd_print_profile(args[1:])
    if args and args[0] == "install-hooks":
        return cmd_install_hooks(args[1:])
    return cmd_launch(args)
