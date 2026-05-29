"""Sandbox invocation (design doc §2).

Builds the ``sandbox-exec -f <profile> /usr/bin/env -i <env…> <claude> <args>``
command line and runs Claude as a **child** process — deliberately not ``exec``
— so control returns and the temp-artifact cleanup still fires (§2). The child's
exit code is propagated.

:func:`build_argv` is a pure function (argv construction only) so the command
shape is unit-testable; the side-effecting :func:`launch` is a thin wrapper with
an injectable runner.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Mapping

__all__ = [
    "SANDBOX_EXEC",
    "build_argv",
    "find_claude",
    "find_executable",
    "launch",
    "require_sandbox_exec",
]

SANDBOX_EXEC = "sandbox-exec"


def require_sandbox_exec() -> str | None:
    """Return the path to ``sandbox-exec`` if available, else ``None`` (§2 preflight)."""
    return shutil.which(SANDBOX_EXEC)


def find_executable(name: str) -> str | None:
    """Resolve a program to an absolute path: a bare name via ``PATH``, or an
    explicit ``/``-containing path verified with :func:`shutil.which`."""
    return shutil.which(name)


def find_claude() -> str | None:
    """Discover the ``claude`` binary via ``PATH`` (§2)."""
    return find_executable("claude")


def build_argv(
    profile_path: str,
    env: Mapping[str, str],
    claude_bin: str,
    claude_args: list[str],
) -> list[str]:
    """Construct the full ``sandbox-exec`` argv (pure).

    Uses ``/usr/bin/env -i`` to clear the environment and re-add only the
    whitelisted variables (§7) — the Seatbelt analogue of ``--clearenv``.
    """
    env_kv = [f"{key}={value}" for key, value in env.items()]
    return [
        SANDBOX_EXEC,
        "-f",
        profile_path,
        "/usr/bin/env",
        "-i",
        *env_kv,
        claude_bin,
        *claude_args,
    ]


def launch(
    profile_path: str,
    env: Mapping[str, str],
    claude_bin: str,
    claude_args: list[str],
    *,
    workdir: str,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> int:
    """Run Claude under the sandbox as a child process; return its exit code (§2).

    The child shares this process's process group, so a terminal SIGINT (Ctrl-C)
    is delivered to Claude directly; our own cleanup runs after the child exits.
    """
    argv = build_argv(profile_path, env, claude_bin, claude_args)
    completed = run(argv, cwd=workdir, check=False)
    return completed.returncode
