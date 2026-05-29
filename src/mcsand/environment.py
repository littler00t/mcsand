"""Clean-environment construction (design doc §7).

The sandbox launches via ``env -i`` (clear everything) and re-adds only an
explicit whitelist — the Seatbelt analogue of bubblewrap's ``--clearenv``.
:func:`build_clean_env` is pure: it takes the outer environment as a mapping and
returns the final dict, so the whitelist behaviour is fully unit-testable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

__all__ = [
    "ALWAYS_DEFAULTS",
    "CONDITIONAL_VARS",
    "SENSITIVE_VARS",
    "build_clean_env",
    "sensitive_var_names",
    "sensitive_vars_present",
]

# Variables withheld from the sandbox unless the user confirms at startup (§7).
# This built-in default is always withheld; users add more (additively) via
# CLAUDE_SANDBOX_SENSITIVE_VARS / --sensitive.
SENSITIVE_VARS: tuple[str, ...] = ("ANSIBLE_VAULT_PASSWORD",)

# Always-present variables and their fallbacks when unset in the outer env (§7).
ALWAYS_DEFAULTS: dict[str, str] = {
    "PATH": "/usr/bin:/bin",
    "TERM": "xterm-256color",
    "SHELL": "/bin/zsh",
    "LANG": "en_US.UTF-8",
}

# Passed through only when present in the outer env (§7).
CONDITIONAL_VARS: tuple[str, ...] = (
    "TMPDIR",
    "SSH_AUTH_SOCK",
    "COLORTERM",
    "NO_COLOR",
    "GPG_TTY",
    "EDITOR",
    "VISUAL",
    "PAGER",
)


def sensitive_var_names(extra: Iterable[str] = ()) -> tuple[str, ...]:
    """The effective sensitive-var list: the built-in default plus ``extra`` (§7).

    Additive by design — the built-in :data:`SENSITIVE_VARS` are always withheld;
    user-configured names (``CLAUDE_SANDBOX_SENSITIVE_VARS`` / ``--sensitive``) only
    extend the set. Order-preserving, deduplicated.
    """
    out: list[str] = list(SENSITIVE_VARS)
    for name in extra:
        if name and name not in out:
            out.append(name)
    return tuple(out)


def sensitive_vars_present(outer: Mapping[str, str], extra: Iterable[str] = ()) -> list[str]:
    """Return the configured sensitive variable names that are set in ``outer`` (§7).

    ``extra`` are user-added names, merged with the built-in default. Drives the
    per-name ``[y/N]`` withholding prompt; the prompt itself lives in the CLI so
    this stays pure.
    """
    return [name for name in sensitive_var_names(extra) if name in outer]


def build_clean_env(
    outer: Mapping[str, str],
    *,
    approved_sensitive: set[str],
    kubeconfig: str | None,
    user_fallback: str,
) -> dict[str, str]:
    """Build the whitelisted environment dict passed to ``env -i`` (§7).

    ``approved_sensitive`` is the subset of :data:`SENSITIVE_VARS` the user
    approved forwarding. ``kubeconfig`` is the minted temp-kubeconfig path (or
    ``None``); when set, the K8s marker variables are added. ``user_fallback`` is
    used for ``USER`` when it is absent from ``outer`` (the CLI computes it via
    ``id -un``).
    """
    env: dict[str, str] = {}

    # Always present.
    env["HOME"] = outer["HOME"]
    env["USER"] = outer.get("USER") or user_fallback
    for key, default in ALWAYS_DEFAULTS.items():
        env[key] = outer.get(key) or default
    env["CLAUDE_SANDBOX"] = "1"

    # Conditional pass-through.
    for key in CONDITIONAL_VARS:
        value = outer.get(key)
        if value:
            env[key] = value

    # Kubernetes (only when a token was minted).
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
        env["CLAUDE_SANDBOX_KUBECONFIG_PATHS"] = kubeconfig
        env["CLAUDE_SANDBOX_ALLOW_KUBECONFIG"] = "1"

    # Approved sensitive variables.
    for name in approved_sensitive:
        value = outer.get(name)
        if value is not None:
            env[name] = value

    return env
