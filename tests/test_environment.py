"""Tests for §7 clean-environment construction (pure)."""

from __future__ import annotations

from mcsand.environment import build_clean_env, sensitive_vars_present


def _build(outer, **kw):
    kw.setdefault("approved_sensitive", set())
    kw.setdefault("kubeconfig", None)
    kw.setdefault("user_fallback", "fallbackuser")
    return build_clean_env(outer, **kw)


class TestBuildCleanEnv:
    def test_always_present_with_defaults(self) -> None:
        env = _build({"HOME": "/h"})
        assert env["HOME"] == "/h"
        assert env["USER"] == "fallbackuser"
        assert env["PATH"] == "/usr/bin:/bin"
        assert env["TERM"] == "xterm-256color"
        assert env["SHELL"] == "/bin/zsh"
        assert env["LANG"] == "en_US.UTF-8"
        assert env["CLAUDE_SANDBOX"] == "1"

    def test_outer_values_win_over_defaults(self) -> None:
        env = _build({"HOME": "/h", "USER": "alice", "PATH": "/custom", "SHELL": "/bin/fish"})
        assert env["USER"] == "alice"
        assert env["PATH"] == "/custom"
        assert env["SHELL"] == "/bin/fish"

    def test_conditional_passthrough(self) -> None:
        env = _build({"HOME": "/h", "TMPDIR": "/private/var/folders/x", "EDITOR": "vim"})
        assert env["TMPDIR"] == "/private/var/folders/x"
        assert env["EDITOR"] == "vim"

    def test_conditional_absent_not_added(self) -> None:
        env = _build({"HOME": "/h"})
        assert "TMPDIR" not in env
        assert "SSH_AUTH_SOCK" not in env

    def test_kubeconfig_sets_markers(self) -> None:
        env = _build({"HOME": "/h"}, kubeconfig="/private/var/folders/x/kc.yaml")
        assert env["KUBECONFIG"] == "/private/var/folders/x/kc.yaml"
        assert env["CLAUDE_SANDBOX_KUBECONFIG_PATHS"] == "/private/var/folders/x/kc.yaml"
        assert env["CLAUDE_SANDBOX_ALLOW_KUBECONFIG"] == "1"

    def test_no_kubeconfig_no_markers(self) -> None:
        env = _build({"HOME": "/h"})
        assert "KUBECONFIG" not in env
        assert "CLAUDE_SANDBOX_ALLOW_KUBECONFIG" not in env

    def test_sensitive_withheld_unless_approved(self) -> None:
        outer = {"HOME": "/h", "ANSIBLE_VAULT_PASSWORD": "secret"}
        assert "ANSIBLE_VAULT_PASSWORD" not in _build(outer)
        approved = _build(outer, approved_sensitive={"ANSIBLE_VAULT_PASSWORD"})
        assert approved["ANSIBLE_VAULT_PASSWORD"] == "secret"


class TestSensitiveVarsPresent:
    def test_detects_set_vars(self) -> None:
        assert sensitive_vars_present({"ANSIBLE_VAULT_PASSWORD": "x"}) == ["ANSIBLE_VAULT_PASSWORD"]

    def test_empty_when_unset(self) -> None:
        assert sensitive_vars_present({"HOME": "/h"}) == []
