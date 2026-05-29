"""Tests for the CLI surface (argument splitting + subcommands)."""

from __future__ import annotations

import sys

import pytest

from mcsand.cli import _split_args, main


class TestSplitArgs:
    def test_double_dash_separates(self) -> None:
        assert _split_args(["--rw", "/x", "--", "--resume", "y"]) == (
            ["--rw", "/x"],
            ["--resume", "y"],
        )

    def test_no_double_dash(self) -> None:
        assert _split_args(["--yes"]) == (["--yes"], [])


@pytest.fixture
def home_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    proj = home / "proj"
    proj.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("KUBECONFIG", raising=False)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(proj)
    return home


class TestDoctor:
    def test_runs_and_reports(self, home_env, capsys) -> None:
        rc = main(["doctor"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "mcsand doctor" in out
        assert "sandbox-exec" in out
        assert "working directory" in out

    def test_sensitive_var_from_env_reported(self, home_env, capsys, monkeypatch) -> None:
        monkeypatch.setenv("CLAUDE_SANDBOX_SENSITIVE_VARS", "NPM_TOKEN")
        monkeypatch.setenv("NPM_TOKEN", "t")
        rc = main(["doctor"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "NPM_TOKEN" in out  # shown as both configured-added and set


class TestPrintProfile:
    def test_renders_profile(self, home_env, capsys) -> None:
        rc = main(["print-profile", "--no-docker", "--no-k8s"])
        out = capsys.readouterr().out
        assert rc == 0
        assert out.startswith("(version 1)\n(allow default)")
        assert "(deny process-info* (target others))" in out

    def test_flag_sugar_adds_blocked_dir(self, home_env, capsys) -> None:
        rc = main(["print-profile", "--block", "./secrets"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "(deny file-read* file-write*" in out
        assert "/./" not in out  # canonicalized


class TestDryRun:
    def test_prints_command_without_launching(self, home_env, capsys) -> None:
        rc = main(["--dry-run", "--no-docker", "--no-k8s", "--", "--version"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "sandbox-exec" in out
        assert "--version" in out


class TestPlatformRefusal:
    @pytest.mark.skipif(sys.platform == "darwin", reason="non-macOS refusal path")
    def test_launch_refuses_off_macos(self, home_env, capsys) -> None:
        rc = main(["--no-docker", "--no-k8s"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "macOS-only" in err


class TestRun:
    def test_dry_run_previews_arbitrary_command(self, home_env, capsys) -> None:
        rc = main(["run", "--no-docker", "--no-k8s", "--dry-run", "--", "echo", "hi"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "sandbox-exec" in out
        # The resolved command + its args appear in the previewed argv.
        assert out.rstrip().endswith("echo hi") or " echo hi" in out

    def test_missing_command_errors(self, home_env, capsys) -> None:
        rc = main(["run"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "no command given" in err


class TestShell:
    def test_dry_run_uses_shell_env(self, home_env, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SHELL", "/bin/zsh")
        rc = main(["shell", "--no-docker", "--no-k8s", "--dry-run"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "sandbox-exec" in out
        assert "/bin/zsh" in out


class TestInstallHooks:
    def test_dry_run_renders_registration(self, home_env, capsys) -> None:
        import json

        rc = main(["install-hooks", "--dry-run"])
        out = capsys.readouterr().out
        assert rc == 0
        parsed = json.loads(out)
        cmds = [e["hooks"][0]["command"] for e in parsed["hooks"]["PreToolUse"]]
        assert "python3 -m mcsand.hooks.bash_precheck" in cmds

    def test_writes_into_claude_config_dir(self, home_env, capsys) -> None:
        rc = main(["install-hooks"])
        assert rc == 0
        settings = home_env / ".claude" / "settings.json"
        assert settings.exists()
