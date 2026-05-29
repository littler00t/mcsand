"""Tests for §2 launch mechanics (argv shape, exit-code propagation)."""

from __future__ import annotations

from types import SimpleNamespace

from mcsand.launcher import build_argv, launch


class TestBuildArgv:
    def test_command_shape(self) -> None:
        argv = build_argv(
            "/tmp/profile.sb",
            {"HOME": "/h", "PATH": "/usr/bin:/bin"},
            "/usr/local/bin/claude",
            ["--resume", "x"],
        )
        assert argv[:5] == ["sandbox-exec", "-f", "/tmp/profile.sb", "/usr/bin/env", "-i"]
        assert "HOME=/h" in argv
        assert "PATH=/usr/bin:/bin" in argv
        # Claude binary + its args come last, in order.
        assert argv[-3:] == ["/usr/local/bin/claude", "--resume", "x"]


class TestLaunch:
    def test_propagates_exit_code_and_cwd(self) -> None:
        captured = {}

        def fake_run(argv, cwd, check):
            captured["argv"] = argv
            captured["cwd"] = cwd
            captured["check"] = check
            return SimpleNamespace(returncode=42)

        code = launch(
            "/tmp/p.sb",
            {"HOME": "/h"},
            "claude",
            ["--help"],
            workdir="/work/proj",
            run=fake_run,
        )
        assert code == 42
        assert captured["cwd"] == "/work/proj"
        assert captured["check"] is False
        assert captured["argv"][0] == "sandbox-exec"
