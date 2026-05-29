"""Behavioural sandbox tests — macOS only (§12.9).

These run the real ``sandbox-exec`` and assert the policy *behaves* as designed.
They are skipped on non-Darwin platforms (e.g. Linux CI). Per the design doc,
``sandbox-exec`` cannot nest, so run these from a plain (non-sandboxed) macOS
terminal: ``uv run pytest -m darwin``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from mcsand.cleanup import CleanupRegistry
from mcsand.config import parse_config
from mcsand.context import build_policy
from mcsand.optins import OptIns
from mcsand.profile import render_profile

pytestmark = [
    pytest.mark.darwin,
    pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec"),
]


def _write_profile(tmp_path, *, cwd, blocked=None) -> str:
    env = {"HOME": os.environ["HOME"]}
    if blocked:
        env["CLAUDE_SANDBOX_BLOCKED_DIRS"] = blocked
    cfg = parse_config(env, cwd=cwd)
    policy = build_policy(cfg, OptIns(), registry=CleanupRegistry())
    profile = tmp_path / "policy.sb"
    profile.write_text(render_profile(policy))
    return str(profile)


def _sandboxed(profile: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sandbox-exec", "-f", profile, *argv],
        capture_output=True,
        text=True,
        check=False,
    )


def test_blocked_dir_denied(tmp_path) -> None:
    proj = tmp_path / "proj"
    secrets = proj / "secrets"
    secrets.mkdir(parents=True)
    secret_file = secrets / "token"
    secret_file.write_text("s3cr3t")

    profile = _write_profile(tmp_path, cwd=str(proj), blocked=str(secrets))
    result = _sandboxed(profile, ["/bin/cat", str(secret_file)])
    assert result.returncode != 0
    assert "operation not permitted" in (result.stderr + result.stdout).lower()


def test_workdir_write_allowed(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    target = proj / "out.txt"
    result = _sandboxed(profile, ["/usr/bin/touch", str(target)])
    assert result.returncode == 0
    assert target.exists()


def test_outside_write_denied(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    # /usr is outside every write-allow entry.
    result = _sandboxed(profile, ["/usr/bin/touch", "/usr/mcsand-should-fail"])
    assert result.returncode != 0


def test_mach_task_read_denied(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    victim = subprocess.Popen(["/bin/sleep", "30"])
    try:
        time.sleep(0.5)
        # vmmap is non-setuid, so it execs — but acquiring the target's Mach
        # task port is denied, so it cannot read another process's memory.
        result = _sandboxed(profile, ["/usr/bin/vmmap", str(victim.pid)])
        assert result.returncode != 0
    finally:
        victim.terminate()
        victim.wait()


@pytest.mark.xfail(reason="setuid binaries cannot exec under Seatbelt — §10 #4", strict=False)
def test_setuid_ps_runs(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    result = _sandboxed(profile, ["/bin/ps", "-p", str(os.getpid())])
    assert result.returncode == 0  # expected to fail: ps is setuid root


def test_outside_home_read_denied(tmp_path) -> None:
    """v2: reads are deny-by-default, so a file in another user's home (under
    /Users but outside $HOME) is no longer readable."""
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    # A path under /Users that is neither a system root nor on the allowlist.
    # Use a temp file under /Users/Shared, which exists on stock macOS.
    target = "/Users/Shared/.mcsand-read-probe"
    try:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("probe")
        result = _sandboxed(profile, ["/bin/cat", target])
        assert result.returncode != 0
        assert "operation not permitted" in (result.stderr + result.stdout).lower()
    finally:
        if os.path.exists(target):
            os.remove(target)


def test_firmlink_alias_denied(tmp_path) -> None:
    """v2 §10: a denied $HOME file must not be readable via its APFS firmlink
    alias under /System/Volumes/Data (which the /System read-root would expose)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    profile = _write_profile(tmp_path, cwd=str(proj))
    # ~/.ssh is blacked out; reach a file in it via the firmlink alias.
    home = os.environ["HOME"]
    alias = f"/System/Volumes/Data{home}/.ssh/id_rsa"
    direct = f"{home}/.ssh/id_rsa"
    if not os.path.exists(direct):
        pytest.skip("no ~/.ssh/id_rsa to probe with")
    result = _sandboxed(profile, ["/bin/cat", alias])
    assert result.returncode != 0
    assert "operation not permitted" in (result.stderr + result.stdout).lower()
