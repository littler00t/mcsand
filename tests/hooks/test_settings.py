"""settings.json fragment builder + the array-preserving installer merge (§6, §8)."""

from __future__ import annotations

import io
import json

from mcsand.hooks import install
from mcsand.hooks.settings import build_settings_fragment, hook_command


class TestFragment:
    def test_registers_all_pretooluse_gates(self) -> None:
        fragment = build_settings_fragment()
        pre = fragment["hooks"]["PreToolUse"]
        matchers = {entry["matcher"] for entry in pre}
        assert matchers == {"Bash", "Glob", "Read", "Edit", "Write"}
        for entry in pre:
            cmd = entry["hooks"][0]["command"]
            assert cmd.startswith("python3 -m mcsand.hooks.")

    def test_post_and_prompt_hooks(self) -> None:
        fragment = build_settings_fragment()
        assert fragment["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == hook_command("scan")
        ups = fragment["hooks"]["UserPromptSubmit"][0]
        assert "matcher" not in ups
        assert ups["hooks"][0]["command"] == hook_command("sandbox_precheck")

    def test_deny_globs_present(self) -> None:
        deny = build_settings_fragment()["permissions"]["deny"]
        assert "Read(**/.env)" in deny
        assert "Write(~/.claude/hooks/*)" in deny
        assert any("dangerously-skip-permissions" in g for g in deny)


class TestMerge:
    def test_preserves_existing_arrays(self) -> None:
        existing = {
            "permissions": {"deny": ["Bash(my-custom-thing)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "user.sh"}]}]},
            "model": "opus",
        }
        merged = install.merge_settings(existing)
        # User's deny entry + own command both survive (explicit array merge).
        assert "Bash(my-custom-thing)" in merged["permissions"]["deny"]
        assert "Read(**/.env)" in merged["permissions"]["deny"]
        pre_cmds = [e["hooks"][0]["command"] for e in merged["hooks"]["PreToolUse"]]
        assert "user.sh" in pre_cmds
        assert hook_command("bash_precheck") in pre_cmds
        # Unrelated scalar keys are untouched.
        assert merged["model"] == "opus"

    def test_idempotent(self) -> None:
        once = install.merge_settings({})
        twice = install.merge_settings(once)
        assert once == twice  # re-installing does not duplicate entries


class TestInstall:
    def test_dry_run_prints_without_writing(self, tmp_path) -> None:
        out = io.StringIO()
        rc = install.install_hooks(str(tmp_path), dry_run=True, out=out)
        assert rc == 0
        assert not (tmp_path / "settings.json").exists()
        parsed = json.loads(out.getvalue())
        assert "hooks" in parsed

    def test_write_creates_settings(self, tmp_path) -> None:
        out = io.StringIO()
        rc = install.install_hooks(str(tmp_path), dry_run=False, out=out)
        assert rc == 0
        data = json.loads((tmp_path / "settings.json").read_text())
        assert data["hooks"]["PreToolUse"]

    def test_refuses_invalid_existing_json(self, tmp_path) -> None:
        (tmp_path / "settings.json").write_text("{ broken")
        out = io.StringIO()
        rc = install.install_hooks(str(tmp_path), dry_run=True, out=out)
        assert rc == 1
        assert "not valid JSON" in out.getvalue()
