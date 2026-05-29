"""UserPromptSubmit sandbox gate (§7.2)."""

from __future__ import annotations

from mcsand.hooks import sandbox_precheck


def test_blocks_without_marker() -> None:
    assert sandbox_precheck.decide({}) is not None
    assert sandbox_precheck.decide({"CLAUDE_SANDBOX": ""}) is not None


def test_allows_with_marker() -> None:
    assert sandbox_precheck.decide({"CLAUDE_SANDBOX": "1"}) is None
