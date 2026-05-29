"""Glob gate — block/allow cases incl. the effective-root trick (§5.3)."""

from __future__ import annotations

import pytest

from mcsand.hooks import glob_precheck

HOME = "/Users/alice"


def _decide(pattern: str, path: str | None = None) -> str | None:
    ti: dict[str, str] = {"pattern": pattern}
    if path is not None:
        ti["path"] = path
    return glob_precheck.evaluate({"tool_input": ti}, HOME)


BLOCK_PATTERN = [
    "~/.ssh/*",
    "~/.ssh/**",
    "~/.aws/*",
    "~/.gnupg/*",
    "**/.env",
    "**/.env.local",
    "**/.envrc",
    "*.pem",
    "*.key",
    "*.pem*",
    "*.gpg",
    "*.asc",
    "/etc/shadow",
    "**/.netrc",
    "secrets.json",
    "credentials.yaml",
    "*.kdbx",
]

ALLOW_PATTERN = [
    "**/*.py",
    "src/**/*.ts",
    "*.md",
    "data/*.json",
    "",  # empty pattern → allow
]


@pytest.mark.parametrize("pattern", BLOCK_PATTERN)
def test_blocks_pattern(pattern: str) -> None:
    assert _decide(pattern) is not None, pattern


@pytest.mark.parametrize("pattern", ALLOW_PATTERN)
def test_allows_pattern(pattern: str) -> None:
    assert _decide(pattern) is None, pattern


def test_effective_root_path_contamination() -> None:
    # The sensitive dir hides in `path`; a bare `*` pattern still gets caught.
    assert _decide("*", path="~/.ssh") is not None
    assert _decide("*", path="~/.aws") is not None
    assert _decide("*", path="~/.gnupg") is not None


def test_benign_path_allows() -> None:
    assert _decide("*.py", path="~/project/src") is None
