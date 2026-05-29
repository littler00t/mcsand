"""PostToolUse scan classifier (§7.1) — pure command→target logic."""

from __future__ import annotations

import pytest

from mcsand.hooks import scan

HOME = "/Users/alice"
ENV = {"HOME": HOME}


@pytest.mark.parametrize(
    ("command", "kind"),
    [
        ("curl -O https://x/pkg.tar", "download"),
        ("wget https://x/file", "download"),
        ("git clone https://x/repo.git", "clone"),
        ("pip install requests", "pip"),
        ("pip3 install -r req.txt", "pip"),
        ("npm install", "npm"),
        ("npm ci", "npm"),
        ("cargo build", "cargo"),
        ("go mod download", "go"),
    ],
)
def test_classify_kind(command: str, kind: str) -> None:
    result = scan.classify(command)
    assert result is not None
    assert result[0] == kind


@pytest.mark.parametrize("command", ["ls -la", "echo hi", "make build", ""])
def test_classify_non_fetch_returns_none(command: str) -> None:
    assert scan.classify(command) is None


def test_download_output_flag_target() -> None:
    kind, raw = scan.classify("curl -o /tmp/pkg.tar https://x")  # type: ignore[misc]
    assert kind == "download"
    assert raw == "/tmp/pkg.tar"
    assert scan.resolve_target(kind, raw, HOME, ENV) == "/tmp/pkg.tar"


def test_download_default_downloads_dir() -> None:
    kind, raw = scan.classify("wget https://x/file")  # type: ignore[misc]
    assert scan.resolve_target(kind, raw, HOME, ENV) == f"{HOME}/Downloads"


def test_clone_explicit_dir_and_default() -> None:
    kind, raw = scan.classify("git clone https://x/repo.git mydir")  # type: ignore[misc]
    assert raw == "mydir"
    assert scan.resolve_target(kind, raw, HOME, ENV) == "mydir"
    kind2, raw2 = scan.classify("git clone https://x/repo.git")  # type: ignore[misc]
    assert scan.resolve_target(kind2, raw2, HOME, ENV) == "."


def test_npm_and_cache_targets() -> None:
    assert scan.resolve_target("npm", "", HOME, ENV) == "node_modules"
    assert scan.resolve_target("cargo", "", HOME, ENV) == f"{HOME}/.cargo/registry/src"
    assert scan.resolve_target("go", "", HOME, ENV) == f"{HOME}/go/pkg/mod/cache"


def test_cache_targets_honor_env() -> None:
    env = {"HOME": HOME, "CARGO_HOME": "/opt/cargo", "GOPATH": "/opt/go"}
    assert scan.resolve_target("cargo", "", HOME, env) == "/opt/cargo/registry/src"
    assert scan.resolve_target("go", "", HOME, env) == "/opt/go/pkg/mod/cache"
