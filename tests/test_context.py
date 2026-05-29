"""Tests for §2/§4/§5 context resolution (FS seams injected)."""

from __future__ import annotations

from mcsand.cleanup import CleanupRegistry
from mcsand.config import parse_config
from mcsand.context import build_policy
from mcsand.optins import DockerPaths, K8sResult, OptIns


def _cfg(env, cwd):
    return parse_config(env, cwd=cwd)


def _no_claude(_name: str) -> str | None:
    """A `which` seam that finds no claude binary (deterministic tests)."""
    return None


class TestWorkdirDecision:
    def test_uses_cwd_when_not_home(self) -> None:
        reg = CleanupRegistry()
        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/proj"), OptIns(), registry=reg, which=_no_claude
        )
        assert policy.workdir == "/h/proj"
        assert reg._dirs == []

    def test_mktemp_when_launched_from_home(self) -> None:
        reg = CleanupRegistry()
        calls = []

        def fake_mkdtemp() -> str:
            calls.append(True)
            return "/private/var/folders/tmp/mcsand-work-xyz"

        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h"),
            OptIns(),
            registry=reg,
            mkdtemp=fake_mkdtemp,
            which=_no_claude,
        )
        assert calls == [True]
        assert policy.workdir == "/private/var/folders/tmp/mcsand-work-xyz"
        # The temp workdir is registered for non-recursive rmdir cleanup.
        assert reg._dirs == ["/private/var/folders/tmp/mcsand-work-xyz"]


class TestAncestors:
    def test_reproduces_v2_design_example(self) -> None:
        # v2 prepends /Users (the parent of $HOME) so realpath walks traverse it
        # under deny-by-default reads.
        policy = build_policy(
            _cfg({"HOME": "/Users/alice"}, "/Users/alice/projects/app"),
            OptIns(),
            registry=CleanupRegistry(),
            which=_no_claude,
        )
        assert policy.ancestors == (
            "/Users",
            "/Users/alice/projects",
            "/Users/alice",
            "/Users/alice/Library/Caches",
            "/Users/alice/Library",
            "/Users/alice/.config",
            "/Users/alice/.local",
            "/Users/alice/.local/share",
        )


class TestClaudeBinaryDir:
    def test_resolved_dir_set_when_found(self) -> None:
        def which(_name: str) -> str | None:
            return "/opt/homebrew/bin/claude"

        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"), OptIns(), registry=CleanupRegistry(), which=which
        )
        assert policy.claude_read_dir == "/opt/homebrew/bin"

    def test_none_when_not_found(self) -> None:
        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"), OptIns(), registry=CleanupRegistry(), which=_no_claude
        )
        assert policy.claude_read_dir is None

    def test_in_home_install_adds_ancestors(self) -> None:
        # A node-version-manager install under $HOME (e.g. ~/.nvm) contributes
        # its $HOME-internal ancestors to the metadata list.
        def which(_name: str) -> str | None:
            return "/h/.nvm/versions/node/v20/bin/claude"

        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"), OptIns(), registry=CleanupRegistry(), which=which
        )
        assert policy.claude_read_dir == "/h/.nvm/versions/node/v20/bin"
        assert "/h/.nvm" in policy.ancestors


class TestSymlinkInstallMode:
    def test_hook_symlink_adds_read_and_tamper(self) -> None:
        def resolve_link(path: str) -> str:
            if path.endswith("/.claude/hooks"):
                return "/repo/hooks"
            return path

        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"),
            OptIns(),
            registry=CleanupRegistry(),
            resolve_link=resolve_link,
            which=_no_claude,
        )
        assert "/repo/hooks" in policy.ro.subpaths  # readable
        assert "/h/.claude/hooks" in policy.tamper_subpaths  # seen path tamper-denied
        assert "/repo/hooks" in policy.tamper_subpaths  # real path tamper-denied

    def test_settings_symlink_denies_both_paths(self) -> None:
        def resolve_link(path: str) -> str:
            if path.endswith("/settings.json"):
                return "/repo/settings.json"
            return path

        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"),
            OptIns(),
            registry=CleanupRegistry(),
            resolve_link=resolve_link,
            which=_no_claude,
        )
        assert "/h/.claude/settings.json" in policy.tamper_literals
        assert "/repo/settings.json" in policy.tamper_literals


class TestOptInsWired:
    def test_docker_dir_ro_socket_both(self) -> None:
        opts = OptIns(
            docker=DockerPaths(socket="/private/var/run/docker.sock", docker_dir="/h/.docker")
        )
        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"), opts, registry=CleanupRegistry(), which=_no_claude
        )
        # ~/.docker is read-only (v2 §5.2): in RO, not RW.
        assert "/h/.docker" in policy.ro.subpaths
        assert "/h/.docker" not in policy.rw.subpaths
        # The socket needs read+write: in both RW and RO literals.
        assert "/private/var/run/docker.sock" in policy.rw.literals
        assert "/private/var/run/docker.sock" in policy.ro.literals

    def test_k8s_in_ro_literals(self) -> None:
        opts = OptIns(k8s=K8sResult(kubeconfig_path="/private/var/folders/x/kc.yaml"))
        policy = build_policy(
            _cfg({"HOME": "/h"}, "/h/p"), opts, registry=CleanupRegistry(), which=_no_claude
        )
        assert "/private/var/folders/x/kc.yaml" in policy.ro.literals
        assert "/private/var/folders/x/kc.yaml" not in policy.rw.literals
