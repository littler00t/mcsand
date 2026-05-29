"""Tests for the §4-§5 SBPL renderer, plus the §12/§13 invariants (v2).

The renderer is pure, so these all run on Linux CI. ``build_policy`` is used to
exercise the realistic composition path; the ``which`` seam is injected with a
fixed claude binary so output is deterministic (the real ``shutil.which`` would
vary by machine), and ``mkdtemp`` is never called here (cwd != home).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from mcsand.cleanup import CleanupRegistry
from mcsand.config import parse_config
from mcsand.context import build_policy
from mcsand.optins import DockerPaths, K8sResult, OptIns
from mcsand.profile import render_profile

# A fixed resolved claude binary dir for deterministic goldens (mirrors the v2
# §4.8 example, where claude lives under a Homebrew Caskroom).
CLAUDE_DIR = "/opt/homebrew/Caskroom/claude-code@latest/2.x.y"


def _which(_name: str) -> str | None:
    return f"{CLAUDE_DIR}/claude"


# The v2 §4.8 concrete rendered example (default options, ssh-agent present).
# Reads are deny-by-default: system roots + "/" + the /etc /tmp /var symlinks +
# the resolved claude dir + the in-$HOME set; then the firmlink alias is denied.
EXPECTED_DEFAULT = """(version 1)
(allow default)

;; Writes: deny everything, then re-allow a specific set
(deny file-write*)
(allow file-write*
  (subpath "/Users/alice/projects/app")
  (subpath "/Users/alice/.claude")
  (subpath "/Users/alice/.cache")
  (subpath "/Users/alice/Library/Caches/claude-cli-nodejs")
  (subpath "/Users/alice/Library/Keychains")
  (subpath "/private/tmp")
  (subpath "/private/var/folders")
  (subpath "/private/var/tmp")
  (literal "/Users/alice/.claude.json")
  (literal "/Users/alice/.claude.json.backup")
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/tty")
  (literal "/dev/ptmx")
  (literal "/dev/stdin")
  (literal "/dev/stdout")
  (literal "/dev/stderr")
  (literal "/private/var/folders/xx/abc/ssh-agent.sock")
  (regex #"^/dev/ttys")
  (regex #"^/dev/fd/"))

;; Reads: deny by default, then re-allow system roots + the in-$HOME set
(deny file-read*)
(allow file-read*
  (subpath "/System")
  (subpath "/private")
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/Library")
  (subpath "/dev")
  (subpath "/opt")
  (literal "/")
  (literal "/etc")
  (literal "/tmp")
  (literal "/var")
  (subpath "/opt/homebrew/Caskroom/claude-code@latest/2.x.y")
  (subpath "/Users/alice/projects/app")
  (subpath "/Users/alice/.claude")
  (subpath "/Users/alice/.cache")
  (subpath "/Users/alice/Library/Caches/claude-cli-nodejs")
  (subpath "/Users/alice/Library/Keychains")
  (subpath "/Users/alice/.config/git")
  (subpath "/Users/alice/.config/ccstatusline")
  (subpath "/Users/alice/.local/bin")
  (subpath "/Users/alice/.local/share/uv")
  (subpath "/Users/alice/.npm")
  (literal "/Users/alice/.claude.json")
  (literal "/Users/alice/.claude.json.backup")
  (literal "/Users/alice/.gitconfig"))
;; Firmlink guard: deny the /System/Volumes/Data alias for $HOME files
(deny file-read* (subpath "/System/Volumes/Data"))

;; Metadata-only (lstat) on workdir & allowlist ancestors
(allow file-read-metadata
  (literal "/Users")
  (literal "/Users/alice/projects")
  (literal "/Users/alice")
  (literal "/Users/alice/Library/Caches")
  (literal "/Users/alice/Library")
  (literal "/Users/alice/.config")
  (literal "/Users/alice/.local")
  (literal "/Users/alice/.local/share"))

;; Tamper-proofing: Claude must not rewrite its own security config
(deny file-write*
  (subpath "/Users/alice/.claude/hooks")
  (literal "/Users/alice/.claude/settings.json"))

;; Process isolation: block inspecting other processes
(deny process-info* (target others))
(deny mach-task-read mach-task-name (target others))
"""


def _policy(
    env: dict[str, str],
    cwd: str,
    opts: OptIns | None = None,
    *,
    which: Callable[[str], str | None] = _which,
):
    cfg = parse_config(env, cwd=cwd)
    return build_policy(cfg, opts or OptIns(), registry=CleanupRegistry(), which=which)


def _rule_paths(profile: str) -> list[str]:
    """Every quoted path inside a subpath/literal matcher."""
    return re.findall(r'\((?:subpath|literal) "([^"]*)"\)', profile)


class TestGolden:
    def test_default_matches_design_example(self) -> None:
        policy = _policy(
            {"HOME": "/Users/alice", "SSH_AUTH_SOCK": "/private/var/folders/xx/abc/ssh-agent.sock"},
            cwd="/Users/alice/projects/app",
        )
        assert render_profile(policy) == EXPECTED_DEFAULT


class TestDenyByDefaultReads:
    """v2 §4.3: reads are a fail-closed allowlist of system roots + the in-$HOME set."""

    def test_global_read_deny_not_home_only(self) -> None:
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        assert "(deny file-read*)\n" in profile
        assert '(deny file-read* (subpath "/Users/alice"))' not in profile

    def test_system_roots_present(self) -> None:
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        for root in ("/System", "/private", "/usr", "/bin", "/sbin", "/Library", "/dev", "/opt"):
            assert f'(subpath "{root}")' in profile
        for lit in ("/", "/etc", "/tmp", "/var"):
            assert f'(literal "{lit}")' in profile

    def test_firmlink_alias_denied(self) -> None:
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        assert '(deny file-read* (subpath "/System/Volumes/Data"))' in profile
        # The deny must come AFTER the /System read-allow (last-match-wins).
        assert profile.index('(subpath "/System")') < profile.index("/System/Volumes/Data")

    def test_claude_binary_dir_read_allowed(self) -> None:
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        assert f'(subpath "{CLAUDE_DIR}")' in profile

    def test_users_parent_in_metadata(self) -> None:
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        assert '(literal "/Users")' in profile

    def test_outside_home_rw_dir_gets_read_allow(self) -> None:
        # A --rw dir outside $HOME and not under a system root must be re-listed
        # for reads (deny-by-default would otherwise leave it unreadable).
        policy = _policy(
            {"HOME": "/Users/alice", "CLAUDE_SANDBOX_ALLOWED_DIRS": "/data/project"},
            cwd="/Users/alice/p",
        )
        profile = render_profile(policy)
        read_block = profile.split("(deny file-read*)")[1].split("Firmlink")[0]
        assert '(subpath "/data/project")' in read_block

    def test_system_root_covered_rw_not_relisted_for_read(self) -> None:
        # /private/tmp et al. are covered by the /private root, so they must NOT
        # be re-listed in the composed read-allow set (matches §4.8).
        profile = render_profile(_policy({"HOME": "/Users/alice"}, cwd="/Users/alice/p"))
        read_block = profile.split("(deny file-read*)")[1].split("Firmlink")[0]
        assert '(subpath "/private/tmp")' not in read_block
        assert '(literal "/dev/null")' not in read_block


class TestSectionOrder:
    def test_sections_in_order(self) -> None:
        profile = render_profile(_policy({"HOME": "/h"}, cwd="/h/p"))
        markers = [
            "(allow default)",
            "(deny file-write*)",
            "(deny file-read*)",
            "(allow file-read*",
            '(deny file-read* (subpath "/System/Volumes/Data"))',
            "(allow file-read-metadata",
            ";; Tamper-proofing",
            "(deny process-info* (target others))",
            "(deny mach-task-read mach-task-name (target others))",
        ]
        positions = [profile.index(m) for m in markers]
        assert positions == sorted(positions)


class TestNoNonCanonical:
    """§12 invariant: no emitted path may contain /./ /../ // or a trailing slash."""

    def test_adversarial_relative_blocked_dir(self) -> None:
        policy = _policy(
            {"HOME": "/h", "CLAUDE_SANDBOX_BLOCKED_DIRS": "./secrets:../x:a//b"},
            cwd="/work/proj",
        )
        profile = render_profile(policy)
        for path in _rule_paths(profile):
            if path == "/":
                continue  # the dyld root literal is intentionally "/"
            assert "/./" not in path, path
            assert "/../" not in path, path
            assert "//" not in path, path
            assert not path.endswith("/"), path

    def test_blocked_dirs_present_in_output(self) -> None:
        policy = _policy(
            {"HOME": "/h", "CLAUDE_SANDBOX_BLOCKED_DIRS": "/work/proj/secrets"},
            cwd="/work/proj",
        )
        profile = render_profile(policy)
        assert "(deny file-read* file-write*" in profile
        assert '(subpath "/work/proj/secrets")' in profile

    def test_no_blocked_section_when_unset(self) -> None:
        profile = render_profile(_policy({"HOME": "/h"}, cwd="/h/p"))
        assert "deny file-read* file-write*" not in profile


class TestProcessIsolation:
    def test_both_rules_present(self) -> None:
        profile = render_profile(_policy({"HOME": "/h"}, cwd="/h/p"))
        assert "(deny process-info* (target others))" in profile
        assert "(deny mach-task-read mach-task-name (target others))" in profile


class TestOptInsRendered:
    def test_docker_socket_rw_and_dir_ro(self) -> None:
        opts = OptIns(
            docker=DockerPaths(socket="/private/var/run/docker.sock", docker_dir="/h/.docker")
        )
        profile = render_profile(_policy({"HOME": "/h"}, cwd="/h/p", opts=opts))
        write_block, read_block = profile.split("(deny file-read*)", 1)
        # Socket needs write: it is in the write-allow. Reads are covered by the
        # /private root, so it is not re-listed in read-allow (and never as a
        # standalone read elsewhere).
        assert '(literal "/private/var/run/docker.sock")' in write_block
        assert profile.count('(literal "/private/var/run/docker.sock")') == 1
        # ~/.docker is read-only: in the read-allow only, never write-allow.
        assert '(subpath "/h/.docker")' not in write_block
        assert '(subpath "/h/.docker")' in read_block
        assert profile.count('(subpath "/h/.docker")') == 1

    def test_k8s_kubeconfig_is_read_only(self) -> None:
        opts = OptIns(k8s=K8sResult(kubeconfig_path="/private/var/folders/zz/kubeconfig.yaml"))
        profile = render_profile(_policy({"HOME": "/h"}, cwd="/h/p", opts=opts))
        # The kubeconfig lives under /private, so the /private read-root already
        # covers it — it must NOT be re-listed (deny-by-default composition), and
        # it is never write-allowed.
        assert profile.count('"/private/var/folders/zz/kubeconfig.yaml"') == 0
