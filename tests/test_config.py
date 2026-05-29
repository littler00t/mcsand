"""Tests for §9 config parsing (pure)."""

from __future__ import annotations

from mcsand.config import parse_config, parse_dir_list


class TestParseDirList:
    def test_none_and_empty(self) -> None:
        assert parse_dir_list(None, cwd="/w") == ()
        assert parse_dir_list("", cwd="/w") == ()

    def test_colon_split_drops_empty(self) -> None:
        assert parse_dir_list("/a:/b::/c", cwd="/w") == ("/a", "/b", "/c")

    def test_relative_entries_resolved(self) -> None:
        assert parse_dir_list("rel:./x", cwd="/w") == ("/w/rel", "/w/x")

    def test_normalize_applied(self) -> None:
        assert parse_dir_list("/tmp/scratch", cwd="/w") == ("/private/tmp/scratch",)

    def test_secrets_bug_no_dot_segment(self) -> None:
        # The demonstrated §10 bypass: ./secrets must canonicalize cleanly.
        (entry,) = parse_dir_list("./secrets", cwd="/work/proj")
        assert entry == "/work/proj/secrets"
        assert "/./" not in entry


class TestParseConfig:
    def test_defaults(self) -> None:
        cfg = parse_config({"HOME": "/Users/alice"}, cwd="/Users/alice/p")
        assert cfg.home == "/Users/alice"
        assert cfg.claude_dir == "/Users/alice/.claude"
        assert cfg.cwd == "/Users/alice/p"
        assert cfg.additional_rw == ()
        assert cfg.ssh_auth_sock is None

    def test_claude_config_dir_override(self) -> None:
        cfg = parse_config(
            {"HOME": "/Users/alice", "CLAUDE_CONFIG_DIR": "/Users/alice/cfg"},
            cwd="/x",
        )
        assert cfg.claude_dir == "/Users/alice/cfg"

    def test_ssh_sock_normalized(self) -> None:
        cfg = parse_config({"HOME": "/h", "SSH_AUTH_SOCK": "/tmp/agent.sock"}, cwd="/x")
        assert cfg.ssh_auth_sock == "/private/tmp/agent.sock"

    def test_allowed_dirs_and_k8s(self) -> None:
        cfg = parse_config(
            {
                "HOME": "/h",
                "CLAUDE_SANDBOX_ALLOWED_DIRS": "/a:/b",
                "CLAUDE_SANDBOX_ALLOWED_RO_DIRS": "/ro",
                "CLAUDE_SANDBOX_BLOCKED_DIRS": "/secret",
                "CLAUDE_SANDBOX_K8S_SA": "ns/sa",
                "CLAUDE_SANDBOX_K8S_IMPERSONATE": "cluster-admin",
                "CLAUDE_SANDBOX_K8S_ROLE": "edit",
                "CLAUDE_SANDBOX_K8S_NAMESPACE": "team-a",
                "CLAUDE_SANDBOX_K8S_CLUSTER_WIDE": "1",
                "CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME": "2h",
            },
            cwd="/x",
        )
        assert cfg.additional_rw == ("/a", "/b")
        assert cfg.additional_ro == ("/ro",)
        assert cfg.blocked_dirs == ("/secret",)
        assert cfg.k8s_sa == "ns/sa"
        assert cfg.k8s_impersonate == "cluster-admin"
        assert cfg.k8s_role == "edit"
        assert cfg.k8s_namespace == "team-a"
        assert cfg.k8s_cluster_wide is True
        assert cfg.k8s_token_lifetime == "2h"

    def test_old_additional_mounts_names_ignored(self) -> None:
        # v2 hard-renamed the vars; the old names must no longer be honored.
        cfg = parse_config(
            {
                "HOME": "/h",
                "CLAUDE_SANDBOX_ADDITIONAL_MOUNTS": "/a",
                "CLAUDE_SANDBOX_ADDITIONAL_RO_MOUNTS": "/ro",
            },
            cwd="/x",
        )
        assert cfg.additional_rw == ()
        assert cfg.additional_ro == ()

    def test_cluster_wide_falsey_and_unset(self) -> None:
        unset = parse_config({"HOME": "/h"}, cwd="/x")
        assert unset.k8s_cluster_wide is None
        false = parse_config({"HOME": "/h", "CLAUDE_SANDBOX_K8S_CLUSTER_WIDE": "0"}, cwd="/x")
        assert false.k8s_cluster_wide is False
        empty = parse_config({"HOME": "/h", "CLAUDE_SANDBOX_K8S_CLUSTER_WIDE": ""}, cwd="/x")
        assert empty.k8s_cluster_wide is False
