"""Tests for the §6 path helpers (pure logic, runs on Linux CI)."""

from __future__ import annotations

import os

from mcsand.paths import abspath, add_ancestors, normalize, resolve1, sbpl_escape


class TestNormalize:
    def test_maps_tmp_var_etc_under_private(self) -> None:
        assert normalize("/tmp/x") == "/private/tmp/x"
        assert normalize("/var/folders/y") == "/private/var/folders/y"
        assert normalize("/etc/hosts") == "/private/etc/hosts"

    def test_bare_roots(self) -> None:
        assert normalize("/var") == "/private/var"
        assert normalize("/tmp") == "/private/tmp"

    def test_leaves_other_paths_unchanged(self) -> None:
        assert normalize("/usr/lib") == "/usr/lib"
        assert normalize("/Users/alice/x") == "/Users/alice/x"
        assert normalize("") == ""

    def test_idempotent_on_private(self) -> None:
        assert normalize("/private/tmp/x") == "/private/tmp/x"
        assert normalize(normalize("/tmp/x")) == "/private/tmp/x"

    def test_does_not_match_lookalike_prefix(self) -> None:
        # "/variable" must not be treated as "/var/...".
        assert normalize("/variable/x") == "/variable/x"


class TestAbspathLexicalFallback:
    """The non-existent-path branch — the §10 ./secrets regression lives here."""

    def test_relative_is_joined_to_cwd(self) -> None:
        assert abspath("./secrets", cwd="/work") == "/work/secrets"

    def test_no_dot_segment_survives(self) -> None:
        # This is the exact bug: "$PWD/./secrets" once silently broke a deny rule.
        assert "/./" not in abspath("./secrets", cwd="/work")

    def test_resolves_dotdot(self) -> None:
        assert abspath("a/../b", cwd="/work") == "/work/b"

    def test_collapses_double_slash(self) -> None:
        assert abspath("//x//y", cwd="/work") == "/x/y"

    def test_empty_stays_empty(self) -> None:
        assert abspath("", cwd="/work") == ""

    def test_dotdot_above_root_discarded(self) -> None:
        assert abspath("/../../foo", cwd="/work") == "/foo"


class TestAbspathRealpathBranch:
    def test_existing_dir_is_realpathed(self, tmp_path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        assert abspath(str(sub), cwd="/anything") == os.path.realpath(str(sub))

    def test_existing_dir_resolves_symlink(self, tmp_path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        assert abspath(str(link), cwd="/x") == os.path.realpath(str(real))


class TestResolve1:
    def test_non_symlink_unchanged(self, tmp_path) -> None:
        f = tmp_path / "f"
        f.write_text("x")
        assert resolve1(str(f)) == str(f)

    def test_absolute_target(self, tmp_path) -> None:
        target = tmp_path / "target"
        target.write_text("x")
        link = tmp_path / "link"
        link.symlink_to(target)
        assert resolve1(str(link)) == str(target)

    def test_relative_target_joined_against_link_dir(self, tmp_path) -> None:
        target = tmp_path / "target"
        target.write_text("x")
        link = tmp_path / "link"
        link.symlink_to("target")  # relative
        assert resolve1(str(link)) == str(tmp_path / "target")

    def test_single_level_only(self, tmp_path) -> None:
        c = tmp_path / "c"
        c.write_text("x")
        b = tmp_path / "b"
        b.symlink_to(c)
        a = tmp_path / "a"
        a.symlink_to(b)
        # One hop: a -> b, NOT a -> c.
        assert resolve1(str(a)) == str(b)


class TestSbplEscape:
    def test_backslash(self) -> None:
        assert sbpl_escape("a\\b") == "a\\\\b"

    def test_quote(self) -> None:
        assert sbpl_escape('a"b') == 'a\\"b'

    def test_order_backslash_first(self) -> None:
        # A literal backslash-quote must become escaped-backslash escaped-quote.
        assert sbpl_escape('\\"') == '\\\\\\"'

    def test_plain_unchanged(self) -> None:
        assert sbpl_escape("/Users/alice/x y") == "/Users/alice/x y"


class TestAddAncestors:
    def test_walks_parent_to_home_inclusive(self) -> None:
        out: list[str] = []
        add_ancestors("/Users/alice/projects/app", home="/Users/alice", into=out)
        assert out == ["/Users/alice/projects", "/Users/alice"]

    def test_not_under_home_contributes_nothing(self) -> None:
        out: list[str] = []
        add_ancestors("/opt/tool/bin", home="/Users/alice", into=out)
        assert out == []

    def test_insertion_order_dedup_reproduces_design_example(self) -> None:
        # §4.8 ancestor list, built from workdir + the fixed in-$HOME allowlist.
        home = "/Users/alice"
        out: list[str] = []
        add_ancestors(f"{home}/projects/app", home=home, into=out)
        for d in (
            f"{home}/.claude",
            f"{home}/.cache",
            f"{home}/Library/Caches/claude-cli-nodejs",
            f"{home}/Library/Keychains",
            f"{home}/.config/git",
            f"{home}/.config/ccstatusline",
            f"{home}/.local/bin",
            f"{home}/.local/share/uv",
            f"{home}/.npm",
        ):
            add_ancestors(d, home=home, into=out)
        assert out == [
            f"{home}/projects",
            home,
            f"{home}/Library/Caches",
            f"{home}/Library",
            f"{home}/.config",
            f"{home}/.local",
            f"{home}/.local/share",
        ]
