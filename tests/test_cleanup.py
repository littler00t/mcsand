"""Tests for §2/§7 temp-artifact cleanup lifecycle."""

from __future__ import annotations

from mcsand.cleanup import CleanupRegistry


class TestCleanupRegistry:
    def test_removes_registered_file(self, tmp_path) -> None:
        f = tmp_path / "profile.sb"
        f.write_text("x")
        reg = CleanupRegistry()
        reg.add_file(str(f))
        reg.run()
        assert not f.exists()

    def test_rmdir_empty_dir(self, tmp_path) -> None:
        d = tmp_path / "work"
        d.mkdir()
        reg = CleanupRegistry()
        reg.add_dir(str(d))
        reg.run()
        assert not d.exists()

    def test_non_recursive_leaves_filled_dir(self, tmp_path) -> None:
        d = tmp_path / "work"
        d.mkdir()
        (d / "user-file.txt").write_text("kept")
        reg = CleanupRegistry()
        reg.add_dir(str(d))
        reg.run()  # rmdir fails on non-empty dir, swallowed
        assert d.exists()
        assert (d / "user-file.txt").exists()

    def test_idempotent(self, tmp_path) -> None:
        f = tmp_path / "f"
        f.write_text("x")
        reg = CleanupRegistry()
        reg.add_file(str(f))
        reg.run()
        reg.run()  # must not raise

    def test_missing_file_is_silent(self) -> None:
        reg = CleanupRegistry()
        reg.add_file("/nonexistent/path/xyz")
        reg.run()  # must not raise

    def test_context_manager_runs_on_exit(self, tmp_path) -> None:
        f = tmp_path / "f"
        f.write_text("x")
        with CleanupRegistry() as reg:
            reg.add_file(str(f))
        assert not f.exists()
