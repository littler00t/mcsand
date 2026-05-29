"""Temp-artifact lifecycle (design doc §2, §7).

The launcher creates up to three temp artifacts that must be removed when the
process ends however it ends: the SBPL profile (``chmod 600``), an optional
temp workdir (when launched from ``$HOME``), and an optional temp kubeconfig.

:class:`CleanupRegistry` owns their removal. Files are ``rm -f``'d; directories
are ``rmdir``'d **non-recursively** — a temp workdir the user filled is left
intact rather than wiped (§2). :meth:`run` is idempotent so the three safety
nets wired up in the CLI (context-manager ``__exit__``, ``atexit``, and the
SIGINT/SIGTERM handler) can all fire without double-removing or erroring.
"""

from __future__ import annotations

import contextlib
import os
from types import TracebackType

__all__ = ["CleanupRegistry"]


class CleanupRegistry:
    """Tracks temp files/dirs and removes them once, on exit."""

    def __init__(self) -> None:
        self._files: list[str] = []
        self._dirs: list[str] = []
        self._done = False

    def add_file(self, path: str) -> None:
        """Register a file for ``rm -f`` on cleanup."""
        self._files.append(path)

    def add_dir(self, path: str) -> None:
        """Register a directory for non-recursive ``rmdir`` on cleanup."""
        self._dirs.append(path)

    def run(self) -> None:
        """Remove all registered artifacts. Idempotent and never raises."""
        if self._done:
            return
        self._done = True
        for path in self._files:
            with contextlib.suppress(OSError):  # already gone / not removable — best effort
                os.unlink(path)
        for path in self._dirs:
            with contextlib.suppress(OSError):  # rmdir is non-recursive: filled workdir stays
                os.rmdir(path)

    def __enter__(self) -> CleanupRegistry:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.run()
