"""Console entry point — delegates to the CLI and propagates the exit code."""

from __future__ import annotations

import sys

from mcsand.cli import main as _cli_main


def main() -> None:
    sys.exit(_cli_main())


if __name__ == "__main__":
    main()
