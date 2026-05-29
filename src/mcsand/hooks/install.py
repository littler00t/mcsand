"""Install/merge the hook registration into Claude's ``settings.json`` (§6, §8).

The reference installer merged with ``jq '*'``, which **replaces** arrays and so
clobbers a user's existing ``permissions.deny`` / ``hooks`` entries (§8 warning).
Here arrays are merged **explicitly** (concatenate + order-preserving dedup), so
pre-existing user entries survive. ``--dry-run`` prints the merged result instead
of writing it; a write is atomic (temp file + replace) and ``chmod 600``.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, TextIO

from .settings import build_settings_fragment

__all__ = ["install_hooks", "merge_settings"]


def _merge(existing: object, fragment: object) -> object:
    """Recursively merge ``fragment`` into ``existing``.

    Dicts merge key-wise; lists concatenate with order-preserving dedup; scalars
    are taken from ``fragment``. This is the explicit array merge that ``jq '*'``
    fails to do (§8).
    """
    if isinstance(existing, dict) and isinstance(fragment, dict):
        out = dict(existing)
        for key, value in fragment.items():
            out[key] = _merge(existing.get(key), value) if key in existing else value
        return out
    if isinstance(existing, list) and isinstance(fragment, list):
        merged = list(existing)
        seen = {json.dumps(item, sort_keys=True) for item in existing}
        for item in fragment:
            marker = json.dumps(item, sort_keys=True)
            if marker not in seen:
                merged.append(item)
                seen.add(marker)
        return merged
    return fragment


def merge_settings(
    existing: dict[str, Any], fragment: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Merge the hooks fragment into an existing ``settings.json`` dict (pure)."""
    fragment = fragment if fragment is not None else build_settings_fragment()
    result = _merge(existing, fragment)
    assert isinstance(result, dict)
    return result


def install_hooks(claude_dir: str, *, dry_run: bool, out: TextIO) -> int:
    """Write/merge the hook registration into ``<claude_dir>/settings.json``."""
    settings_path = os.path.join(claude_dir, "settings.json")
    try:
        with open(settings_path, encoding="utf-8") as fh:
            existing = json.load(fh)
        if not isinstance(existing, dict):
            existing = {}
    except FileNotFoundError:
        existing = {}
    except ValueError:
        out.write(f"mcsand: {settings_path} is not valid JSON; refusing to overwrite.\n")
        return 1

    merged = merge_settings(existing)
    rendered = json.dumps(merged, indent=2) + "\n"

    if dry_run:
        out.write(rendered)
        return 0

    os.makedirs(claude_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="settings-", suffix=".json", dir=claude_dir)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(rendered)
    os.replace(tmp, settings_path)
    out.write(f"mcsand: installed security hooks into {settings_path}\n")
    return 0
