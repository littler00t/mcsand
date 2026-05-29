"""Build the ``settings.json`` fragment that wires the hooks (§6).

Pure: produces the ``permissions.deny`` glob set (§6.2, the fast/coarse first
line) and the hook registration (§6.1) whose commands invoke the Python gates
via ``python3 -m mcsand.hooks.<name>``. The deny globs are intentionally a strict
subset of the regex hooks — they exist for speed and UI visibility, while the
hooks are the authoritative, audited layer.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "DENY_GLOBS",
    "PRE_TOOL_GATES",
    "build_settings_fragment",
    "hook_command",
]

# matcher -> hook module (PreToolUse), in registration order (§6.1).
PRE_TOOL_GATES: tuple[tuple[str, str], ...] = (
    ("Bash", "bash_precheck"),
    ("Glob", "glob_precheck"),
    ("Read", "read_precheck"),
    ("Edit", "edit_precheck"),
    ("Write", "write_precheck"),
)

# permissions.deny globs (§6.2) — Claude's Tool(pattern) syntax.
DENY_GLOBS: dict[str, list[str]] = {
    "Bash": [
        "Bash(*--dangerously-skip-permissions*)",
        "Bash(*--no-verify*)",
        "Bash(* --force*)",
        "Bash(*--force *)",
        "Bash(* | bash*)",
        "Bash(* | sh*)",
        "Bash(* | zsh*)",
        "Bash(* | fish*)",
        "Bash(* | dash*)",
        "Bash(* | ksh*)",
        "Bash(* | csh*)",
        "Bash(* | tcsh*)",
        "Bash(rm -rf /*)",
        "Bash(rm -rf ~*)",
        "Bash(rm -rf $HOME*)",
        "Bash(rm -rf .ssh*)",
        "Bash(rm -rf .claude*)",
        "Bash(rm -rf .gnupg*)",
        "Bash(chmod 777 *)",
        "Bash(chmod 0777 *)",
        "Bash(chmod a+rwx *)",
        "Bash(chmod ugo+rwx *)",
    ],
    "Glob": [
        "Glob(~/.ssh/*)",
        "Glob(~/.ssh/**)",
        "Glob(~/.aws/*)",
        "Glob(~/.aws/**)",
        "Glob(~/.gnupg/*)",
        "Glob(~/.gnupg/**)",
        "Glob(**/.env)",
        "Glob(**/.env.*)",
        "Glob(**/.envrc)",
    ],
    "Edit": [
        "Edit(~/.ssh/*)",
        "Edit(~/.aws/*)",
        "Edit(~/.gnupg/*)",
        "Edit(**/.env)",
        "Edit(**/.env.*)",
        "Edit(**/.envrc)",
    ],
    "Read": [
        "Read(**/.env)",
        "Read(**/.env.*)",
        "Read(**/.envrc)",
        "Read(~/.ssh/*)",
        "Read(~/.aws/credentials)",
        "Read(~/.aws/config)",
        "Read(~/.gnupg/*)",
        "Read(~/.netrc)",
        "Read(/etc/shadow)",
        "Read(/etc/gshadow)",
        "Read(/etc/sudoers)",
        "Read(**/*.pem)",
        "Read(**/*.key)",
        "Read(**/*.p12)",
        "Read(**/*.pfx)",
        "Read(**/*.kdbx)",
    ],
    "Write": [
        "Write(~/.ssh/*)",
        "Write(~/.aws/*)",
        "Write(~/.gnupg/*)",
        "Write(**/.env)",
        "Write(**/.env.*)",
        "Write(**/.envrc)",
        "Write(~/.netrc)",
        "Write(/etc/*)",
        "Write(~/.claude/settings.json)",
        "Write(~/.claude/hooks/*)",
    ],
}


def hook_command(module: str) -> str:
    """The shell command Claude runs for a gate module."""
    return f"python3 -m mcsand.hooks.{module}"


def _entry(module: str, matcher: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"hooks": [{"type": "command", "command": hook_command(module)}]}
    if matcher is not None:
        entry["matcher"] = matcher
    return entry


def build_settings_fragment() -> dict[str, Any]:
    """Build the full ``settings.json`` fragment (hooks + permissions.deny)."""
    deny: list[str] = []
    for matcher, _module in PRE_TOOL_GATES:
        deny += DENY_GLOBS.get(matcher, [])

    return {
        "permissions": {"deny": deny},
        "hooks": {
            "PreToolUse": [_entry(module, matcher) for matcher, module in PRE_TOOL_GATES],
            "PostToolUse": [_entry("scan", "Bash")],
            "UserPromptSubmit": [_entry("sandbox_precheck")],
        },
    }
