"""Read / Edit / Write path gates — block/allow cases (§5.2, §5.4, §5.5)."""

from __future__ import annotations

import pytest

from mcsand.hooks import edit_precheck, read_precheck, write_precheck

HOME = "/Users/alice"


def _read(path: str) -> str | None:
    return read_precheck.evaluate({"tool_input": {"file_path": path}}, HOME)


def _edit(path: str) -> str | None:
    return edit_precheck.evaluate({"tool_input": {"file_path": path}}, HOME)


def _write(path: str) -> str | None:
    return write_precheck.evaluate({"tool_input": {"file_path": path}}, HOME)


# --- Shared secret files blocked by all three gates. --------------------------
COMMON_BLOCK = [
    ".env",
    "~/.env.local",
    "/proj/.envrc",
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.gnupg/secring.gpg",
    "backup.gpg",
    "message.asc",
    "server.pem",
    "private.KEY",  # ci
    "cert.p12",
    "~/.netrc",
    "login.keychain",
    "login.keychain-db",
    "secrets.json",
    "credentials.yaml",
    "passwords.txt",
    "api_key.json",
    "vault.kdbx",
    "store.1pif",
]

COMMON_ALLOW = [
    "main.py",
    "README.md",
    "data.json",
    "/proj/src/app.ts",
    "environment.config",  # not a dotfile env
    "",  # empty → allow
]


@pytest.mark.parametrize("path", COMMON_BLOCK)
@pytest.mark.parametrize("gate", [_read, _edit, _write])
def test_common_secrets_blocked(gate, path: str) -> None:
    assert gate(path) is not None, path


@pytest.mark.parametrize("path", COMMON_ALLOW)
@pytest.mark.parametrize("gate", [_read, _edit, _write])
def test_common_safe_allowed(gate, path: str) -> None:
    assert gate(path) is None, path


# --- SSH: Read gates specific names; Edit/Write deny the whole dir. -----------
def test_read_ssh_specific_names() -> None:
    assert _read("~/.ssh/id_rsa") is not None
    assert _read("~/.ssh/authorized_keys") is not None
    assert _read("~/.ssh/config") is not None
    # A non-key file under ~/.ssh is allowed by the (precise) read gate.
    assert _read("~/.ssh/notes.txt") is None


def test_edit_write_ssh_whole_dir() -> None:
    for gate in (_edit, _write):
        assert gate("~/.ssh/id_rsa") is not None
        assert gate("~/.ssh/notes.txt") is not None  # whole dir denied for writes


# --- /etc: Read/Edit specific cred files; Write denies all of /etc. -----------
def test_etc_credential_files() -> None:
    for gate in (_read, _edit, _write):
        assert gate("/etc/shadow") is not None
        assert gate("/etc/sudoers") is not None


def test_etc_breadth_differs() -> None:
    assert _read("/etc/hosts") is None  # read: only specific cred files
    assert _write("/etc/hosts") is not None  # write: all of /etc


# --- Check 11 self-protection (Edit/Write only). ------------------------------
def test_self_protection_edit_write() -> None:
    for gate in (_edit, _write):
        assert gate("~/.claude/settings.json") is not None
        assert gate("~/.claude/hooks/security.sh") is not None
        assert gate("~/.claude/memory/note.md") is None  # other state stays editable


def test_self_protection_not_on_read() -> None:
    # Reading settings.json is not a check-11 concern (only edits/writes are).
    assert _read("~/.claude/settings.json") is None
