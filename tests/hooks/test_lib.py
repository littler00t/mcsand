"""Hook protocol runner + helpers (§3-§4), incl. the fail-closed deviation."""

from __future__ import annotations

import io
import json

from mcsand.hooks import lib


def _run(evaluate, payload: str, *, parse: bool = True) -> str:
    out = io.StringIO()
    rc = lib.run_gate(
        evaluate,
        tool_name="Test",
        parse=parse,
        stdin=io.StringIO(payload),
        stdout=out,
        home="",  # disables logging side effects
    )
    assert rc == 0  # gates always exit 0
    return out.getvalue()


class TestExpandHome:
    def test_leading_tilde(self) -> None:
        assert lib.expand_home("~/.ssh/id_rsa", "/h") == "/h/.ssh/id_rsa"
        assert lib.expand_home("~", "/h") == "/h"

    def test_no_change_for_absolute_or_embedded(self) -> None:
        assert lib.expand_home("/etc/passwd", "/h") == "/etc/passwd"
        assert lib.expand_home("a/~/b", "/h") == "a/~/b"


class TestProtocol:
    def test_allow_is_empty_stdout(self) -> None:
        assert _run(lambda data, home: None, '{"tool_input":{}}') == ""

    def test_block_emits_decision_json(self) -> None:
        out = _run(lambda data, home: "nope", '{"tool_input":{}}')
        assert json.loads(out.strip()) == {"decision": "block", "reason": "nope"}

    def test_empty_stdin_allows(self) -> None:
        # Empty input is a valid empty call, not garbage → allow.
        assert _run(lambda data, home: None, "") == ""


class TestFailClosed:
    def test_internal_error_blocks(self) -> None:
        def boom(data, home):
            raise RuntimeError("kaboom")

        out = _run(boom, '{"tool_input":{}}')
        decision = json.loads(out.strip())
        assert decision["decision"] == "block"
        assert "fail-closed" in decision["reason"]

    def test_malformed_json_blocks(self) -> None:
        out = _run(lambda data, home: None, "{not valid json")
        decision = json.loads(out.strip())
        assert decision["decision"] == "block"
        assert "fail-closed" in decision["reason"]

    def test_non_object_payload_blocks(self) -> None:
        out = _run(lambda data, home: None, "[1, 2, 3]")
        assert json.loads(out.strip())["decision"] == "block"

    def test_parse_false_ignores_bad_payload(self) -> None:
        # The env-only gate must not fail-closed on a malformed body.
        assert _run(lambda data, home: None, "garbage", parse=False) == ""
