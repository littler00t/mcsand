"""Claude Code security hooks (claude-hooks-design.md).

A second, in-process defence layer that complements the OS sandbox: regex/glob
pre-execution gates (PreToolUse), a post-download ClamAV scan (PostToolUse), and
a "must run in the sandbox" gate (UserPromptSubmit). Each gate is a small Python
module run by Claude Code via ``python3 -m mcsand.hooks.<name>``.

The matching logic lives in pure functions (``evaluate`` / ``decide`` /
``classify``) that are exhaustively unit-tested; :func:`mcsand.hooks.lib.run_gate`
is the thin stdin→stdout protocol shell around them.

**Deviation from the reference (by design):** the gates are **fail-closed** — an
unexpected internal error or a malformed (non-empty, non-JSON) payload emits a
``block``, rather than the reference's fail-open *allow*. A clean "no rule
matched" still allows (empty stdout).
"""
