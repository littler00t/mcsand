#!/usr/bin/env bash
# Runs once after the dev container is built. Anything that needs npm or any
# devcontainer feature MUST live here, not in the Dockerfile.
set -euo pipefail

cd /workspace

# Named volumes mount as root by default; hand /home/vscode/.claude to the
# vscode user so claude-code can write credentials/settings.
echo "==> ensuring ~/.claude is owned by vscode"
sudo chown -R vscode:vscode /home/vscode/.claude || true

# QMD keeps its index under ~/.cache/qmd by default. Store that cache in the
# workspace so rebuilt dev containers can share it.
echo "==> linking qmd cache to /workspace/.qmd/cache"
mkdir -p /workspace/.qmd/cache
if [ -d /home/vscode/.cache/qmd ] && [ ! -L /home/vscode/.cache/qmd ]; then
  cp -a /home/vscode/.cache/qmd/. /workspace/.qmd/cache/
  rm -rf /home/vscode/.cache/qmd
fi
mkdir -p /home/vscode/.cache
ln -sfn /workspace/.qmd/cache /home/vscode/.cache/qmd
sudo chown -R vscode:vscode /workspace/.qmd /home/vscode/.cache || true

echo "==> configuring fish shell"
sudo chsh -s /usr/bin/fish vscode || true
mkdir -p /home/vscode/.config/fish/conf.d
ln -sfn /workspace/.devcontainer/fish/mcsand-aliases.fish \
  /home/vscode/.config/fish/conf.d/mcsand-aliases.fish

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "==> configuring repo git identity"
  git config user.name "Hans Hansen"
  git config user.email "janb@brunnert.de"
else
  echo "==> skipping git identity (not a git repo)"
fi

# claude-code goes here (not the Dockerfile): npm is only on PATH after the
# Node devcontainer feature has been applied on top of the built image.
echo "==> installing claude-code globally (inside container)"
npm install -g @anthropic-ai/claude-code

echo "==> installing codex globally (inside container)"
npm install -g @openai/codex

# ast-grep CLI — provides `sg` (and `ast-grep`) for AST-aware code search
# (see CLAUDE.md "Code Search Tool Selection"). The npm package installs both
# binaries into the Node feature's bin dir, which precedes /usr/bin on PATH so
# `sg` shadows Debian's `newgrp` alias.
echo "==> installing ast-grep CLI globally (inside container)"
npm install -g @ast-grep/cli

# bun — runtime required by qmd. Install for the vscode user, then symlink to
# /usr/local/bin so it's discoverable from non-interactive shells (qmd shells
# out to `bun`).
if ! command -v bun >/dev/null 2>&1; then
  echo "==> installing bun (qmd runtime dependency)"
  curl -fsSL https://bun.sh/install | bash
  sudo ln -sf "$HOME/.bun/bin/bun" /usr/local/bin/bun
fi

# qmd — markdown search engine for doc/ (see CLAUDE.md "Documentation Search").
echo "==> installing qmd globally (inside container)"
npm install -g @tobilu/qmd

# Bootstrap the `doc` collection if doc/ exists and the collection is missing,
# then refresh embeddings. `qmd collection add` is idempotent-ish: skip when
# the collection already exists so rebuilds don't error out.
if [ -d /workspace/doc ]; then
  if ! qmd collection list 2>/dev/null | grep -q "^doc\b"; then
    echo "==> initializing qmd 'doc' collection"
    qmd collection add /workspace/doc --name doc --mask "**/*.md"
  fi
  echo "==> refreshing qmd index + embeddings (may take a minute on first run)"
  qmd update
  qmd embed
else
  echo "==> skipping qmd doc collection bootstrap (no /workspace/doc yet)"
fi

# Sync the Python project at the repo root.
if [ -f pyproject.toml ]; then
  echo "==> syncing Python deps via uv"
  uv sync
fi

echo ""
echo "==> dev container ready"
echo "    Run     : uv run python -m mcsand"
echo "    Test    : uv run pytest"
echo "    Lint    : uv run ruff check ."
echo "    Format  : uv run ruff format ."
