# mcsand — VS Code dev container image.
#
# Python 3.11 + uv is baked in here. Node 20 / npm are layered on via the
# devcontainer Node feature (see devcontainer.json) — NOT here, because the
# NodeSource one-liner does not reliably leave npm on PATH inside this base
# image. All npm-based tooling (claude-code, codex, ast-grep, qmd) is
# installed from post-create.sh.

FROM rust:1.95-bookworm AS rtk-builder

ARG RTK_VERSION=0.40.0
RUN cargo install rtk \
    --git https://github.com/rtk-ai/rtk \
    --tag "v${RTK_VERSION}" \
    --locked \
    --root /out

FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

# uv — used for the Python project (`uv run python -m mcsand`) and inline-script
# Python tools (`# /// script` blocks).
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv  /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx

# System packages.
# - sqlite3: handy CLI for poking sqlite databases during dev.
# - fish: project standard shell (see CLAUDE.md).
# - fd-find / ripgrep / jq / yq / less: project-required CLIs.
#
# NOTE: the MS python base image preconfigures a Yarn apt source whose GPG key
# has rotated, which makes `apt-get update` fail fatally. We don't need Yarn
# (npm comes from the Node feature), so drop the Yarn source before updating.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        procps \
        less \
        jq \
        yq \
        fd-find \
        ripgrep \
        fish \
        sqlite3 \
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*

# semgrep — pattern/dataflow static analysis (see CLAUDE.md "CLI Tools").
# Installed system-wide via uv so it lands on /usr/local/bin and avoids
# Debian's PEP 668 externally-managed restriction.
RUN uv pip install --system --no-cache semgrep

# rtk — agent runtime toolkit used by the local agent containers.
COPY --from=rtk-builder /out/bin/rtk /usr/local/bin/rtk
RUN rtk --version

# mq — markdown query CLI used to navigate large markdown docs (see CLAUDE.md
# "Markdown Navigation with `mq`"). The published .deb requires glibc 2.39 but
# bookworm ships 2.36, so we install the musl-static binary instead.
ARG MQ_VERSION=0.5.29
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) mq_arch=aarch64 ;; \
      amd64) mq_arch=x86_64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/mq \
      "https://github.com/harehare/mq/releases/download/v${MQ_VERSION}/mq-${mq_arch}-unknown-linux-musl"; \
    install -m 0755 /tmp/mq /usr/local/bin/mq; \
    rm /tmp/mq

USER vscode
ENV PATH="/usr/local/bin:${PATH}"

RUN set -eux; \
    jq --version >/dev/null; \
    yq --version >/dev/null; \
    mq --version >/dev/null; \
    rg --version >/dev/null; \
    semgrep --version >/dev/null; \
    rtk --version >/dev/null
