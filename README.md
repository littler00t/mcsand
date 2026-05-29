# mcsand — macOS Claude Code Sandbox

`mcsand` runs [Claude Code](https://claude.com/claude-code) inside the macOS
**Seatbelt** sandbox (`sandbox-exec`). It generates a fresh, per-launch policy
that is **allow-by-default** but subtracts four targeted capabilities:

1. **Writes** are denied everywhere, then re-allowed for a small explicit set
   (your project dir, Claude's own state/caches, the login Keychain, system temp,
   std devices, and any directories you opt in).
2. **Reads** are denied everywhere (v2 — deny-by-default), then re-allowed for the
   system roots Claude needs to boot (`/System`, `/private`, `/usr`, …, the `/`
   root + the `/etc` `/tmp` `/var` symlinks), the resolved `claude` binary dir, and
   a short in-`$HOME` list. The rest of `$HOME`, other users under `/Users`, and all
   of `/Volumes` are unreadable; the `/System/Volumes/Data` firmlink alias is denied.
3. Claude's own **security hooks and `settings.json` are write-denied** even
   though they live under the otherwise-writable `~/.claude` (tamper-proofing).
4. **Inspecting other processes** is denied — both the `proc_info` syscalls and
   Mach task-port acquisition — so a compromised session cannot dump
   `ssh-agent` / `gpg-agent` / password-manager memory.

It does this without a mount namespace (macOS has none): files keep their real
paths, and every rule is matched against the **kernel-canonical** path. A second,
optional layer — the Claude Code **security hooks** (`mcsand install-hooks`) — adds
in-process PreToolUse/PostToolUse gates on top.

> Inspect the exact policy any time with `mcsand print-profile`, and your resolved
> configuration with `mcsand doctor`.

## Requirements

- **macOS** to actually *launch* the sandbox (`sandbox-exec` is built in).
- Python ≥ 3.11 and [`uv`](https://docs.astral.sh/uv/).
- `claude` on your `PATH`.

> **Develop on Linux, target macOS.** All policy logic (path canonicalization,
> SBPL generation, env construction, config parsing) is pure and unit-tested on
> any platform. Only the behavioural sandbox tests require macOS. On non-macOS,
> `mcsand` refuses to *launch* but `print-profile`/`doctor`/`--dry-run` still work.

## Install / run

```fish
# From the repo
uv run python -m mcsand            # launch claude under the sandbox
# Or, once installed as a tool:
uv tool install .
mcsand                             # same thing
```

## Usage

```
mcsand [opts] [-- CLAUDE_ARGS…]    # default: sandbox + launch claude
mcsand run [opts] -- CMD [ARGS…]    # run any command under the same sandbox
mcsand shell [opts]                 # open $SHELL under the sandbox
mcsand print-profile [opts]         # render the SBPL profile to stdout, no launch
mcsand doctor                       # preflight checks, no launch
mcsand install-hooks [--dry-run]    # register the security hooks in settings.json
```

`run` and `shell` apply the **same** generated profile to an arbitrary program —
the launcher isn't hardwired to `claude`. Handy for poking at the sandbox or doing
sandboxed work in your own tools:

```fish
mcsand run -- tmux new -s work       # tmux under the sandbox
mcsand run --rw ~/scratch -- make    # a build with an extra writable dir
mcsand shell                         # an interactive shell (fish/zsh/…)
```

The launched binary's own directory is added to the read-allow set automatically,
so a tool installed outside the system roots (e.g. under `~/.nvm`) stays runnable.

Anything after `--` is passed straight through to the launched program (`claude` by
default):

```fish
mcsand -- --resume
mcsand --rw ~/scratch -- --model opus
```

### Flags

Flags are convenience sugar; the environment variables below are the canonical
configuration and always work. Flags override them.

| Flag | Effect |
|---|---|
| `--rw DIR` | Add a read-write dir (repeatable). |
| `--ro DIR` | Add a read-only dir (repeatable). |
| `--block DIR` | Hard-deny a dir, read **and** write (repeatable). |
| `--workdir DIR` | Override the working directory (default `$PWD`). |
| `--sensitive VAR` | Also withhold this env var unless confirmed (repeatable; additive). |
| `-y`, `--yes` | Auto-accept every opt-in prompt (Docker, K8s, sensitive vars). |
| `--no-docker` | Never offer the Docker socket. |
| `--no-k8s` | Never mint a Kubernetes token. |
| `--k8s-role ROLE` | ClusterRole for the auto-provisioned SA (sugar for `CLAUDE_SANDBOX_K8S_ROLE`). |
| `--k8s-namespace NS` | Namespace for the RoleBinding (sugar for `CLAUDE_SANDBOX_K8S_NAMESPACE`). |
| `--cluster-wide` | Bind the SA cluster-wide (sugar for `CLAUDE_SANDBOX_K8S_CLUSTER_WIDE`). |
| `--k8s-lifetime DUR` | K8s token lifetime, e.g. `8h` (sugar for `CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME`). |
| `--dry-run` | Resolve everything and print the `sandbox-exec` command, but don't launch. |

### `print-profile` and `doctor`

- **`print-profile`** renders the exact policy that *would* be applied. Use it to
  audit what your project will expose, or to diff after changing options. This is
  the same code path the tests assert against.
- **`doctor`** reports your resolved configuration: whether `sandbox-exec`/`claude`
  are found, the Claude config dir, the working dir, detected `ssh-agent`/Docker/
  `kubectl`, any extra/blocked dirs and sensitive vars, the resolved `claude` binary,
  and whether the security hooks are installed.

## Configuration (environment variables)

| Variable | Effect |
|---|---|
| `CLAUDE_CONFIG_DIR` | Use this instead of `~/.claude` for state + tamper-proofing. |
| `CLAUDE_SANDBOX_ALLOWED_DIRS` | Colon-separated dirs granted **read-write** access. |
| `CLAUDE_SANDBOX_ALLOWED_RO_DIRS` | Colon-separated dirs granted **read-only** access. |
| `CLAUDE_SANDBOX_BLOCKED_DIRS` | Colon-separated dirs hard-denied (read + write), overriding allows. |
| `CLAUDE_SANDBOX_K8S_SA` | Use an existing ServiceAccount instead of auto-provisioning one. |
| `CLAUDE_SANDBOX_K8S_ROLE` | ClusterRole to bind (default prompt value `view`). Skips the role prompt. |
| `CLAUDE_SANDBOX_K8S_NAMESPACE` | Namespace for the RoleBinding. Skips the namespace (and scope) prompt. |
| `CLAUDE_SANDBOX_K8S_CLUSTER_WIDE` | Truthy ⇒ cluster-wide `ClusterRoleBinding`. Skips the scope prompt. |
| `CLAUDE_SANDBOX_K8S_TOKEN_LIFETIME` | Token lifetime (default `8h`). Skips the lifetime prompt and counts as opting in. |
| `CLAUDE_SANDBOX_K8S_IMPERSONATE` | `--as=…` for the kubectl provisioning/token calls. |
| `CLAUDE_SANDBOX_SENSITIVE_VARS` | Colon-separated env-var **names** to withhold unless confirmed (additive to the built-in `ANSIBLE_VAULT_PASSWORD`). |

Relative entries are resolved against `$PWD` and canonicalized; a path already
allowed can be re-added to widen access (last-match-wins). Reads are
**deny-by-default**: only the system roots Claude needs to boot, the resolved
`claude` binary dir, and a short in-`$HOME` list are readable — run
`mcsand print-profile` to see the exact set.

### Opt-in resources (prompted at startup)

- **Docker socket** — if `/var/run/docker.sock` exists you're asked whether to
  expose it (read-write) plus `~/.docker` (read-only). Accepting is effectively
  host-root; decline unless you need it.
- **Kubernetes** — if `$KUBECONFIG` is set and `kubectl` is on `PATH`, you're
  offered a short-lived, token-only kubeconfig minted **outside** the sandbox
  (your real kubeconfig and auth helpers are never exposed). Auto-provisioning is
  **least-privilege by default**: a single-namespace `RoleBinding` to the read-only
  `view` ClusterRole, widened only at the prompts (or via the env vars above). Any
  failure degrades gracefully — the launch proceeds without Kubernetes.

### Security hooks

`mcsand install-hooks` registers a second defence layer — the Claude Code
PreToolUse/PostToolUse gates (regex/glob checks on tool calls plus a post-download
ClamAV scan) — into `settings.json`, merging rather than clobbering your existing
entries. The gates are **fail-closed**: an unexpected error blocks rather than
silently allowing.

### Sensitive variables

Named sensitive variables are **withheld** from the sandbox unless you confirm
each at startup. The built-in default is `ANSIBLE_VAULT_PASSWORD`; add more
(additively — the default is always withheld) with `CLAUDE_SANDBOX_SENSITIVE_VARS`
(colon-separated names) or repeated `--sensitive VAR` flags:

```fish
set -x CLAUDE_SANDBOX_SENSITIVE_VARS AWS_SECRET_ACCESS_KEY:NPM_TOKEN
mcsand --sensitive GITHUB_TOKEN -- --resume
```

## Development

```fish
uv run pytest                       # full suite (macOS-only tests auto-skip elsewhere)
uv run pytest -m darwin             # behavioural sandbox tests (run on macOS, not nested)
uv run ruff check src tests
uv run ruff format src tests
uv run mypy src tests
```

The package is stdlib-only (no runtime dependencies).

## License

[MIT](LICENSE) © 2026 Hans Hansen.
