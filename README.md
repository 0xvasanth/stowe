# stowe

Local-first secrets vault for macOS, backed by the system Keychain.

[![CI](https://github.com/0xvasanth/stowe/actions/workflows/ci.yml/badge.svg)](https://github.com/0xvasanth/stowe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Status: pre-1.0.** All eight planned milestones (`m1`–`m6a`) are tagged.
> Code signing & notarization (full M6) are still pending an Apple Developer
> account; without that, biometric Keychain ACL items can't be created.

## Why

`.env` files in projects have three real problems:

1. **Plaintext on disk.** Anyone with read access to your home folder
   (a malicious npm package's `postinstall`, a screen-share, a leaked backup,
   a stolen laptop without FileVault) gets every key in every `.env`.
2. **Accidental commits.** `.env` slips past `.gitignore`, ends up in git
   history, then on GitHub. Even after rotation the old key is permanent.
3. **Shell-rc baking.** Synced `~/.zshrc` files end up with
   `export OPENAI_API_KEY=...` in dotfile repos.

`stowe` fixes all three by keeping secrets in the macOS Keychain (encrypted
at rest, key bound to your login + Secure Enclave on Apple Silicon),
exposing them only as env vars in the lifetime of one child process,
recording every access in a SQLite audit log, and (optionally) running that
child under `sandbox-exec` so a malicious dependency can't ship the secrets
out over an unallowed host.

## Install (dev)

```bash
git clone https://github.com/0xvasanth/stowe
cd stowe

# Build the GUI frontend (required even for CLI-only use, because
# `stowe ui` embeds it via Tauri's compile-time macro).
cd crates/stowe/web && bun install && bun run build && cd -

cargo install --path crates/stowe
```

## Quickstart

### Store a secret

```
$ stowe add cognis ANTHROPIC_API_KEY
Value for stowe.cognis/ANTHROPIC_API_KEY: ********
stored stowe.cognis/ANTHROPIC_API_KEY (biometric: Never)
```

### Declare it in your project

`stowe.toml` (committable, no values):

```toml
namespace = "cognis"

[vars]
ANTHROPIC_API_KEY = { required = true }
OPENAI_API_KEY    = { required = false }

[policy]
allowed_binaries = ["cargo", "node", "npm"]

[policy.sandbox]
enabled        = true
network_allow  = ["registry.npmjs.org", "api.anthropic.com"]
fs_write_allow = ["~/.npm", "~/Library/Caches"]
```

### Run a command with secrets injected

```
$ stowe run cargo run
# Equivalent to: ANTHROPIC_API_KEY=... cargo run
# but the value never lives in your shell's env, only in the child's.
```

If `policy.sandbox.enabled = true`, the child runs under `sandbox-exec`
and can't write to `/private/etc`, exfiltrate via `curl evil.com`, or
shadow `npm` from `node_modules/.bin`.

### Audit what happened

```
$ sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "SELECT ts, namespace, var_names, outcome FROM accesses ORDER BY id DESC LIMIT 5;"
```

### Open the desktop app

```
$ stowe ui
```

Native Tauri 2 window. Browse namespaces, view variable lists, reveal
values (last-4 by default, full-reveal with 30-second clipboard auto-clear),
add / delete secrets, export to encrypted `.age` backup, wipe everything
behind a typed-phrase confirm. Live audit feed at the bottom polls every
5 seconds.

## CLI reference

| Command | What it does |
|---|---|
| `stowe add [--biometric=never\|always] <ns> <var>` | Store a secret. Prompts for value (hidden). |
| `stowe list [<ns>]` | List namespaces (or vars in a namespace). |
| `stowe reveal <ns> <var>` | Print a secret to stdout. |
| `stowe run [--] <cmd> [args...]` | Run `cmd` with declared secrets injected as env vars. |
| `stowe ui` | Open the desktop app. |

## Architecture

Two-crate Cargo workspace (`stowe-core` library + `stowe` binary). The
`stowe` binary is one executable that handles both CLI subcommands and
the Tauri desktop window.

```
                   ┌──────────────────────────────┐
                   │  stowe (single binary)       │
                   │                              │
  $ stowe add ─────┼─► CLI dispatcher ──┐         │
                   │                    │         │
  $ stowe ui  ─────┼─► Tauri webview ──┐│         │
                   │  (TS frontend)   ▼▼          │
                   │            ┌───────────┐     │
                   │            │ Core lib  │     │
                   │            │  • Vault  │ ─► macOS Keychain
                   │            │  • Audit  │ ─► SQLite (~/Library/Application Support/stowe/)
                   │            │  • Sandbox│ ─► /usr/bin/sandbox-exec
                   │            │  • Runner │ ─► spawn child + audit row
                   │            └───────────┘     │
                   └──────────────────────────────┘
```

## Milestones

The `m*` git tags mark shippable cuts:

| Tag | What it added |
|---|---|
| `m1` | Skeleton + minimal CLI (`add`, `list`, `reveal`) |
| `m2` | `stowe run` + manifest parser + SQLite audit log |
| `m3` | `[policy]` section, codesign verification, biometric flag, denial audit (dev-cut) |
| `m4` | `sandbox-exec` profile generator + runner integration |
| `m5a` | Tauri 2 read-only desktop UI (Vault list + Project detail + Audit feed) |
| `m5b` | UI edit flows: Reveal (last-4 + clipboard auto-clear), Add, Delete |
| `m5c` | Export (age + plaintext) + Wipe (two-factor confirm) |
| `m6a` | Distribution polish: LICENSE, Cargo metadata, GitHub Actions CI, Homebrew formula draft |

Pending: full M6 (code signing + notarization + real `.icns` + partition
list activation). Requires an Apple Developer account.

## Threat model

`stowe` defends against:

- **Stolen laptop / leaked backup** — Keychain is encrypted; key bound to
  login password (and Secure Enclave on Apple Silicon).
- **Accidental git commit** — only `stowe.toml` (zero secret material) is
  committable.
- **Malicious extension / shell history grep** — no plaintext on disk.
- **Malicious npm `postinstall`** — `policy.sandbox` blocks writes outside
  the project + outbound network outside the allowlist, even though the
  child sees the env vars.
- **Binary swap (`node_modules/.bin/fake-npm`)** — codesign verification +
  excluded-build-dir check refuses.

`stowe` does **not** defend against:

- A malicious binary that *is* on your `allowed_binaries` list.
- A child reading its env and exfiltrating *over an allowed network host*
  (covert channel through `npmjs.org` etc.).
- A user typing `stowe run -- bash` and running everything from that
  shell. (Use `--allow-shell` opt-in in a future release.)

The trade-offs are documented per-milestone in
[`crates/stowe/SMOKE.md`](crates/stowe/SMOKE.md).

## Manual smoke tests

`crates/stowe/SMOKE.md` is the canonical end-to-end runbook. Each
milestone appends its scenarios. Click through them after a fresh build
to verify nothing regressed in user-facing behavior; the automated test
suite covers everything that doesn't need a real Keychain or Touch ID.

## Contributing

This is a personal project; PRs and issues welcome. CI runs `cargo fmt
--check`, `cargo clippy -D warnings`, and the non-ignored test suite on
macOS 14. Touch-ID and Keychain integration tests are gated behind
`#[ignore]` because they require a real user-facing Keychain that can't
be automated.

## License

MIT — see [`LICENSE`](LICENSE).
