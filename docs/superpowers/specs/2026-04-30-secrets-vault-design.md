# `secrets` — local-first secrets vault for macOS

> **Note (post-M1):** Project renamed to `stowe`. See commit `f8a82b8`. This document preserves the original wording for historical reference; M2+ docs use `stowe`.

**Status:** Design (brainstorm complete, awaiting user spec review)
**Date:** 2026-04-30
**Working directory:** `/Users/vasanth/Developer/tryouts/secret` (empty git repo)

---

## 1. Problem

Most projects use `.env` files for API keys, DB passwords, OAuth tokens. That has three real risks:

1. **Plaintext on disk.** Anyone with read access to the home folder (malicious npm package, screen-share, leaked backup, stolen laptop without FileVault) gets every key in every `.env`.
2. **Accidental commits.** `.env` slips past `.gitignore`, ends up in git history, then on GitHub. Even after rotation, the old key is permanently public.
3. **Shell-rc baking.** People sync `~/.zshrc` to dotfile repos with `export OPENAI_API_KEY=...` baked in. Same problem at scale.

1Password solves (1) and (2) but it is paid, cloud-based, and does not actually defend against the most common 2025-era threat: **a malicious dependency that reads env vars at runtime**. We want something open-source, local-only (macOS Keychain), and meaningfully *more* secure for this specific threat than 1Password's `op run`.

## 2. Goals

- **Local-only.** Secrets live in the macOS Keychain; never leave the device.
- **Run-scoped exposure by default.** No `cd`-triggered shell-wide loading. Vars exist for the lifetime of one child process.
- **Defense against malicious dependencies.** Per-binary ACL + optional `sandbox-exec` profile. A `postinstall` script cannot exfiltrate secrets even if it reads the env.
- **Touch ID per access.** Each batch of reads requires biometric or device passcode.
- **Auditable.** SQLite log of every access (binary, hash, time, outcome).
- **CLI-first, GUI-rich.** A single binary serves both; the GUI is a viewer/editor over the same operations.
- **Open-source, single-user, single-Mac.**

## 3. Non-goals (v1)

- Cross-platform (Linux/Windows). Keychain is Apple-specific. Adding a portable backend (libsecret, Windows Credential Manager) is a 2–3x scope expansion.
- Cloud sync across devices. By design — anything that leaves the Secure Enclave is out.
- Team / multi-user secret sharing. Single user only. Future work.
- Browser-extension auto-fill, SSH-agent integration, secret references inside arbitrary files.
- "Session" mode where Touch ID unlocks for N minutes (1Password-style). Considered a meaningful weakening of the security model. Re-evaluate post-v1.

## 4. Threat model

### What this design protects against

| Threat | Defense |
|---|---|
| Stolen laptop, disk image, leaked backup | Keychain encrypted at rest, key derived from login password, never leaves Secure Enclave |
| Accidental `git add .` | `.envrc`/`.env` are gone; the only committable file is `secrets.toml` which contains zero secret material |
| Malicious VS Code extension scanning `~` | No plaintext to grep |
| Random binary calling `SecItemCopyMatching` | Keychain partition list rejects every binary except our signed `secrets` |
| Malicious npm `postinstall` reading env vars | (a) secrets only present during `secrets run`, not in the surrounding shell; (b) optional sandbox blocks outbound network so values cannot be shipped out |
| Time-of-check / time-of-use binary swap | Open-fd-then-verify-then-`fexecve` pattern |
| `node_modules/.bin/fake-npm` shadowing real `npm` | Codesign verification + path/inode pinning |

### What it does NOT protect against (honest limits)

- A malicious binary that *is* the allowed binary (compromised upstream `npm`, malicious code committed to your own repo). Trust must terminate somewhere; we terminate at "the codesigned binary you opted into".
- A child of `secrets run -- ...` reading env from its own memory and exfiltrating *over an allowed network destination*. If `registry.npmjs.org` is on the sandbox allowlist and the attacker uses npm's own publish API as a covert channel, we lose. Not solvable in userspace.
- A user typing `secrets run -- bash` and then running everything in that shell. We refuse shells by default (`--allow-shell` opt-in) but cannot force discipline.
- The user revealing values into a clipboard manager that persists clipboard history.

## 5. Architecture

```
                ┌─────────────────────────────────────────────┐
                │  secrets (single Rust binary)               │
                │                                             │
  $ secrets add ─┼──► CLI dispatcher ──┐                       │
                │                      │                       │
  $ secrets ui ──┼──► Tauri webview ──┐│                       │
                │  (TS frontend)     ││                       │
                │                    ▼▼                       │
                │              ┌──────────────┐               │
                │              │  Core crate  │               │
                │              │              │               │
                │              │  - Vault     │  ───► macOS Keychain (Security.framework)
                │              │  - Policy    │       per-item ACL + biometric flag
                │              │  - Audit     │  ───► ~/Library/Application Support/secrets/audit.db
                │              │  - Runner    │  ───► spawns child with env / sandbox-exec
                │              └──────────────┘               │
                └─────────────────────────────────────────────┘
```

### Crate layout

- `secrets-core` — library. Keychain I/O, policy/ACL, audit log, sandbox profile generation, run-scoped child spawning. Zero UI dependencies. Most code lives here.
- `secrets-cli` — thin binary. `clap`-based argument parsing, calls into core.
- `secrets-ui` — Tauri shell. Bridges TS frontend to core via Tauri commands. Same binary as CLI; `secrets ui` opens the window.

### Why one binary, why a separate core crate

- **One binary** simplifies distribution (`brew install secrets`), shares code without IPC, and prevents UI/CLI behavioral drift on security-sensitive paths.
- **Core as a library** lets us unit-test the security boundary against an in-memory `Vault` without touching macOS APIs or Tauri.

### Bounded external dependencies

- `security-framework` — Rust bindings to Apple's `Security.framework`.
- `tauri` v2 — desktop window.
- `clap` — CLI parsing.
- `rusqlite` — audit log.
- `age` — encrypted export format.
- `zeroize` — memory zeroing for secret values.
- `sandbox-exec` — system binary; we shell out with a generated profile, no Rust crate.

### Why Tauri (not Electron)

- Direct first-class access to Apple's Keychain and `LocalAuthentication` via `security-framework`. The Node ecosystem's standard wrapper (`keytar`) was archived in 2023; building a security tool on an unmaintained Keychain library is unacceptable.
- CLI and UI share **one Rust crate**. Electron would force either a Node-based CLI (slow startup, ugly install) or two implementations of security-critical code in different languages.
- ~10–15 MB bundle vs. ~100–150 MB for Electron.
- Cold-start `secrets ui` ≈ 100–300 ms vs. ~1–2 s.

## 6. Data model

Three storage locations, each with one job:

```
1. macOS Keychain (the vault)
   service = "secrets.<namespace>"
   account = "<VAR_NAME>"
   data    = secret value (bytes)
   ACL     = SecAccessControl flags + partition list

2. Per-project manifest      ─►  ./secrets.toml         (committable, no values)
3. Central registry          ─►  ~/Library/Application Support/secrets/
                                   ├── projects.toml    (namespace ↔ folder map)
                                   ├── audit.db         (SQLite append-only)
                                   └── config.toml      (defaults, UI prefs)
```

### Keychain item shape

We use macOS **Generic Password** items, with a `secrets.` service prefix to keep them distinguishable from `envchain.` items:

```
service:        secrets.cognis
account:        ANTHROPIC_API_KEY
data:           sk-ant-... (the value)
access:         SecAccessControl {
                  protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                  flags: kSecAccessControlBiometryAny
                       | kSecAccessControlOr
                       | kSecAccessControlDevicePasscode,
                }
partition list: ["teamid:XXXXXXXXXX"]   // 10-char Apple Team ID of our signed binary
```

- `...ThisDeviceOnly` prevents iCloud Keychain sync.
- Biometry-or-passcode = Touch ID prompt with passcode fallback.
- Partition list scoped to our signed binary's identity means random binaries get rejected by the OS *before* any prompt fires.

### `./secrets.toml` — per-project manifest (committable)

```toml
namespace = "cognis"

[vars]
ANTHROPIC_API_KEY = { required = true, description = "Anthropic API key" }
OPENAI_API_KEY    = { required = false }
DATABASE_URL      = { required = true }

[policy]
biometric        = "always"               # "always" = Touch ID prompt every read;
                                          # "never"  = Keychain ACL with no biometric flag
                                          # ("first-launch" cache mode deferred to v2)
allowed_binaries = ["cargo", "node", "npm", "pnpm"]
sandbox          = false                  # see [policy.sandbox] for allowlists

[policy.sandbox]
network_allow  = ["registry.npmjs.org", "github.com", "*.amazonaws.com"]
fs_write_allow = ["~/.npm", "~/Library/Caches"]
```

This replaces both `.envrc` and the tribal knowledge of "which env vars this project needs". It is safe and *encouraged* to commit.

### `projects.toml` — central registry

```toml
[[project]]
namespace  = "cognis"
path       = "/Users/vasanth/Developer/cognis"
last_used  = "2026-04-30T10:33:00Z"
```

Tracking file for the UI's "all projects" view. Source of truth is each project's `secrets.toml`. Rebuilt by scanning configured roots if it gets out of sync.

### `audit.db` — SQLite, append-only

```sql
CREATE TABLE accesses (
  id           INTEGER PRIMARY KEY,
  ts           TEXT NOT NULL,             -- ISO 8601
  namespace    TEXT NOT NULL,
  var_names    TEXT NOT NULL,             -- JSON array
  binary_path  TEXT NOT NULL,
  binary_hash  TEXT,                      -- sha256 of binary at access time
  pid          INTEGER,
  ppid         INTEGER,
  argv         TEXT,                      -- JSON array
  outcome      TEXT NOT NULL,             -- "allowed" | "denied" | "biometric_failed"
  reason       TEXT,
  duration_ms  INTEGER,                   -- filled on close-row update
  child_exit   INTEGER
);
CREATE INDEX idx_accesses_ts        ON accesses(ts);
CREATE INDEX idx_accesses_namespace ON accesses(namespace);
```

Open/close pattern: `secrets run` writes a row at start, updates the same row on child exit. `secrets wipe --audit` writes its own deletion row, fsyncs, then truncates.

## 7. Run-scoped execution

Walking through `secrets run -- npm install`:

```
1. LOAD MANIFEST
   Walk ancestors from cwd looking for secrets.toml.
   Parse → namespace, vars, policy.

2. RESOLVE TARGET BINARY
   which("npm") → /opt/homebrew/bin/npm
   Open the file (O_RDONLY | O_CLOEXEC) — pin it by fd from now on.
   Check basename ∈ allowed_binaries.
   Verify codesign on the open fd (SecStaticCodeCreateWithPath against
   inode, or `codesign -dvvv` shell-out as fallback).
   Refuse if path is inside any excluded build dir (default list:
   node_modules/, .venv/, target/, build/, dist/, .next/; configurable
   via config.toml).
   Compute sha256 for audit.

3. UNLOCK SECRETS
   For each var in manifest:
     SecItemCopyMatching with one shared LAContext.
   → ONE Touch ID prompt for the batch.
   On denial: log denial row, exit 2.

4. AUDIT-LOG OPENING
   INSERT row with outcome="allowed", duration_ms=NULL.

5. SPAWN CHILD
   env = current_env ∪ secret_vars (overwriting collisions).
   If policy.sandbox:
     Generate profile to /tmp/secrets-<pid>.sb (mode 0600).
     fexecve sandbox-exec with -f profile and argv.
   Else:
     fexecve(fd, argv, env).
   Forward SIGINT/SIGTERM.

6. AUDIT-LOG CLOSING
   UPDATE the row with duration_ms and child_exit.
   Zeroize the env vector in our memory.
   Exit with the child's exit code.
```

### Per-binary ACL

Two layers:
- **Path basename + location.** Manifest declares `["npm", "node"]`; resolved binary's basename must match, and it must not live in `node_modules/`, `.venv/`, or build trees.
- **Code signature verification.** Either signed by Apple, signed by an explicitly trusted team ID, or hash-pinned in the manifest. Unsigned binaries refused unless the project sets a `--allow-unsigned` opt-in flag.

These run *before* the env injection step. A denial is loud: stderr explains exactly which check failed, and the audit row records `outcome="denied"`.

### The honest limit: child inheritance

Once `npm` runs with secrets in its env, every subprocess inherits — `node`, `node-gyp`, postinstall scripts. This is the OS process model; userspace cannot change it.

Two mitigations:
- **Time-bounded.** Vars exist only while the run is alive.
- **Sandbox option.** `policy.sandbox = true` runs the child under `sandbox-exec` with a generated profile that blocks outbound network except to allowlist. A malicious postinstall can `printenv` all it wants — it can't ship the values anywhere.

### Sandbox profile (generated)

Paths and hostnames below are illustrative; real values come from the manifest's `[policy.sandbox]` table and the project root's canonical path.

```scheme
(version 1)
(deny default)

(allow process-fork)
(allow process-exec)
(allow signal (target self))

(allow file-read*)
(allow file-write*
  (subpath "/Users/vasanth/Developer/cognis")
  (subpath "/private/tmp")
  (subpath "/Users/vasanth/.npm")
  (subpath "/Users/vasanth/Library/Caches"))

(allow network-outbound
  (remote tcp "registry.npmjs.org:443")
  (remote tcp "*.amazonaws.com:443"))
(deny network-outbound)
(deny mach-lookup)
```

User-supplied hostnames are validated against `^[a-zA-Z0-9.\-*]+$` before being splatted into the profile (prevent profile-syntax injection).

### Shell escape hatch

If the resolved binary is a known shell (`bash`, `zsh`, `fish`, `sh`, `dash`, `nu`), refuse unless `--allow-shell` is passed. The audit row marks it loudly.

### Failure modes

| Situation | Behavior |
|---|---|
| `secrets.toml` missing | Error: "no manifest in this directory or ancestors" |
| Required var not in Keychain | Interactive prompt to set it; in non-TTY contexts, error |
| Touch ID denied / failed 3x | Falls back to passcode; on full denial, audit row + exit 2 |
| Binary not in allowlist | Refuse with explicit reason; audit row records resolved path |
| Binary signature mismatch | Refuse; UI offers a "trust this binary" dialog with codesign details |
| Sandbox profile blocks an action | Child exits non-zero; sandbox violation captured in audit row |
| User Ctrl-C during run | Forward SIGINT to child; on child exit, zeroize env + write close row |

## 8. UI surface

Six screens, each backed by a Tauri command that calls `secrets-core`. Nothing in the UI does work the CLI cannot do.

### 8.1 — Vault (main window)

Project list with inline policy summary; `[+ Add project]`; `[⌘K Search]`; recent-accesses strip showing the last few audit rows. Denials styled red and clickable into the audit detail.

### 8.2 — Project detail

Per-project view with three sections: variables (set/unset/reveal/edit/delete), policy (biometric, allowed_binaries, sandbox), activity sparkline. Editing policy here writes back to `./secrets.toml` with a confirmation dialog if the file is git-tracked (so the user knows there will be a diff in `git status`).

### 8.3 — Add / edit secret

Name + value form. Value field never echoes; submit triggers Touch ID, writes to Keychain, updates manifest schema (not value).

### 8.4 — Audit log

Filter by project / outcome / time range; full-text search on argv. Each row expands to show binary path, sha256, codesign identity, ppid chain, sandbox violations.

### 8.5 — Export

Encrypted backup (`age` format, default) with passphrase, or plaintext `.env` dump (gated by an explicit second confirmation). Per-project or whole-vault scope. File save via native dialog.

### 8.6 — Wipe

Two-factor confirm: typed phrase ("WIPE EVERYTHING") + Touch ID. Optionally also offers to delete every `secrets.toml` listed in the central registry. Audit-log self-deletion writes its own deletion row first.

### 8.7 — First-run onboarding

Welcome → permissions self-check (verifies the running binary is signed, displays team ID for user verification) → optional sample project (`~/secrets-demo` with one fake var) → optional envchain migration (detects `envchain.*` Keychain items, offers to convert).

### Reveal flow (security-relevant)

Default: clicking `[reveal]` triggers Touch ID and shows **only the last 4 characters** in a copy-on-click bubble. A separate "show full value" action (also Touch-ID-gated) reveals the entire value with a 30-second clipboard auto-clear *and* an explicit warning that clipboard managers (Alfred, Maccy, Raycast) often persist history. This is a partial mitigation, not a fix; we tell the user that.

### Design language

Native macOS feel via Tauri's WKWebView: SF Pro fonts, native menu bar, system traffic-light buttons, native `NSAlert` modal dialogs for destructive actions, dark/light mode tracking. No web-app aesthetic. Keyboard-first: ⌘K search, ⌘N add, ⌘E export, ⌘, settings.

### Menu-bar icon (deferred to v2)

A status-bar icon for live audit notifications and a one-click "wipe panic" button is desirable but not a v1 requirement. Re-evaluate after the main window ships.

## 9. Testing strategy

| Layer | How we test it |
|---|---|
| `secrets-core` logic (vault, policy, manifest) | Unit tests against an in-memory `Vault` trait fake. No macOS APIs. |
| Real Keychain I/O + ACL flags | Integration tests in a dedicated test namespace `secrets.test.<rand>`. `#[ignore]` so CI default skip; `cargo test --ignored` runs locally. Each test cleans up its own items. |
| Codesign verification | Test fixtures: known-signed binary (`/usr/bin/git`), known-unsigned binary (compiled from `testdata/`), relocated copy (path mismatch). |
| Sandbox profile generation | (1) Snapshot tests for generated `.sb` text. (2) E2E: a `canary` binary that tries `printenv`, writes to `/etc`, curls `example.com`. Assert sandbox permits/denies the right ones. |
| Run-scoped lifecycle | Spawn `/bin/echo`, `/bin/sh -c …`. Assert env contents, exit code, Ctrl-C propagation, audit open/close rows. |
| Manifest / TOML / age parsers | `cargo-fuzz` on each parser. |
| Tauri UI | WebDriver-driven smoke tests: add var → reveal → export → wipe. |

### Pre-flagged correctness traps

- **Memory zeroing.** All secret values wrapped in `Zeroizing<Vec<u8>>` from Keychain read until env injection. Audit every code path.
- **TOCTOU on target binary.** Resolve → open fd → verify on fd → `fexecve`. Never re-resolve by path between verify and exec.
- **Symlink resolution.** Canonicalize paths before codesign check.
- **Sandbox profile injection.** User-supplied hostnames validated to `[a-zA-Z0-9.\-*]+` before substitution.
- **Audit log self-deletion ordering.** Wipe row written and fsynced *before* table truncation.

## 10. Build milestones

Estimates are indicative for relative sizing, not commitments.

```
M1: Skeleton + minimal CLI       [~5 days]
    • Cargo workspace: secrets-core, secrets-cli, (secrets-ui stub)
    • Vault trait + InMemoryVault + KeychainVault
    • CLI: add, list, reveal (no ACLs, no manifest yet)
    • Unit tests against InMemoryVault
    Ship state: usable as an envchain replacement.

M2: Run-scoped execution         [~5 days]
    • secrets.toml parser, ancestor-walk discovery
    • secrets run -- <cmd>: env inject, signal forwarding, exit codes
    • Audit log: SQLite schema, open/close pattern, zeroize on exit
    Ship state: secrets run works end-to-end without ACL hardening.

M3: ACL & per-binary hardening   [~7 days]
    • SecAccessControl with biometric flag
    • Partition list scoped to our signed bundle ID
    • allowed_binaries: codesign verify, hash pin, denial audit row
    • TOCTOU-safe binary resolution (open-then-verify-then-exec)
    • Integration tests against real Keychain (--ignored gate)
    Ship state: meaningfully more secure than `.env` / `op run`.

    ── PUBLIC v0.1 SHIP TARGET ──
    Cut a `secrets-cli` v0.1 here for dogfooding before UI work.

M4: Sandbox                      [~5 days]
    • Profile generator (manifest → .sb text)
    • Network/fs allowlist
    • Canary E2E test fixture
    Ship state: optional sandbox=true blocks postinstall exfil.

M5: Tauri UI                     [~10 days]
    • Vault, project detail, add/edit, reveal, audit, export, wipe
    • Touch ID flows, clipboard auto-clear with last-4 default
    • WebDriver smoke tests
    Ship state: GUI complete.

M6: Distribution & onboarding    [~5 days]
    • Code signing + notarization (Developer ID)
    • Onboarding wizard, envchain migration, sample project
    • Homebrew tap (`brew install secrets`)
    Ship state: friend can install and use it.
```

Total: ~37 working days of focused effort. Realistically 8–10 weeks with macOS-specific debugging.

### Hard floor

**M1 + M2 + M3.** Below this, no reason to switch from envchain.

### Cuttable from v1 if scope explodes (in priority order)

1. **M5 — Tauri UI.** Ship CLI-only first.
2. **M4 — Sandbox.** ACL + biometric alone are already a real upgrade.
3. **Onboarding migration from envchain.** Manual migration is acceptable for v1.
4. **`secrets export`/`import`.** Time Machine backs up Keychain.

## 11. Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Form factor | Tauri (Rust + TS) single binary | Best macOS-API integration, shared code, small bundle |
| Storage backend | macOS Keychain direct | Need ACL/Touch ID control envchain doesn't expose |
| Exposure model | Run-scoped by default | Tightens blast radius vs. direnv-style auto-load |
| Biometric | Touch ID per access (always/never modes for v1) | First-launch caching is a security weakening; defer to v2 |
| Per-binary ACL | Yes — basename + location + codesign | Catches `node_modules/.bin/fake-npm` attacks |
| Sandbox | Optional, default off | Killer feature but breaks tools first time; opt-in |
| Manifest | Committable `./secrets.toml` | Solves "which keys does this need" handoff |
| Partition list | Scoped to signed binary | Requires we ship a properly signed/notarized app |
| Shell escape | Refuse by default; `--allow-shell` opt-in | Prevent accidental return to convenience-mode |
| Manifest UI editing | Yes, with git-tracked-file confirm | Convenience worth the diff-noise risk |
| Reveal default | Last-4 only; full-reveal needs second action | Mitigate clipboard-history persistence |
| Menu-bar icon | v2 | Not required for the core flow |
| CLI-only ship cut | After M3, before M5 | Real dogfooding before UI investment |
| Cross-platform | Out of scope for v1 | 2–3x scope expansion; defer |

## 12. Open questions to revisit during implementation

1. **Codesign trust list.** Do we ship a built-in allowlist (Apple, Homebrew, popular dev teams) or require explicit per-binary opt-in? Implementation will surface real-world friction here.
2. **`first-launch` biometric mode.** Should we re-evaluate adding it for v1 if user testing shows always-prompt is unacceptable?
3. **Audit-log size cap.** Unbounded growth eventually matters. Default rotation policy (90 days? 100k rows?) to be picked once we see real usage.
4. **Distribution before signing.** M1–M3 ship as `cargo install`. Signing/notarization is M6. The partition list ACL requires a signed binary — do we relax to "no partition list" for the unsigned dev-cut and document the gap?

---

*Next step: writing-plans skill produces the implementation plan from this spec.*
