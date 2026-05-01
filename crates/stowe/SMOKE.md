# `stowe` smoke test

End-to-end check that `stowe run` reads from the real macOS Keychain, injects
secrets into a child process, and writes an audit row.

## Requirements

- macOS (`security` and `sqlite3` are part of the base install)
- The repo built locally: `cargo build --bin stowe`

## What it verifies

1. `security add-generic-password` can seed Keychain items under `stowe.<ns>`.
2. `stowe run` walks up from cwd to find `stowe.toml`.
3. The runner reads each declared variable from the Keychain.
4. The child process sees those variables in its environment.
5. An audit row is written to `~/Library/Application Support/stowe/audit.db`
   with `outcome="allowed"` and the child's exit code.
6. Cleanup removes both the Keychain items and the audit row.

## Notes before running

The first time `target/debug/stowe` reads from the Keychain, macOS will show a
system dialog: **"stowe wants to use your confidential information stored in
'STOWE_TEST_FOO' in your keychain."** Click **Always Allow** (and again for
`STOWE_TEST_BAR`). The script blocks until the prompt is answered. Subsequent
runs in the same build are silent.

For unattended CI runs the binary needs to be signed and notarized
(planned for M6); until then this script is a manual verification step.

## Run

```bash
set -e
STOWE="$(pwd)/target/debug/stowe"

# Build (no-op if already built).
cargo build --quiet --bin stowe

NS="m2smoke.$(date +%s).$$"

# 1. Seed two Keychain items under our namespace.
security add-generic-password -U \
  -a "STOWE_TEST_FOO" -s "stowe.${NS}" -w "foo-value"
security add-generic-password -U \
  -a "STOWE_TEST_BAR" -s "stowe.${NS}" -w "bar-value"

# 2. Make a tempdir, drop a stowe.toml in it.
TMPDIR_M2=$(mktemp -d)
cat > "$TMPDIR_M2/stowe.toml" <<EOF
namespace = "$NS"

[vars]
STOWE_TEST_FOO = { required = true }
STOWE_TEST_BAR = { required = true }
EOF

# 3. Run the binary FROM the tempdir, exec'ing /bin/sh that asserts both vars.
( cd "$TMPDIR_M2" && \
  "$STOWE" run /bin/sh -c \
  '[ "$STOWE_TEST_FOO" = "foo-value" ] && [ "$STOWE_TEST_BAR" = "bar-value" ] && \
    echo "[smoke] PASS" && exit 0 || \
    (echo "[smoke] FAIL: foo=$STOWE_TEST_FOO bar=$STOWE_TEST_BAR" && exit 1)' )
SMOKE_EXIT=$?
echo "[smoke] runner exit code: $SMOKE_EXIT"

# 4. Verify an audit row exists.
AUDIT_DB="$HOME/Library/Application Support/stowe/audit.db"
sqlite3 "$AUDIT_DB" \
  "SELECT namespace, var_names, outcome, child_exit FROM accesses
   WHERE namespace = '$NS' ORDER BY id DESC LIMIT 1;"
# Expected: $NS|["STOWE_TEST_FOO","STOWE_TEST_BAR"]|allowed|0

# 5. Cleanup.
security delete-generic-password -a "STOWE_TEST_FOO" -s "stowe.${NS}" >/dev/null
security delete-generic-password -a "STOWE_TEST_BAR" -s "stowe.${NS}" >/dev/null
sqlite3 "$AUDIT_DB" "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M2"

if [ $SMOKE_EXIT -eq 0 ]; then echo "OVERALL: OK"; else echo "OVERALL: FAILED"; exit 1; fi
```

## Troubleshooting

- **`security add-generic-password` prompts for the login keychain password** —
  click "Always Allow" or run `security unlock-keychain` first.
- **`stowe run` hangs indefinitely** — there is a Keychain access prompt waiting
  on screen. Click it, or run via `Console.app` to see if any prompts are
  being suppressed.
- **`SecKeychainSearchCopyNext: not found` after cleanup** — expected; means
  the cleanup deletes worked.

---

## M3 additions: ACL & per-binary hardening

### Biometric flag (Touch ID)

**Dev-cut limitation:** `--biometric=always` calls `SecItemAdd` with a biometric
`SecAccessControl`, which requires the calling binary to be signed with
`keychain-access-groups` entitlements. Unsigned `target/debug/stowe` fails
with `errSecMissingEntitlement` (-34018). The default in M3 is therefore
`--biometric=never`; `always` will work once M6 ships proper signing.

```bash
NS="m3bio.$(date +%s)"
"$STOWE" add --biometric=never "$NS" PLAIN_TEST       # type: hello-plain
"$STOWE" reveal "$NS" PLAIN_TEST                       # no prompt; prints: hello-plain

# This will fail with errSecMissingEntitlement until M6:
"$STOWE" add --biometric=always "$NS" BIO_TEST
# Expected: keychain error: ... (code -34018)

security delete-generic-password -a "PLAIN_TEST" -s "stowe.${NS}"
```

### `allowed_binaries` denial

```bash
TMPDIR_M3=$(mktemp -d)
NS="m3deny.$(date +%s)"
cat > "$TMPDIR_M3/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allowed_binaries = ["cargo"]
INNER

cd "$TMPDIR_M3" && "$STOWE" run /bin/sh -c 'echo hi'
# Expected stderr: stowe: denied: binary "sh" not in allowed_binaries ["cargo"]
# Expected exit:   2

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "SELECT outcome, reason FROM accesses WHERE namespace = '$NS' ORDER BY id DESC LIMIT 1;"
# Expected: denied|binary "sh" not in allowed_binaries [...]

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M3"
```

### Unsigned-binary denial

```bash
TMPDIR_M3=$(mktemp -d)
NS="m3unsigned.$(date +%s)"
echo 'int main(){return 0;}' > "$TMPDIR_M3/hello.c"
/usr/bin/cc "$TMPDIR_M3/hello.c" -o "$TMPDIR_M3/hello"
/usr/bin/codesign --remove-signature "$TMPDIR_M3/hello" 2>/dev/null || true

cat > "$TMPDIR_M3/stowe.toml" <<INNER
namespace = "$NS"
INNER

cd "$TMPDIR_M3" && "$STOWE" run "$TMPDIR_M3/hello"
# Expected: stowe: denied: binary ".../hello" is not codesigned ...
# Exit 2

# Allow it explicitly:
cat > "$TMPDIR_M3/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allow_unsigned = true
INNER

cd "$TMPDIR_M3" && "$STOWE" run "$TMPDIR_M3/hello"
# Expected exit: 0

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M3"
```

### Excluded build directory

The runner refuses binaries inside `node_modules/`, `.venv/`, `venv/`,
`target/`, `build/`, `dist/`, `.next/` — even if they're in
`allowed_binaries`. Catches the malicious-postinstall pattern where
`./node_modules/.bin/fake-npm` shadows real `npm`.

```bash
TMPDIR_M3=$(mktemp -d)
NS="m3excluded.$(date +%s)"
mkdir -p "$TMPDIR_M3/node_modules/.bin"
cp /bin/sh "$TMPDIR_M3/node_modules/.bin/sh"

cat > "$TMPDIR_M3/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allow_unsigned = true
INNER

cd "$TMPDIR_M3" && "$STOWE" run "$TMPDIR_M3/node_modules/.bin/sh" -c 'exit 0'
# Expected: stowe: denied: binary "..." is inside excluded build directory node_modules/

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M3"
```

### Notes on M3 dev-cut

- **Partition list is not active** because `target/debug/stowe` is unsigned.
  Once M6 ships signing, partition-list scoping will activate and only
  `stowe` itself will be able to read items via Keychain APIs.
- **Biometric ACL items can't be created** from unsigned builds (M5's
  `set_with_biometric_always_persists_acl` test is gated on M6 for the
  same reason).
- **TOCTOU window** between `binary::verify` (codesign check) and
  `Command::spawn` (exec). Real but small; an attacker with same-user
  fs-write access could swap the binary in between. Deferred to a focused
  follow-up after M3.

---

## M4 additions: sandbox-exec wrapping

### Sandbox blocks out-of-allowlist file writes

```bash
TMPDIR_M4=$(mktemp -d)
NS="m4sandbox.$(date +%s)"
cat > "$TMPDIR_M4/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allow_unsigned = true

[policy.sandbox]
enabled = true
INNER

# Inside the sandbox, /bin/sh tries to write to /private/etc — should fail.
cd "$TMPDIR_M4" && "$STOWE" run /bin/sh -c \
  '(echo blocked > /private/etc/stowe-test 2>/dev/null) && echo "WROTE (BAD)" || echo "BLOCKED (OK)"'
# Expected stdout: BLOCKED (OK)

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M4"
```

### Sandbox allows writes inside project root

```bash
TMPDIR_M4=$(mktemp -d)
NS="m4sandbox-allow.$(date +%s)"
cat > "$TMPDIR_M4/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allow_unsigned = true

[policy.sandbox]
enabled = true
INNER

cd "$TMPDIR_M4" && "$STOWE" run /bin/sh -c 'echo ok > inside.txt && cat inside.txt'
# Expected stdout: ok

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M4"
```

### Network allowlist (manual; needs internet)

```bash
TMPDIR_M4=$(mktemp -d)
NS="m4sandbox-net.$(date +%s)"
cat > "$TMPDIR_M4/stowe.toml" <<INNER
namespace = "$NS"

[policy]
allowed_binaries = ["curl"]

[policy.sandbox]
enabled = true
network_allow = ["www.example.com"]
INNER

# Allowed host — should succeed.
cd "$TMPDIR_M4" && "$STOWE" run curl --silent --max-time 5 https://www.example.com >/dev/null && echo "OK"
# Expected: OK

# Disallowed host — should fail.
cd "$TMPDIR_M4" && "$STOWE" run curl --silent --max-time 5 https://www.google.com >/dev/null \
  && echo "GOT GOOGLE (BAD)" || echo "BLOCKED (OK)"
# Expected: BLOCKED (OK)

sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M4"
```

### Notes on sandbox-exec

- `sandbox-exec` is officially deprecated by Apple but still functional in
  every shipping macOS release through 15.x. M4 takes the deprecation as
  acceptable risk for v0.4. If a future macOS removes `sandbox-exec`, the
  fallback is either Endpoint Security framework or dropping sandbox
  support and recommending containers.
- The profile uses `(deny default)` then explicit allows. The default-deny
  covers anything not listed.
- `mach-lookup` and `sysctl-read` are broadly allowed because denying them
  breaks too many legitimate libc/dyld calls. We rely on the network and
  fs allowlists for the actual security gates.
- Binary lives at `/usr/bin/sandbox-exec` on current macOS (not `/usr/sbin/`
  as some older docs say).

---

## M5a additions: read-only desktop UI

### Launch the UI and verify the three views

Prereq: have at least one namespace populated. If you don't, add one quickly:
`"$STOWE" add demo MYKEY` (defaults to `--biometric=never`).

```bash
# 1. Build the frontend bundle.
( cd crates/stowe/web && bun install && bun run build )

# 2. Build the binary (with embedded Tauri).
cargo build --bin stowe

# 3. Launch the UI.
"$STOWE" ui &
```

Expected:

- A "Stowe" window opens (~1100x720).
- **Sidebar** lists existing namespaces with var counts (e.g. "demo - 1 var").
- Clicking a namespace shows its variable names (no values) in the main pane.
- **Bottom strip** shows recent activity from the audit log, refreshing every 5 seconds.
- Closing the window exits cleanly.

### Verify polling picks up new audit rows

While the UI is open, in a separate terminal:

```bash
TMPDIR_M5=$(mktemp -d)
NS="m5demo.$(date +%s)"
cat > "$TMPDIR_M5/stowe.toml" <<INNER
namespace = "$NS"
[policy]
allow_unsigned = true
INNER

# Trigger a real audit row (allowed). Cargo is signed by Apple, so verify passes.
cd "$TMPDIR_M5" && "$STOWE" run cargo --version 2>&1
```

Within ~5 seconds the bottom strip in the UI should show a new "allowed" row tagged with `m5demo.<ts>`.

Cleanup:

```bash
sqlite3 ~/Library/Application\ Support/stowe/audit.db \
  "DELETE FROM accesses WHERE namespace = '$NS';"
rm -rf "$TMPDIR_M5"
```

### Notes on M5a dev-cut

- **No edit flows yet.** Add/Reveal/Export/Wipe come in M5b. The note in
  ProjectDetail directs users back to the CLI for revealing values.
- **No real macOS icons.** Placeholder Tauri default. M6 distribution adds
  proper iconography.
- **No code-signed app bundle.** `cargo run --bin stowe -- ui` works for
  dev; production `.app` build is M6.
- **Polling, not push.** AuditFeed polls every 5 seconds. M5b will switch
  to push events when reveal/edit flows demand finer-grained updates.
- **macOS may prompt for Keychain access** the first time the UI loads
  namespaces (same prompt as the M2 CLI). Click "Always Allow" once.

---

## M5b additions: edit flows in the desktop UI

### Reveal a non-biometric secret

Prereq: have at least one secret with `--biometric=never` (the M3 default).
If you don't, add one via CLI: `"$STOWE" add demo MYKEY` and type `secret-value`.

1. Launch UI: `"$STOWE" ui`.
2. Click "demo" in the sidebar.
3. Click "Reveal" next to MYKEY.
4. The dialog shows the value masked (e.g., `••••••value`).
5. Click "Show full value" — the full secret renders.
6. Click "Copy to clipboard" — the dialog confirms with a 30-second
   auto-clear notice.
7. Paste somewhere within 30s: gets the value. Wait 30s, paste again:
   gets an empty string.

### Try to reveal a biometric secret (will fail in dev-cut)

Try to add a `--biometric=always` secret via CLI; expect `errSecMissingEntitlement`
until M6. The UI's reveal of an existing biometric secret would show a
similar error. Documented limit; not a bug.

### Add a secret via the UI

1. Launch UI.
2. Click any namespace in the sidebar.
3. Click "+ Add secret" in the top-right.
4. Fill: variable name "TEST_NEW", value "test-value", biometric "never".
5. Click "Add".
6. The dialog closes, the variable list refreshes, "TEST_NEW" appears.

### Delete a secret via the UI

1. Click "Delete" next to TEST_NEW.
2. Confirm dialog appears with destructive styling.
3. Click "Delete" to confirm.
4. Variable disappears from the list.

### Notes on M5b

- **Edit-existing secret** is a future M5c convenience — for now, delete + add.
- **Export and Wipe** UIs deferred to M5c.
- **Audit log full view** with filters/expand still M5c. The bottom strip
  shows the most recent 25 rows.
- **Clipboard auto-clear** writes empty string to the system clipboard after
  30s. Clipboard managers (Alfred, Maccy, Raycast) keep history independently
  and aren't affected.

---

## M5c additions: export + wipe

### Encrypted export round-trip

```bash
"$STOWE" ui &
# 1. Click "Export" in header.
# 2. Format: Encrypted; passphrase: "test-passphrase"; confirm same.
# 3. Click "Choose file & export"; pick ~/Desktop/stowe-backup-*.age.
# 4. Confirm "Wrote backup to: ..." appears.
# 5. Decrypt manually:
age -d ~/Desktop/stowe-backup-*.age
# (Prompts for passphrase; outputs the plaintext namespaces+vars dump.)
```

### Wipe with two-factor confirm

```bash
# 1. In the UI, click "Wipe…" in header.
# 2. Try clicking "Wipe" without typing the phrase — disabled.
# 3. Type "WIPE EVERYTHING" exactly.
# 4. Optionally check "Also clear the audit log".
# 5. Click "Wipe". Confirm the report shows N namespaces, M vars deleted.
# 6. Sidebar refreshes empty.
```

### Notes on M5c

- **Plaintext export** writes secrets in cleartext to disk. Use only for
  migration; delete the file after.
- **stowe.toml files** in projects are NOT touched by Wipe.
- **Onboarding** and **filterable audit view** are deferred to M5d.

---

## M5d additions: UI polish

### Filterable audit view

```bash
"$STOWE" ui &
# 1. Click "Audit" tab in the header.
# 2. The full audit log loads with filter bar (Namespace, Outcome, Limit).
# 3. Drop the Outcome filter to "denied" — list narrows to denial rows.
# 4. Click a row — it expands inline showing full path, sha, pid, argv,
#    duration, exit code, and reason if present.
# 5. Switch back to "Vault" tab — sidebar + project detail re-renders.
```

### Edit existing secret

```bash
# 1. In Vault tab, click any namespace.
# 2. Click "Edit" next to a variable.
# 3. Modal opens with the var name pre-filled and a new-value field.
# 4. Type a new value, click "Save".
# 5. Modal closes, list refreshes. Reveal to confirm new value sticks.
```

### Onboarding wizard (first-run only)

The wizard fires only when:
- The vault has no namespaces, AND
- `localStorage` has no `stowe.onboarding_seen=true` flag.

```bash
# To force-re-test on a populated vault:
# (in the running webview's devtools console)
localStorage.removeItem('stowe.onboarding_seen');
# ...then run "$STOWE" wipe (typing the phrase) to empty the vault.
# Re-launch UI: the 3-step wizard appears.
# Click "Create a sample secret" on step 2 — adds demo/EXAMPLE_KEY.
```

### Notes on M5d

- **Audit view** queries the same SQLite file the bottom strip polls — both
  reflect the same data; the strip is live (5s) while the audit view
  refreshes only when filters change.
- **Edit secret** uses `addSecret` under the hood (which is upsert via
  `set_with_biometric`); biometric=always still hits the M6 entitlement
  gate from unsigned builds.
- **Onboarding** uses `localStorage` to remember the dismiss. Clearing
  the webview's storage (or wiping the vault to empty) re-triggers it.
