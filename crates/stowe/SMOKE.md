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
