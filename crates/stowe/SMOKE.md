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
