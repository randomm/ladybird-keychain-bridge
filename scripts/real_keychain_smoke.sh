#!/bin/sh
# Owner-run only (README table). Verifies the SecItem adapter against a throwaway
# file-based keychain — never the login keychain, never CI.
set -eu
[ "${LKB_OWNER_RUN:-}" = "1" ] || { echo "owner-run only: set LKB_OWNER_RUN=1 to run"; exit 0; }
[ -n "${LKB_TEST_KEYCHAIN_PATH:-}" ] || { echo "LKB_TEST_KEYCHAIN_PATH required"; exit 1; }
[ -f "$LKB_TEST_KEYCHAIN_PATH" ] && { echo "refusing: $LKB_TEST_KEYCHAIN_PATH already exists"; exit 1; }

BUILD="${LKB_BUILD_DIR:-build}"
BIN="$BUILD/Libraries/KeychainCore/lkb-smoke"
if [ ! -x "$BIN" ]; then
    cmake -S . -B "$BUILD" > /dev/null
    cmake --build "$BUILD" > /dev/null
fi

PW=$(date +%s | shasum | cut -c1-24)
security create-keychain -p "$PW" "$LKB_TEST_KEYCHAIN_PATH"
security unlock-keychain -p "$PW" "$LKB_TEST_KEYCHAIN_PATH"
# Best-effort: current macOS rejects this for a freshly created empty keychain;
# the smoke roundtrip itself is the visibility check.
security set-key-partition-list -S apple-tool:,apple: -s -k "$PW" "$LKB_TEST_KEYCHAIN_PATH" > /dev/null 2>&1 || true

rc=0
"$BIN" --keychain "$LKB_TEST_KEYCHAIN_PATH" || rc=$?

security delete-keychain "$LKB_TEST_KEYCHAIN_PATH" > /dev/null 2>&1 || true
exit $rc
