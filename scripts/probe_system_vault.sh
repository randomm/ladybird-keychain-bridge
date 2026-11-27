#!/bin/sh
# M10 empirical capability matrix — OWNER-RUN ONLY.
# Creates a throwaway file-based keychain, runs the probe against it, and tears
# it down. Refuses to run unless LKB_OWNER_RUN=1 is set by a human. The login
# keychain is never addressed.
set -u
cd "$(dirname "$0")/.." || exit 2

if [ "${LKB_OWNER_RUN:-0}" != "1" ]; then
    echo "PROBE REFUSED: set LKB_OWNER_RUN=1 to run the owner matrix"
    exit 2
fi

BUILD="${LKB_BUILD_DIR:-build}"
PROBE="$BUILD/Libraries/KeychainCore/lkb-probe"
[ -x "$PROBE" ] || { echo "lkb-probe not built — run: cmake --build $BUILD"; exit 1; }

TMP_KC_DIR="$(mktemp -d)"
TMP_KC="$TMP_KC_DIR/probe.keychain-db"
PASS="$(/usr/bin/uuidgen)"
trap 'security delete-keychain "$TMP_KC" > /dev/null 2>&1; rm -rf "$TMP_KC_DIR"' EXIT

security create-keychain -p "$PASS" "$TMP_KC" > /dev/null || { echo "PROBE FAILED: create-keychain"; exit 1; }
security unlock-keychain -p "$PASS" "$TMP_KC" > /dev/null || { echo "PROBE FAILED: unlock-keychain"; exit 1; }
security set-keychain-settings -u -t 3600 "$TMP_KC" > /dev/null 2>&1
# Best-effort: some macOS builds reject this for a freshly created, empty keychain;
# the probe's own roundtrip is the authority on visibility.
security set-key-partition-list -S apple-tool:,apple: -s -k "$PASS" "$TMP_KC" > /dev/null 2>&1 \
    || echo "note: set-key-partition-list declined (continuing)"

LKB_OWNER_RUN=1 "$PROBE" --keychain "$TMP_KC" --json "${LKB_PROBE_RESULTS:-docs/probes/latest.json}"
rc=$?
echo "probe exit: $rc"
exit "$rc"
