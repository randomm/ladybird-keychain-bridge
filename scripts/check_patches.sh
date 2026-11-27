#!/bin/sh
# Apply-check the Ladybird patch set against the pinned tree. No network beyond
# sync_ladybird's own clone/fetch (which is offline-safe once the tree exists).
set -u
cd "$(dirname "$0")/.." || exit 2
TARGET="${LKB_LADYBIRD_DIR:-$PWD/../ladybird-pinned}"

sh scripts/sync_ladybird.sh || { echo "sync failed"; exit 1; }
[ -d patches/ladybird ] || { echo "no patches dir"; exit 1; }
found=0
fail=0
for p in patches/ladybird/[0-9][0-9][0-9][0-9]-*.patch; do
    [ -e "$p" ] || continue
    found=1
    # Apply-checks must run from the tree root, clean tree, verbose.
    git -C "$TARGET" checkout -- . > /dev/null 2>&1
    git -C "$TARGET" clean -fd > /dev/null 2>&1
    if git -C "$TARGET" apply --check --verbose "$OLDPWD/$p" 2>&1 | tail -3; then
        echo "APPLY-OK $p"
    else
        echo "APPLY-FAIL $p"
        fail=1
    fi
done
[ "$found" -eq 1 ] || { echo "no patch files (expected while Task 11 is open)"; exit 1; }
[ "$fail" -eq 0 ] || exit 1
echo "patches apply clean"
