#!/bin/sh
# Apply-check the Ladybird patch set against the pinned tree. The patch set is
# a STACK: each patch is checked against the tree as the previous patches left
# it (that is how the tree gets built), then the tree is restored to pristine.
# No network beyond sync_ladybird's own clone/fetch (offline-safe once it exists).
set -u
cd "$(dirname "$0")/.." || exit 2
TARGET="${LKB_LADYBIRD_DIR:-$PWD/../ladybird-pinned}"

sh scripts/sync_ladybird.sh || { echo "sync failed"; exit 1; }
[ -d patches/ladybird ] || { echo "no patches dir"; exit 1; }
found=0
fail=0
git -C "$TARGET" checkout -- . > /dev/null 2>&1
git -C "$TARGET" clean -fd > /dev/null 2>&1
for p in patches/ladybird/[0-9][0-9][0-9][0-9]-*.patch; do
    [ -e "$p" ] || continue
    found=1
    if git -C "$TARGET" apply --check --verbose "$PWD/$p" > /dev/null 2>&1; then
        # Checked against the accumulated state; now let it land so the next
        # patch sees this patch's context.
        git -C "$TARGET" apply "$PWD/$p" || { echo "APPLY-FAIL (after check) $p"; fail=1; break; }
        echo "APPLY-OK $p"
    else
        echo "APPLY-FAIL $p"
        git -C "$TARGET" apply --check --verbose "$PWD/$p" 2>&1 | tail -5
        fail=1
        break
    fi
done
# Drift check (added by the pi-rukas ticket verifier, which caught a source
# name typo no apply-check can see): every source the stack adds to the
# ladybird_impl block must exist as a real file after the stack is applied.
if [ "$fail" -eq 0 ]; then
    for src in $(awk '/add_library\(ladybird_impl STATIC/{f=1;next} f&&/^\)/{f=0} f' \
                 "$TARGET/UI/Qt/CMakeLists.txt" 2>/dev/null \
                 | grep -oE '[A-Za-z0-9_]+\.cpp' | sort -u); do
        [ -f "$TARGET/UI/Qt/$src" ] \
            || { echo "FAIL: CMake names missing source UI/Qt/$src"; fail=1; }
    done
fi
git -C "$TARGET" checkout -- . > /dev/null 2>&1
git -C "$TARGET" clean -fd > /dev/null 2>&1
[ "$found" -eq 1 ] || { echo "no patch files"; exit 1; }
[ "$fail" -eq 0 ] || exit 1
echo "patches apply clean (stacked)"
