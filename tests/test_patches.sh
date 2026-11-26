#!/bin/sh
# Patch-set gate: the pinned Ladybird tree must accept every patch cleanly.
# Empty patch-set is valid (bootstrap) — existence of patches is a later task.
set -eu
cd "$(dirname "$0")/.." || exit 2
sh scripts/sync_ladybird.sh
target="${LKB_LADYBIRD_DIR:-$PWD/../ladybird-pinned}"
count=0
for p in patches/ladybird/*.patch; do
    [ -e "$p" ] || continue
    count=$((count + 1))
    if ! git -C "$target" apply --check --verbose "$PWD/$p"; then
        echo "PATCH REJECTED: $p" >&2
        exit 1
    fi
done
echo "patches: ${count} applied-clean"
