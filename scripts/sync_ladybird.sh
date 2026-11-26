#!/bin/sh
# Provide the pinned Ladybird tree for patch application. Never mutates user dirs
# outside its own target. The pinned SHA is a mutable fact owned by this file +
# patches/ladybird/MANIFEST.
set -eu
PINNED_SHA='09fa48340dc54458a50ba524398fa4011eba3637'
TARGET="${LKB_LADYBIRD_DIR:-$PWD/../ladybird-pinned}"
URL='https://github.com/LadybirdBrowser/ladybird.git'

if [ ! -d "$TARGET/.git" ]; then
    git clone --depth 1 "$URL" "$TARGET" >/dev/null
fi
cd "$TARGET"
if [ "$(git rev-parse HEAD)" != "$PINNED_SHA" ]; then
    git fetch --depth 1 origin "$PINNED_SHA" >/dev/null
    git checkout --detach FETCH_HEAD >/dev/null
fi
actual=$(git rev-parse HEAD)
if [ "$actual" != "$PINNED_SHA" ]; then
    echo "sync_ladybird: HEAD $actual != pinned $PINNED_SHA" >&2
    exit 1
fi
echo "ladybird tree ready at $TARGET @ $actual"
