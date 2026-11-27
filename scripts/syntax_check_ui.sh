#!/bin/sh
# Offline compile proof for the patched UI/Qt credentials surfaces.
#
# The full browser build stays the owner's release step (offline doctrine),
# but the credentials TUs do not need Qt or IPC codegen to be CHECKED: this
# script applies the patch stack to the pinned tree and runs clang
# -fsyntax-only over the credentials-only files, faking only the handful of
# CMake-generated headers they transitently touch (export/Debug headers that
# carry no semantics for a syntax check). A compile error here is a compile
# error in the owner build; it catches API drift against the pinned tree
# (JsonValue accessors, StringView/ByteString conversions, the
# AK_ALLOC_WITH_KMALLOC make<> contract) long before an owner build runs.
#
# Env: LKB_LADYBIRD_DIR (pinned tree, default ../ladybird-pinned).
set -u
cd "$(dirname "$0")/.." || exit 2
BRIDGE=$PWD
TREE=${LKB_LADYBIRD_DIR:-$PWD/../ladybird-pinned}
fail=0

say() { printf '%s\n' "$*"; }
die() { say "FAIL: $*"; fail=1; }

[ -d "$TREE/.git" ] || die "pinned tree not found at $TREE"
[ -n "$(git -C "$TREE" status --porcelain)" ] && die "pinned tree is not clean"

for p in "$BRIDGE"/patches/ladybird/000*.patch; do
    git -C "$TREE" apply "$p" || { die "apply failed: $p"; break; }
done

STUB=$(mktemp -d)
GEN="$STUB/gen"     # include root for faked generated headers
ROOT="$STUB/root"   # include root for the bridge library headers (flat symlinks)
MACROS="$STUB/macros.h"  # NOT inside an include root: -include'ing a file from
                         # inside an -I root poisons that root's lookups in clang
mkdir -p "$GEN" "$ROOT"
: > "$MACROS"
for d in BridgeHost CredentialService KeychainCore VaultStore Core CredentialCrypto CsvBridge; do
    for h in "$BRIDGE"/Libraries/"$d"/*.h; do ln -s "$h" "$ROOT"; done
done
ln -s "$BRIDGE"/Libraries/CredentialService/testing "$ROOT/testing" 2>/dev/null

check() {
    file=$1; shift
    i=0
    while [ "$i" -lt 60 ]; do
        i=$((i + 1))
        out=$(clang++ -fsyntax-only -w -std=c++23 "$@" -include "$MACROS" \
              -I "$GEN" -I "$ROOT" -I Libraries -I . "UI/Qt/$file" 2>&1)
        miss=$(printf '%s' "$out" | grep -oE "'[A-Za-z0-9_/]+\.h' file not found" | head -1 | sed "s/'//g;s/ file not found//")
        if [ -n "$miss" ]; then
            mkdir -p "$GEN/$(dirname "$miss")"
            case "$miss" in
                *Debug.h)
                    # CMake-generated debug-flag headers: define the flags off.
                    {
                        printf '#pragma once\n'
                        printf '%s' "$out" | grep -oE "use of undeclared identifier '[A-Z0-9_]+_DEBUG'" |
                            grep -oE '[A-Z0-9_]+_DEBUG' | sort -u |
                            while read -r flag; do printf '#define %s 0\n' "$flag"; done
                    } > "$GEN/$miss" ;;
                *) printf '#pragma once\n' > "$GEN/$miss" ;;
            esac
            continue
        fi
        macros=$(printf '%s' "$out" | grep -oE "unknown type name '[A-Z0-9_]+'|incomplete type 'class [A-Z0-9_]+'|use of undeclared identifier '[A-Z0-9_]+_DEBUG'" | grep -oE '[A-Z][A-Z0-9_]+' | sort -u)
        if [ -n "$macros" ]; then
            for m in $macros; do
                case "$m" in
                    *_DEBUG) printf '#ifndef %s\n#define %s 0\n#endif\n' "$m" "$m" >> "$MACROS" ;;
                    *)       printf '#ifndef %s\n#define %s\n#endif\n' "$m" "$m" >> "$MACROS" ;;
                esac
            done
            continue
        fi
        n=$(printf '%s' "$out" | grep -c 'error:')
        if [ "$n" -ne 0 ]; then
            say "FAIL: $file ($n errors)"
            printf '%s\n' "$out" | grep 'error:' | head -10
            fail=1
        else
            say "SYNTAX-OK $file ${*:-plain}"
        fi
        return
    done
    die "$file: stub loop exhausted"
}

cd "$TREE" || die "cannot enter $TREE"
check CredentialsBridgeHost.cpp
check CredentialsBridgeHost.cpp -DHAVE_LKB_BRIDGE=1
check CredentialSettingsPage.cpp

git -C "$TREE" checkout -- .
git -C "$TREE" clean -fdq -e .codegraph
[ -n "$(git -C "$TREE" status --porcelain)" ] && die "tree dirty after restore"
rm -rf "$STUB"

if [ "$fail" -eq 0 ]; then say "SYNTAX ALL GREEN"; else say "SYNTAX GATE FAILED"; exit 1; fi
