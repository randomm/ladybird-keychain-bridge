#!/bin/sh
# The full local gate. AGENTS.md binds every push to this exiting 0.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0

echo "== hygiene =="
sh scripts/hygiene_grep.sh || fail=1

echo "== suites =="
found=0
for t in tests/test_*.sh; do
    [ -e "$t" ] || continue
    found=1
    if sh "$t"; then echo "PASS $t"; else echo "FAIL $t"; fail=1; fi
done
[ "$found" -eq 1 ] || echo "(no suites yet)"

echo "== clang-format (all tracked + untracked sources) =="
# AGENTS.md gate 3. Checking only the working-tree diff is vacuous on a clean
# CI checkout — check every tracked source instead.
changed=$( { git ls-files '*.cpp' '*.h' '*.hpp' '*.mm' 2>/dev/null; \
             git ls-files --others --exclude-standard 2>/dev/null | grep -E '\.(cpp|h|hpp|mm)$'; } | sort -u || true )
if [ -n "$changed" ]; then
    CF_BIN=clang-format
    command -v clang-format >/dev/null 2>&1 || CF_BIN=$(xcrun --find clang-format 2>/dev/null || true)
    if [ -n "$CF_BIN" ]; then
        # shellcheck disable=SC2086
        "$CF_BIN" --dry-run --Werror $changed || { echo "FAIL: clang-format"; fail=1; }
    else
        echo "FAIL: clang-format not installed but source files changed"
        fail=1
    fi
fi

echo "== SecItem boundary (AGENTS gate 5) =="
if grep -rniE 'SecItem(Add|CopyMatching|Update|Delete)' --include='*.cpp' --include='*.h' . \
        | grep -v testing; then
    echo "FAIL: SecItem* outside .mm backends"
    fail=1
fi

echo "== offline doctrine =="
if grep -REn --include=CMakeLists.txt --include='*.cmake' \
        -i -e 'FetchContent' -e 'ExternalProject' -e 'file\(DOWNLOAD' . 2>/dev/null; then
    echo "FAIL: networked cmake construct (offline doctrine)"
    fail=1
fi

echo "== cmake core =="
if [ -f CMakeLists.txt ]; then
    cmake -S . -B build > build-configure.log 2>&1 || { echo "configure FAILED"; tail -20 build-configure.log; fail=1; }
    cmake --build build > build-compile.log 2>&1 || { echo "build FAILED"; tail -40 build-compile.log; fail=1; }
    ctest --test-dir build --output-on-failure || fail=1
    if [ "$(uname)" = "Darwin" ]; then
        # The owner-run probe tool must always compile (it is the release gate's instrument).
        [ -x build/Libraries/KeychainCore/lkb-probe ] \
            || { echo "FAIL: lkb-probe not built on macOS"; fail=1; }
    fi
else
    echo "(no CMakeLists.txt yet)"
fi

echo "== patched-UI syntax =="
sh scripts/syntax_check_ui.sh || fail=1

if [ "$fail" -eq 0 ]; then echo "ALL GREEN"; exit 0; fi
echo "GATE FAILED"
exit 1
