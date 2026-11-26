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

echo "== cmake core =="
if [ -f CMakeLists.txt ]; then
    cmake -S . -B build > build-configure.log 2>&1 || { echo "configure FAILED"; tail -20 build-configure.log; fail=1; }
    cmake --build build > build-compile.log 2>&1 || { echo "build FAILED"; tail -40 build-compile.log; fail=1; }
    ctest --test-dir build --output-on-failure || fail=1
else
    echo "(no CMakeLists.txt yet)"
fi

if [ "$fail" -eq 0 ]; then echo "ALL GREEN"; exit 0; fi
echo "GATE FAILED"
exit 1
