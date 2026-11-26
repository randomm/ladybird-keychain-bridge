#!/bin/sh
# M0: the build must configure, ctest must run at least one passing test, hygiene clean.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0

rm -rf build-selftest
if ! cmake -S . -B build-selftest > .superpowers-selftest-configure.log 2>&1; then
    echo "FAIL: cmake configure"; tail -15 .superpowers-selftest-configure.log; fail=1
fi
if ! cmake --build build-selftest > .superpowers-selftest-build.log 2>&1; then
    echo "FAIL: build"; tail -15 .superpowers-selftest-build.log; fail=1
fi
out=$(ctest --test-dir build-selftest --output-on-failure 2>&1) || fail=1
echo "$out" | grep -Eq '100% tests passed|[1-9][0-9]* tests? passed' || { echo "FAIL: no passing ctest"; echo "$out" | tail -5; fail=1; }
rm -rf build-selftest .superpowers-selftest-configure.log .superpowers-selftest-build.log

sh scripts/hygiene_grep.sh > /dev/null || { echo "FAIL: hygiene"; fail=1; }

[ "$fail" -eq 0 ] || exit 1
echo "scaffold ok"
