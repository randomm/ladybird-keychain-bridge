#!/bin/sh
# Self-test for scripts/hygiene_grep.sh: must flag planted bait, must be clean on repo.
set -u
cd "$(dirname "$0")/.." || exit 2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bait="$tmp/bait.txt"
printf 'x %s y\n' "$(printf 'gh%s_' 'o')ABCDEF0123456789ABCDEF" > "$bait"
printf '%s\n' "$(printf 'BEGIN %s PRIVATE KEY' 'RSA')" >> "$bait"

out=$(sh scripts/hygiene_grep.sh "$bait" 2>&1) && { echo "expected bait hit, got clean"; exit 1; }
echo "$out" | grep -q 'token-gho' || { echo "missed gho pattern"; exit 1; }
echo "$out" | grep -q 'token-rsa' || { echo "missed rsa pattern"; exit 1; }

sh scripts/hygiene_grep.sh > /dev/null || { echo "hygiene not clean on tracked files"; exit 1; }
exit 0
