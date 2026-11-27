#!/bin/sh
# Release-docs hygiene: the README env table is the single source of truth and
# must exactly match the LKB_* variables the scripts actually read; the release
# gate must be written down and named from AGENTS.md.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0

# 1. Env-var table == scripts' actual usage (across the whole repo incl. fixtures).
used=$(grep -rhoE 'LKB_[A-Z_]+' scripts/ 2>/dev/null | sort -u)
documented=$(grep -ohE 'LKB_[A-Z_]+' README.md 2>/dev/null | sort -u)
for v in $used; do
    printf '%s\n' "$documented" | grep -qx "$v" || { echo "FAIL: $v used by scripts but not in README"; fail=1; }
done
for v in $documented; do
    printf '%s\n' "$used" | grep -qx "$v" || { echo "FAIL: $v documented in README but used by no script"; fail=1; }
done

# 2. The release gate is written down.
if [ ! -f docs/release-gate.md ]; then
    echo "FAIL: docs/release-gate.md missing"
    fail=1
else
    grep -q 'LKB_OWNER_RUN' docs/release-gate.md || { echo "FAIL: release-gate.md must name the owner-run gate"; fail=1; }
    grep -qi 'smoke' docs/release-gate.md || { echo "FAIL: release-gate.md must require smoke logs"; fail=1; }
    grep -qi 'probe' docs/release-gate.md || { echo "FAIL: release-gate.md must require probe logs"; fail=1; }
fi

# 3. AGENTS.md points at the release gate.
grep -q 'docs/release-gate.md' AGENTS.md || { echo "FAIL: AGENTS.md must reference docs/release-gate.md"; fail=1; }

# 4. The probe matrix artifact is documented where it lands.
grep -qi 'docs/probes' README.md || { echo "FAIL: README must point to the probe results directory"; fail=1; }

if [ "$fail" -eq 0 ]; then echo "RELEASE DOCS OK"; exit 0; fi
exit 1
