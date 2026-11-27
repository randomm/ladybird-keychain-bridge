# Release gate (owner ruling, 2026-11-27)

Two tiers, deliberately different:

## Merge gate (every PR, automated)
The core suites only — `sh scripts/run_tests.sh` exits 0 on macOS:
hygiene grep, all `tests/test_*.sh` suites (including `test_release_docs.sh`),
clang-format on changed sources, offline doctrine, and the full CMake build +
ctest (which compiles and runs `lkb-probe`-bearing targets on macOS).
`skipped`/`neutral` CI checks are not passes. A merge is blocked on red core.

## Release gate (tag only)
A release tag additionally requires the OWNER to attach logs from both
owner-run scripts, run on the release build, to the tag/PR:

1. `LKB_OWNER_RUN=1 LKB_TEST_KEYCHAIN_PATH=<fresh path> sh scripts/real_keychain_smoke.sh`
   → `SMOKE OK`
2. `LKB_OWNER_RUN=1 sh scripts/probe_system_vault.sh`
   → `PROBE PASSED` plus the JSON matrix at `LKB_PROBE_RESULTS`
   (default `docs/probes/latest.json`).

Both refuse to run without `LKB_OWNER_RUN=1`, set by a human; CI never sets
it and never touches a real keychain. If the probe reports degradation
(any capability `NO`, audit `error`/`mismatch`/`still-present`), the release
is blocked until the degradation is explained and the capability matrix in
`docs/probes/` is updated with the run.

Agents never merge or tag; the owner does (AGENTS.md merge grant: none).
