# ladybird-keychain-bridge

An Apple-ecosystem credentials bridge for the [Ladybird browser](https://ladybird.org):
website passwords are saved to a Ladybird-owned, at-rest-encrypted vault whose 128-bit
master key lives in the user's macOS login keychain — the Chrome "Safe Storage" model.
Apple exposes no public API to read the Passwords app / iCloud Keychain vault directly;
migration from/to the Passwords app is via its documented CSV format.

Status: pre-1.0, developed by coding agents under the protocol in `AGENTS.md`.
The binding design is `docs/superpowers/specs/`; the active build order is
`docs/superpowers/plans/`.

## User-facing surfaces (single source of truth)

### Keychain item naming

| Field | Value |
|---|---|
| class | `kSecClassGenericPassword` |
| service | `Ladybird Safe Storage` |
| account | `Ladybird` |
| key size | 128 bits, random, created on first use |

`kSecAttrAccessibleWhenUnlocked` is set but is ignored on the file-based login
keychain (Apple TN3137) — it provides no at-rest claim there.

### Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `LKB_OWNER_RUN` | Must be `1` for the two owner-run scripts to do anything; CI never sets it | unset (scripts no-op + exit 0) |
| `LKB_TEST_KEYCHAIN_PATH` | Dedicated keychain file that owner-run smoke/probe scripts create, use, and destroy; never the login keychain | required when `LKB_OWNER_RUN=1` |
| `LKB_PROBE_RESULTS` | Path where `scripts/probe_system_vault.sh` writes its JSON probe matrix | `docs/probes/latest.json` |
| `OPENSSL_ROOT_DIR` | Standard CMake hint for locating OpenSSL on macOS | brew prefix |

### Owner-run scripts (never wired into CI)

| Script | Purpose |
|---|---|
| `scripts/real_keychain_smoke.sh` | Master-key add/read/update/delete against a dedicated keychain |
| `scripts/probe_system_vault.sh` | Empirical availability probes (ASAuthorization password provider, CXP, delivered codes) on the current signing state |

A release tag requires owner-attached logs from both (see `docs/release-gate.md`).
Merges gate on the core suites only.

## Building

```sh
scripts/run_tests.sh          # the full local gate: hygiene + suites + ctest
cmake -S . -B build && cmake --build build && ctest --test-dir build
scripts/sync_ladybird.sh      # clone/verify the pinned Ladybird tree for patch application
```

Linux CI runs everything except the Objective-C++ files; macOS CI adds them. The
Ladybird-tree parts are `patches/ladybird/*.patch` verified by `git apply --check`;
the full Ladybird build is a manually-dispatched CI job, not a merge gate.

## Security model in one paragraph

Credentials are keyed to the frame origin that owns the fields (never the top-level
origin), matched exactly on scheme+host+port, stored only for https (localhost opt-in
with exact port), encrypted per record under a master key the keychain hands out only
to the pinned designated requirement. Administrative reads (list/export/delete-bulk)
require a short-TTL token minted by a real re-authentication — fail closed. Secrets
never appear in logs, telemetry, crash reports, or suggestion payloads. Seatbelt
sandboxed helpers never gain keychain access; credential I/O stays in the unsandboxed
UI process, the same trust level as history/cookies today.
