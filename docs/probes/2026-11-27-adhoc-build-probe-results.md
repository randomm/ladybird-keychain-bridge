# SystemVaultSource empirical probe matrix — 2026-11-27 (owner-run)

Host: macOS (Darwin 27.3.0), ad-hoc-signed local build, throwaway file-based
keychain (`security create-keychain` in a temp dir; login keychain untouched —
verified absent afterwards via `security find-generic-password`).

Command: `LKB_OWNER_RUN=1 sh scripts/probe_system_vault.sh`

```
note: set-key-partition-list declined (continuing)
capabilities:
  keychain_available:  yes
  save_read_roundtrip: yes
  update:              yes
  delete:              yes
audit:
  save=ok
  read=ok
  update=ok
  read=ok
  delete=ok
  read=not-found
PROBE PASSED
probe exit: 0
```

`scripts/real_keychain_smoke.sh` (owner-run) also reports `SMOKE OK` on this host.

## Findings that shaped the backend

* An un-unlocked `security create-keychain` keychain reads as absent — the
  probe script unlocks it explicitly.
* `security set-key-partition-list` fails (`SecItemCopyMatching -25300`) for a
  freshly created empty keychain on this OS; it is best-effort now. Item
  visibility is decided by the probe roundtrip itself, not by this step.
* **SecItem scoping defect (fixed here):** items added with `kSecUseKeychain`
  are stored in the file keychain (visible in `security dump-keychain`) but
  `SecItemCopyMatching`/`SecItemDelete` scoped by `kSecUseKeychain` report
  `errSecItemNotFound` on this OS; scoping matching queries with
  `kSecMatchSearchList` (same keychain) works. The adapter now uses
  `kSecMatchSearchList` for match queries and keeps `kSecUseKeychain` only on
  add.
* Degradation semantics exercised for real: with the defect present the probe
  reported `save_read_roundtrip: NO / update: NO / delete: NO` with audit
  `save=ok, read=not-found` — explicit, never optimistic.
