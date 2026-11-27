# Apple Credentials Bridge for Ladybird — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An origin-scoped password save/autofill/update/delete capability for Ladybird on macOS, backed by a Ladybird-owned encrypted vault whose master key lives in the macOS login keychain (Chrome model), with Passwords-app-compatible CSV.

**Architecture:** Standalone repo. Portable core libraries (C++20, CMake/ctest) carry all logic — keychain seam, crypto, vault, policy, CSV, wire format — tested offline against `FakeKeychainBackend`. Ladybird-tree parts (LibWeb hooks, .ipc, Qt UI, Rust bindings) ship as `patches/ladybird/NNNN-*.patch` against pinned HEAD `09fa4834`; `scripts/sync_ladybird.sh` provides the tree. Owner-run scripts cover real-keychain and signed-probe matrices.

**Tech Stack:** C++20, CMake 4 + ctest, Objective-C++ (Security.framework), OpenSSL EVP (brew `openssl@3` locally; apt/brew in CI), SQLite3 (system on macOS, apt on Linux), RFC 8785 JCS canonicalization.

**Spec:** `docs/superpowers/specs/2026-11-27-apple-credentials-bridge-design.md` (owner-approved 2026-11-27)

## Global Constraints

- Tests never touch a real keychain, network, or live account endpoint; `FakeKeychainBackend` is the only backend tests may construct. Real-keychain matrices are owner-run (`scripts/real_keychain_smoke.sh`), gate release tags only (owner ruling).
- Crypto only via OpenSSL EVP: AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, ECDH P-256. No hand-rolled primitives.
- Master key: 128-bit random; keychain item `kSecClassGenericPassword`, service `"Ladybird Safe Storage"`, account `"Ladybird"`.
- Origin matching everywhere: exact (scheme, host-casefolded, port-with-default-stripped); `http` rejected except `localhost` with explicit port; registrable-domain grouping only for settings display, never fill.
- Save requires: `frame_origin == submit_action_origin`; records keyed by `frame_origin`.
- `list/export_csv/import_csv/delete_bulk` require a `CapabilityToken` (TTL 60 s) minted only by a successful re-auth callback; unavailable re-auth → fail closed.
- `autocomplete="off"` ignored on credential fields; `new-password` honored.
- CSV unmapped columns preserved verbatim in `extra_fields` and re-emitted on export.
- Every tracked file < 800 lines; scripts < 200 lines (ratchet-only).
- Conventional Commits; branches `feature/<slug>`; squash-merge; never push main except bootstrap; never force-push.
- No operator name, personal path, or token-like string in any tracked file (hygiene grep gates every push).

## Review Focus

Inputs/conditions no task's happy-path test exercises that must not break the program:

1. Malformed/oversized CSV (huge rows, embedded quotes/newlines, formula prefixes) → typed errors, no crash, no code execution.
2. `errSecInteractionNotAllowed` (locked keychain / headless session) → typed "keychain unavailable" with retry, never a hang or silent empty result.
3. Corrupt vault record / wrong master key (GCM tag mismatch) → `ErrorOr` failure per record; `all()` reports count of undecodable records, never crashes, never returns partial plaintext for a damaged record.
4. BridgeProto frames: truncated length prefix, size-cap overflow, seq out of window, replayed nonce across reconnect → rejected MAC/decode, state untouched.
5. Origin edge cases: `Host` case-insensitivity, default-port stripping (`https://x:443` == `https://x`), userinfo/fragment never part of key, `localhost:PORT` exact-port rule.

Each line's pinning test is added to the owning task's steps.

---

### Task 1: Build scaffold + gates wired (M0)

**Files:** Create `CMakeLists.txt`, `scripts/run_tests.sh`, `tests/test_scaffold.sh`; Modify `README.md` (build table), `.github/workflows/ci.yml` (wire to run_tests.sh).
**Interfaces:** Produces: `run_tests.sh` discovers `tests/test_*.sh` (exit non-zero on any fail) and runs `cmake --build build && ctest --test-dir build`; CI Linux+macOS jobs call it.
- [ ] Step 1: Write `tests/test_scaffold.sh` asserting `cmake -S . -B build` configures, `ctest` reports at least one passing test, and `scripts/hygiene_grep.sh` exits 0.
- [ ] Step 2: Run it; expect FAIL (no CMakeLists).
- [ ] Step 3: Implement `CMakeLists.txt` (C++20, `add_subdirectory(Libraries...)` guarded by existence, `enable_testing()`; find OpenSSL via `find_package(OpenSSL REQUIRED)`, SQLite3 via `find_package(SQLite3 REQUIRED)`). Add `Libraries/Core/tests/TestCorePlaceholder.cpp` with one trivial `EXPECT(true)`-style test using a 20-line assert helper.
- [ ] Step 4: Run `scripts/run_tests.sh`; expect PASS.
- [ ] Step 5: Commit `feat: build scaffold with ctest and offline gate` on `feature/scaffold`; PR; squash-merge per gate.

### Task 2: Core primitives (ErrorOr, ByteBuffer, Origin)

**Files:** Create `Libraries/Core/{ErrorOr.h,ByteBuffer.h,Origin.h,Origin.cpp}`, `Libraries/Core/tests/TestOrigin.cpp`.
**Interfaces:** Produces `ErrorOr<T>{T value | Error{Code,String}}` with `TRY()`/`must_use`; `ByteBuffer = Vector<uint8_t>`; `class Origin{ String scheme,host; u16 port; static ErrorOr<Origin> parse(StringView); bool is_local_opt_in() const; }` (host casefolded, default ports 443/80 stripped, userinfo/fragment rejected).
Pins Review Focus 5.
- [ ] Step 1: Failing tests in `TestOrigin.cpp`: `parse("HTTPS://Example.COM:443/")` → scheme https, host example.com, port 443; default-port equality `parse("https://x:443") == parse("https://x")` via `Origin::equal()`; `parse("https://u:p@x/y#z")` → error `InvalidOrigin`; `parse("http://localhost:8080").is_local_opt_in()` true; `parse("http://evil.com").is_local_opt_in()` false.
- [ ] Step 2: Run → FAIL.
- [ ] Step 3: Implement per signatures (casefold via `std::tolower` on ASCII only).
- [ ] Step 4: Run → PASS.
- [ ] Step 5: Commit `feat(core): ErrorOr, ByteBuffer, Origin with exact-origin normalization`.

### Task 3: KeychainBackend seam + fake (M1 core)

**Files:** Create `Libraries/KeychainCore/{KeychainBackend.h,MasterKey.h,MasterKey.cpp}`, `Libraries/KeychainCore/testing/FakeKeychainBackend.{h,cpp}`, `Libraries/KeychainCore/tests/TestMasterKey.cpp`.
**Interfaces:** Produces:
```cpp
enum class KeychainError { NotFound, InteractionNotAllowed, AuthFailed, UnexpectedData };
enum class Accessibility { WhenUnlocked };
class KeychainBackend { public: virtual ErrorOr<ByteBuffer> read_master_key() = 0;
  virtual ErrorOr<void> write_master_key(ByteBuffer const&, Accessibility) = 0;
  virtual bool is_available() = 0; virtual ~KeychainBackend(); };
class FakeKeychainBackend : public KeychainBackend { /* in-memory; injectable error mode */ };
ErrorOr<ByteBuffer> master_key_or_create(KeychainBackend&); // 16 random bytes on NotFound
```
Pins Review Focus 2 (InteractionNotAllowed typed, surfaced, no hang).
- [ ] Step 1: Failing tests: first `master_key_or_create` on empty fake → 16-byte key, stored; second call returns same key; fake injected `InteractionNotAllowed` → `master_key_or_create` returns that error code (no retry loop); injected `UnexpectedData` on a 15-byte stored blob.
- [ ] Step 2: Run → FAIL. Step 3: Implement. Step 4: Run → PASS. Step 5: Commit `feat(keychain): KeychainBackend seam, fake, master-key lifecycle`.

### Task 4: SecItemKeychainBackend (APPLE-only) + owner smoke script

**Files:** Create `Libraries/KeychainCore/SecItemKeychainBackend.{h,mm}` (compiled only when `APPLE`), `scripts/real_keychain_smoke.sh`, `Libraries/KeychainCore/tests/TestSecItemCompile.cpp` (APPLE-guarded: links symbol).
**Interfaces:** Consumes Task 3 interface; implements it with SecItemAdd/CopyMatching/Update on `kSecClassGenericPassword`, service `"Ladybird Safe Storage"`, account `"Ladybird"`, `kSecAttrAccessibleWhenUnlocked` set with doc note that it is ignored on the file-based keychain; maps errOSStatus → KeychainError.
- [ ] Step 1: Smoke script (owner-run, never in CI): creates dedicated test keychain via `security create-keychain`, unlocks, runs a tiny CLI `lkb-smoke --roundtrip` (add/read/update/delete master item in **that** keychain, not login keychain), asserts roundtrip, deletes test keychain. Write it first.
- [ ] Step 2: Write APPLE-guarded compile test; run on this Mac → FAIL (no implementation).
- [ ] Step 3: Implement the .mm with the exact SecItem dictionary keys; `is_available()` probes `SecItemCopyMatching` with `kSecReturnRef` on a sentinel.
- [ ] Step 4: `cmake --build build` → PASS on macOS; on Linux CI the file is excluded and core suite still green.
- [ ] Step 5: Commit `feat(keychain): SecItem master-key backend and owner-run smoke script`.

### Task 5: CredentialCrypto (OpenSSL EVP wrappers)

**Files:** Create `Libraries/CredentialCrypto/{AesGcm.{h,cpp},Hkdf.{h,cpp},HmacSha256.{h,cpp},Random.{h,cpp}}`, tests `TestAesGcm.cpp`, `TestKdf.cpp`; fuzz target `Meta/Fuzzers/FuzzAesGcmCodec.cpp`.
**Interfaces:** Produces `AesGcm::encrypt(ByteBuffer key16, ByteBuffer aad, ByteBuffer plaintext) -> ErrorOr<ByteBuffer /*nonce(12)|tag(16)|ct*/>`, `decrypt(...) -> ErrorOr<ByteBuffer>`; `Hkdf::expand(sha256, ikm, salt, info, len)`; `HmacSha256::mac(key, data)`; `Random::bytes(n)` (getrandom/CCRandomGenerateBytes).
Pins Review Focus 3 (tag mismatch) and Review Focus 4 partially.
- [ ] Step 1: Failing tests: NIST SP 800-38D vector roundtrip; flipped ciphertext byte → `decrypt` → `Error{Authentication}`; wrong key → same error; empty plaintext roundtrip yields tag present; HKDF RFC 5869 test vector.
- [ ] Step 2: FAIL → Step 3: implement EVP wrappers (EVP_aes_256_gcm with 16-byte key widened per RFC 5869-derived split: derive 32-byte enc key + 12-byte nonce-mask from 16-byte master via HKDF — pin this derivation in `Kdf::vault_key(master)`) → Step 4: PASS → Step 5: Commit `feat(crypto): AES-GCM/HKDF/HMAC/RNG over OpenSSL EVP`.

### Task 6: VaultStore schema + encrypted CRUD (M2b)

**Files:** Create `Libraries/VaultStore/{CredentialRecord.h,VaultStore.{h,cpp}}`, tests `TestVaultStore.cpp`.
**Interfaces:** Consumes Tasks 2,3,5. Produces:
```cpp
struct CredentialRecord { Origin origin; String username; ByteBuffer secret;
  i64 created, last_used, updated; JsonObject extra_fields; Optional<String> form_meta; };
class VaultStore { public: static ErrorOr<VaultStore> open(Path db_path, ByteBuffer master_key);
  ErrorOr<Vector<Match>> find(Origin const&, Optional<StringView> username_hint); // exact-origin only
  ErrorOr<void> put(CredentialRecord const&); ErrorOr<void> remove_credential(int64_t id);
  ErrorOr<Vector<CredentialRecord>> all(size_t& out_undecodable); ErrorOr<void> remove_origin(Origin const&); };
```
Per-record AES-GCM on (username||secret||extra||meta) with AAD = canonical origin string; schema v1 table `credentials(id INTEGER PRIMARY KEY, scheme,host,port, blob, created, last_used, updated)` + `pragma user_version=1`.
Pins Review Focus 3 (`all()` undecodable count) and Review Focus 5 (origin column roundtrip).
- [ ] Step 1: Failing tests: put→find exact origin returns match with plaintext; find on different port (8080 vs 8081 localhost) → empty; `all()` with one record corrupted in DB by hand → `out_undecodable==1`, others intact plaintext; remove_origin wipes all rows for that origin (casefolded).
- [ ] Step 2: FAIL → Step 3: implement (sqlite3 C API; prepared statements; no SQL formatting from strings — bound parameters only) → Step 4: PASS → Step 5: Commit `feat(vault): encrypted record store on SQLite`.

### Task 7: Dedup / merge / update-on-change (M2c)

**Files:** Modify `Libraries/VaultStore/VaultStore.cpp`; tests `TestVaultMerge.cpp`.
**Interfaces:** Consumes Task 6. Produces: `put` upsert semantics — same (origin, username) updates secret+updated and keeps created; new username on same origin inserts; never-save markers table `never_saved(origin)`.
- [ ] Step 1: Failing tests: second `put` same origin+username → one row, new secret, `updated` bumped, `created` preserved; different username → two rows; `mark_never(origin)`/`is_never(origin)` roundtrip incl. casefold.
- [ ] Step 2–5: FAIL → implement → PASS → Commit `feat(vault): upsert merge rules and never-save markers`.

### Task 8: CredentialService policy + CapabilityToken (design §7 core)

**Files:** Create `Libraries/CredentialService/{CredentialService.{h,cpp},CapabilityToken.{h,cpp},SaveRequest.h}`, tests `TestServicePolicy.cpp`, `TestCapabilityToken.cpp`.
**Interfaces:** Consumes 2,3,6,7. Produces:
```cpp
struct SaveRequest { Origin frame_origin, top_level_origin, submit_action_origin;
  String username; ByteBuffer secret; Optional<String> form_meta; };
class CredentialService { ErrorOr<SaveDecision> offer_save(SaveRequest const&);   // Save|Reject|NeverList
  ErrorOr<Vector<Match>> lookup_for_origin(Origin const&, Optional<StringView> hint, u64 page_token);
  ErrorOr<void> save_from_form(SaveRequest const&, SaveDecision);
  ErrorOr<void> delete_credential(int64_t); ErrorOr<void> delete_bulk(Origin const&, CapabilityToken const&);
  ErrorOr<Vector<CredentialRecord>> list(CapabilityToken const&); ErrorOr<void> mark_never(Origin const&);
  Capabilities capabilities() const; };
class CapabilityToken { static ErrorOr<CapabilityToken> mint(RedisAuthCallback&); bool valid() const; }; // TTL 60s, clock-injectable
```
Pins Review Focus 1 (secret never logged: service has no logging sink; audit events carry only `{event, origin, length}` — test asserts secret bytes absent from audit strings).
- [ ] Step 1: Failing tests: `offer_save` with `frame_origin != submit_action_origin` → `Reject{CrossOriginSubmit}`; http non-localhost → `Reject{HttpProhibited}`; localhost:8080 allowed; never-list origin → silent reject; `lookup` with revoked token on `list()` → `Error{Unauthorized}`; expired token (injected clock +61 s) invalid; `delete_bulk` without token fails.
- [ ] Step 2–5: FAIL → implement → PASS → Commit `feat(service): origin policy, never-list, capability-gated admin`.

### Task 9: CSV bridge (M9b/M9c) — Passwords-app compatible

**Files:** Create `Libraries/CsvBridge/{CsvBridge.{h,cpp}}`, tests `TestCsvRoundtrip.cpp`, fixtures `tests/fixtures/passwords_export_columns.csv` (community-known column set: `Title,Username,Password,URL,Notes,Created,Last Modified,Last Used,Verified,OTP Auth Token`, values redacted), fuzz target `FuzzCsvImport.cpp`.
**Interfaces:** Consumes 2,6. Produces `ErrorOr<size_t> import_csv(ReadonlyBytes, VaultStore&)`, `ErrorOr<ByteBuffer> export_csv(VaultStore&)`; URL→Origin parse via Task 2; unmapped/unparsed columns preserved verbatim per record in `extra_fields`; export re-emits them; formula-injection prefixes (`=`,`+`,`-`,`@`) escaped with leading `'` in export text fields.
Pins Review Focus 1.
- [ ] Step 1: Failing tests: fixture roundtrip → N records, then export→reimport → byte-equal column header + `extra_fields` preserved (assert `OTP Auth Token` survives roundtrip); 1 MiB field → `Error{TooLarge}`; unbalanced quote → `Error{MalformedCsv}`; `=cmd` username exported as `'=cmd`; caps enforced (10k rows).
- [ ] Step 2–5: FAIL → implement → PASS → Commit `feat(csv): Passwords-app-compatible import/export with verbatim extras`.

### Task 10: BridgeProto — framing, handshake, authenticated frames (M3)

**Files:** Create `Libraries/BridgeProto/{Frame.{h,cpp},Handshake.{h,cpp},CanonicalJson.{h,cpp}}`, tests `TestFrame.cpp`, `TestHandshake.cpp`, golden `tests/fixtures/proto_golden.json`.
**Interfaces:** Consumes 5. Produces: 4-byte LE length + JSON frame, caps 1 MiB req / 16 MiB resp; `hello{proto_version,caller_bundle_id,eph_pub,nonce}` → `hello_ack{server_pub,capabilities,transcript}`; session key `HKDF-EXP(sha256, ECDH_p256(eph_a,eph_b), salt=hello||ack, info="lkb-session")`; every frame `{seq,mac}` with `mac=HMAC(key_mac, seq_be64||direction_byte||canonical_json(RFC8785 subset))`; verifier holds per-session `next_seq`, rejects `< next_seq` and `> next_seq+64`; transcript hash binds hello to peer identity string.
Pins Review Focus 4 fully.
- [ ] Step 1: Failing tests: full handshake then `lookup` request/response roundtrip; truncated 2-byte buffer → `Error{IncompleteFrame}`; 1 MiB+1 request → `Error{TooLarge}`; replayed frame (same seq) rejected; seq jump 200 rejected; MAC over non-canonical JSON rejected; transcript mismatch (peer identity string differs) → `Error{Handshake}`.
- [ ] Step 2–5: FAIL → implement → PASS → Commit `feat(proto): length-prefixed frames, ECDH handshake, sequence-MAC`.

### Task 11: Ladybird tree + LoginFormDetector patches (M4 + M4b)

**Files:** Create `scripts/sync_ladybird.sh` (clone Ladybird to `../ladybird-pinned` if absent; hard-assert HEAD `09fa4834`; verify-cmd), `patches/ladybird/0001-form-detection.patch`, `0002-split-page-heuristic.patch`, apply-manifest `patches/ladybird/MANIFEST` (sha + `git apply --check` instructions).
**Interfaces:** Consumes nothing from other tasks (patch-set is standalone; payload struct mirrors Task 8 `SaveRequest` field names **verbatim** — `top_level_origin, frame_origin, submit_action_origin, username, secret, field_scope, frame_id`). Produces in Ladybird: `HTMLFormElement::submit_form()/implicitly_submit_form()` call `page().did_request_save_credentials(...)` (new PageClient hook, mirrors `page_did_request_context_menu`); M4b adds password-field blur/Enter triggers on standalone password inputs without a same-page username field.
- [ ] Step 1: Write `scripts/check_patches.sh`: runs `scripts/sync_ladybird.sh`, then for each patch `git -C ../ladybird-pinned apply --check --verbose patches/ladybird/NNNN-*.patch` from clean tree; expect FAIL (no patches).
- [ ] Step 2: Write patch 0001 consuming `AutocompleteElement::attribute_details()` (`credential_type/scope/field_name`): username+password at submit → fire once per form with all three origins; add WPT-style headless test `Tests/LibWeb/TestLoginFormDetection.cpp` asserting hook payloads incl. the embedded-iframe case (frame origin != top-level → payload keeps both).
- [ ] Step 3: Write patch 0002 (M4b): `password_field_blurred` / Enter on password input without same-page username field → fire with `field_scope=password_only, username=empty` marker so UI offers "fill username later".
- [ ] Step 4: Run `scripts/check_patches.sh` → PASS (apply-clean); Ladybird full build verification is CI/manual-dispatch job (documented, not faked).
- [ ] Step 5: Commit `feat(patches): form submit + split-page credential detection against ladybird 09fa4834`.

### Task 12: IPC plumbing patch (M5)

**Files:** `patches/ladybird/0003-credentials-ipc.patch`; MANIFEST updated.
**Interfaces:** Consumes Task 11 payload names. Produces in Ladybird: `endpoint Credentials routed by Web::PageId page_id` in `Services/Hub/CredentialsServer.ipc` + messages `did_request_save_credentials(…) => ()`, `request_credential_suggestions(Origin, FrameId) => (Vector<Suggestion>)`, `credential_selected(SuggestionId) => (bool)` mirroring the spell-checker round-trip.
- [ ] Step 1: `scripts/check_patches.sh` still green with new patch (apply-clean). Step 2: patch adds the .ipc file + Hub dispatch + headless scripted-UI test `Tests/LibWebView/TestCredentialsIpc.cpp` (submit → request reaches scripted client). Step 3: CI/manual-dispatch build verifies codegen compiles (documented). Step 4: PASS apply-check. Step 5: Commit `feat(patches): credentials IPC endpoint on the Hub`.

### Task 13: Save prompt patch (M6)

**Files:** `patches/ladybird/0004-save-prompt.patch`; UI: Qt dialog Save / Not now / Never for this site via `PermissionPromptRequest` pattern.
- [ ] Steps 1–5: same shape as Task 12; tests assert the three decisions route to `save_from_form` decision outcomes and the never-list write; commit `feat(patches): save-credential prompt`.

### Task 14: Autofill popup + injection patch (M7a/M7b)

**Files:** `patches/ladybird/0005-autofill-popup.patch`, `0006-textediting-insert.patch`.
**Interfaces:** Produces: field-anchored popup (Omnibox scripted-provider pattern) with `Suggestion{ id, username, label }` **secret never in suggestion payloads**; selection → `InsertText` new `Web::TextEditingCommand` case + `EventHandler` case firing site-visible `input`+`change` events; dismiss-on scroll/blur/focus-loss/navigation; UI-process hit-test against last-committed layout; injection requires user activation.
Pins Review Focus 5 again on popup filtering (exact origin via Task 8 lookup).
- [ ] Steps 1–5: apply-clean + headless tests (filtering, no-match, multi-account, dismissal rules); commit `feat(patches): field-anchored autofill with insert-text command`.

### Task 15: Credential Management + settings page patches (M8, M9a)

**Files:** `patches/ladybird/0007-credentials-container.patch` (Rust: `CredentialsContainer::store/get/preventSilentAccess` against the Credentials IPC, exact-origin `get`, no silent cross-subdomain), `0008-credential-settings-webui.patch` (WebUI page calling re-auth-gated `list()/delete_bulk()`).
- [ ] Steps 1–5: apply-clean; WPT-style `TestCredentialsContainer.cpp`; commit `feat(patches): navigator.credentials + management page`.

### Task 16: SystemVaultSource probes + empirical probe matrix (M10)

**Files:** Create `Libraries/KeychainCore/{SystemVaultSource.h,SystemVaultSourceProbe.mm}`, tool `Meta/Tools/lkb-probe.cpp` (+ `scripts/probe_system_vault.sh`), results doc `docs/probes/2026-11-27-adhoc-build-probe-results.md`.
**Interfaces:** Produces `enum class ProbeState { Available, UnvalidatedAdhoc, UnavailableSystemVersion, UnavailableUnsigned }`; probes `ASAuthorizationPasswordProvider`, `ASAuthorizationWebBrowserPublicKeyCredentialManager`, CXP managers, `ASDeliveredVerificationCodesManager`; **runs for real on this unsigned/ad-hoc Mac** — results recorded empirically, no hardcoded `unavailable_*`.
- [ ] Step 1: Write failing test asserting `capabilities()` degrades explicitly (no half-state) and audit logs redact secrets. Step 2: FAIL. Step 3: Implement probes with availability enum; tool prints JSON per API. Step 4: Run `scripts/probe_system_vault.sh` on this Mac; commit real results into the docs file (evidence). Step 5: Commit `feat(probes): system-vault capability probes with empirical adhoc results`.

### Task 17: Gate polish + owner matrix docs + release gate (M0/§7 close-out)

**Files:** Modify `README.md` (owner matrix table, env vars: `LKB_TEST_KEYCHAIN_PATH`, `LKB_OWNER_RUN=1`), `AGENTS.md` (final gate list), `scripts/run_tests.sh` (include probe tool compile on macOS), `docs/release-gate.md` (release tag requires owner-run smoke+probe logs attached; merges gate on core suites only — owner ruling 2026-11-27).
- [ ] Step 1: `tests/test_release_docs.sh`: hygiene grep over repo incl. fixtures; asserts README env table matches `grep -rhoE 'LKB_[A-Z_]+' scripts/`. Step 2: FAIL → Step 3: fix docs → Step 4: `scripts/run_tests.sh` fully green on macOS (this session, evidence in PR) → Step 5: Commit `docs: release gate and owner-run matrix documentation`.

## Out of plan (owner-run tickets, spec §8)

- M11 passkey spike (signed Developer-ID build) — report + method shapes only.
- M12 CXP / AutoFill provider paid-account feasibility — go/no-go doc + stub Info.plist.
