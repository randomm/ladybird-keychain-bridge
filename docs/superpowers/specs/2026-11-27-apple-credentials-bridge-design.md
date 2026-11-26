# Apple credentials bridge for Ladybird — design

Date: 2026-11-27 · Status: **owner-approved 2026-11-27** (rulings recorded in §10; steering record
`noni decide` in the private direction repo) · Authors: the owner + agent research panel
Ground truth: Ladybird HEAD `09fa4834` (release 2026.48.0, 2026-11-26); Apple docs as of macOS 26/27.
This doc was produced by a 3-researcher fan-out, one architect, and three adversarial
verifiers (facts / feasibility / security); every verifier correction is folded in and marked.

## 1. Intent and why

Apple-ecosystem users keep their web credentials in the macOS Keychain / Passwords app and
expect any browser to "just use" them. Ladybird (https://ladybird.org) currently has **zero**
credential infrastructure: no password store, no autofill, no save prompt, no keychain access,
no WebAuthn (all stubs with explicit FIXMEs). This project builds the missing credential layer
for Ladybird on macOS so that logging in with your Apple-side credentials is easy, and the
bridge follows both Ladybird's engineering conventions and Apple's security model rather than
fighting either.

**The central honest finding (drives everything):** Apple exposes **no public API** for a
non-Apple app to read the Passwords app / iCloud Keychain vault. (Negative evidence: no
Passwords framework page on developer.apple.com; AuthenticationServices autofill/CXP surface is
the entire documented area; Apple's Mac Passwords User Guide v3.0 documents CSV-only
import/export. Confidence: medium-high — negative evidence.) Therefore "use your Keychain
credentials in Ladybird" is delivered the way Chrome and every third-party manager does it:

- the macOS Keychain is the **master-key vault** (one `kSecClassGenericPassword` item holding a
  128-bit key — Chrome's exact model, `keychain_password_mac.mm`), and
- credentials live in a **Ladybird-owned, at-rest-encrypted vault**, with **CSV
  import/export compatible with the Apple Passwords app** as the sanctioned migration path, and
- the **system-mediated surfaces** (per-site autofill via `ASAuthorizationPasswordProvider`,
  Credential Exchange CXP, passkeys via `ASAuthorizationWebBrowserPublicKeyCredentialManager`)
  sit behind feature-probed adapters until an owner-run signed spike validates them.

## 2. Goals, non-goals, anti-goals

**Goals (MVP):** origin-scoped save / autofill / update / delete of website passwords in the
Ladybird-owned encrypted vault; save prompt; field-anchored autofill popup; functional
`navigator.credentials.store()/get()`; re-auth-gated management page; Passwords-app-compatible
CSV. All logic unit-tested **offline** against an in-memory fake keychain; CI never touches a
real keychain or any live account endpoint.

**Non-goals (MVP):** reading the Passwords app vault directly (no such API exists); passkeys
(probe + owner-run spike only, coordinate with Ladybird #751/#14821); CXP; iOS; Windows/Linux
keychain; OTP autofill beyond the `oneTimeCode` autocomplete affordance.

**Anti-goals:** anything that looks like "exported 500 passwords to a helper an attacker can
query"; a permanent Ladybird fork; plaintext secrets in logs, crash reports, or on disk outside
the vault.

## 3. Constraints

- Repo: public, under GitHub org `randomm`; built primarily by coding agents with TDD; one PR
  per task; Conventional Commits; squash-merge; never force-push.
- Tests offline-only against stubs; real-keychain matrix is owner-run by design.
- Ladybird's own conventions must survive review by its maintainers: LibIPC `.ipc` codegen,
  LibTest, Qt-only frontend with Objective-C++ `.mm` files inside `UI/Qt/` for macOS-native
  code, Seatbelt-sandboxed helpers (never granted keychain access), ad-hoc `codesign -s -` for
  local builds.
- Upstream-portable: components are libraries against real Ladybird interfaces, not a fork.

## 4. Verified ground truth (from research panel; verifier-checked)

Ladybird (HEAD `09fa4834`, verified live):
- `Libraries/LibWeb/HTML/AutocompleteElement.{h,cpp}` parses `autocomplete` into
  `AttributeDetails{hint_set, scope, field_name, credential_type}`; it is the base class of
  input/textarea/select and its parse feeds only the IDL getter — **no autofill/credential
  consumer exists**. `HTMLFormElement::submit_form()/implicitly_submit_form()` exist with no
  page-client hook → M4 adds both.
- IPC: `.ipc` DSL with `endpoint ... routed by Web::PageId page_id` (`WebContentClient.ipc:83`);
  `Services/Hub/{HubServer,HubClient}.ipc` carry `PermissionPromptRequest` round-trips;
  `--headless` mode has the Hub take over UI (`Documentation/ProcessArchitecture.md`).
- Precedent for macOS-native code: `UI/Qt/SpellCheckerMac.mm` → `Libraries/LibWebView/
  SpellChecker.h` (APPLE-only impl), `Services/RequestServer/SystemTrustMacOS.cpp`. Writing/
  spell suggestions: `Libraries/LibWebCommon/Page/WritingSuggestion.h`, `SpellingError.h` with
  `spell_checker_*` messages in `HubClient.ipc`.
- `navigator.credentials` Rust bindings (`LibWeb/Bindings/Rust/src/credential_management/
  credentials_container.rs`) reject `get()/store()/create()/preventSilentAccess()` with
  `NotImplemented` — M8 replaces stubs.
- In-tree SQLite wrapper is **Libraries/LibDatabase** (vcpkg sqlite3, used by
  `LibWebView/AutocompleteService`) — *not* "LibSQL" (name corrected per fact-check).
- Crypto: LibCrypto has **no** AES/GCM/HKDF/ECDH; use the already-vendored **OpenSSL::Crypto
  EVP** APIs (vcpkg openssl, linked PUBLIC by LibCrypto).
- `Web::TextEditingCommand` (`LibWebCommon/Page/TextEditingCommand.h`) contains only
  caret/delete commands — M7 must **extend** the seam with an insert-text command (or synthesized
  keydowns) **and fire site-visible `input`/`change` events**; budget a sub-PR for it.
- Issues: **#15541** is the open canonical credentials spec (duplicates #15652/#15683/#15685
  closed as dupes by trflynn89); **#15551** Qt does not implement macOS AutoFill XPC;
  **#751/#14821** track WebAuthn; all open as of 2026-11-27.
- Build: macOS first-class (Xcode 26 + Qt 6.10+); `Meta/CMake/utils.cmake` signs ad-hoc
  `codesign -s - -f`; `Meta/Entitlements.plist` currently has only audio-input/location.

Apple (verified against developer.apple.com; confidence noted):
- SecItem (`kSecClassGenericPassword` etc.) is fully public for an app's own items on the
  **file-based login keychain** — no entitlement needed; works on unsigned/ad-hoc dev builds.
  Access from a foreign app triggers the SecurityAgent Deny/Allow/Always-Allow prompt (per-item
  ACLs). (high)
- Data-protection keychain + access groups (`kSecAttrSynchronizable`) require
  provisioning-profile-authorized entitlements + app-like bundle — not usable on unsigned
  builds (TN3137, verbatim). (high)
- `ASAuthorizationPasswordProvider` (macOS 10.15+) and
  `ASAuthorizationWebBrowserPublicKeyCredentialManager` (macOS 13.3+): documented public APIs;
  Apple documents **no** entitlement/provisioning requirement; whether they work on ad-hoc
  builds is an **unvalidated empirical question** — probe before hardcoding `unavailable`
  (corrected per fact-check: the earlier blanket "requires paid provisioning" claim was
  inference). (medium — needs spike)
- AutoFill credential-provider registration requires the
  `com.apple.developer.authentication-services.autofill-credential-provider` entitlement
  (paid provisioning, host app AND extension). CXP (`ASCredentialExportManager/
  ASCredentialImportManager`, macOS 26.0+) participation is configured in the
  credential-provider extension's Info.plist. (high)
- macOS Passwords app: CSV-only documented migration on Mac (User Guide v3.0 / macOS 27);
  app-to-app CXP pairing with the Mac Passwords app is an **open question** → owner-run spike
  M12. (medium)
- `kSecAttrAccessibleWhenUnlocked` is a data-protection-keychain attribute, **ignored** on the
  file-based keychain — do not claim at-rest protection from it (TN3137; feasibility-check).
- macOS 27 `ASDeliveredVerificationCodesManager`: caller gating undocumented → probe-only until
  spike. `ASCredentialDataManager` (26.2+) for manager sync — helper-era only.

Prior art (licensing-safe reference only where GPL): Chrome macOS model (single 128-bit key in
keychain, own store) = the chosen shape; Bitwarden/KeePassXC/1Password helper protocols informed
the helper-era wire format; Chromium code is BSD-style and reusable-with-attribution;
KeePassXC/Bitwarden desktop are GPL-3.0 — behavioral reference only, no code reuse.

## 5. Approaches considered

**(A) In-browser Chrome model — CHOSEN.** Credential logic lives in Ladybird following the
SpellCheckerMac.mm precedent: LibWeb detects login forms at submit, relays
WebContent → Hub → UI over `.ipc`; the unsandboxed UI process owns the encrypted vault whose
master key is a `kSecClassGenericPassword` item ("Ladybird Safe Storage"). Works today on
unsigned builds; every layer offline-testable; smallest upstream conversation. Tradeoff:
plaintext secrets transit the UI process (same trust level as history/cookies today); ad-hoc
signing makes keychain ACLs churn across rebuilds (mitigations in §7).

**(B) Hub-spawned PasswordsServer helper — DEFERRED to post-MVP extraction.** Fits "Hub launches
all helpers" doctrine and removes plaintext from the UI process in principle. Rejected as MVP
because the phase-2 system APIs bind to the **calling app's** bundle/entitlements anyway (a
helper cannot hold them), so it buys marginal isolation now while adding build/sign artifacts
and slowing agent iteration. The M3 wire contract + `KeychainBackend` seam are designed so this
extraction stays a contained refactor.

**(C) Standalone manager app + system AutoFill provider extension (+CXP) — REJECTED for MVP,
kept as Phase-2 spike.** The only sanctioned door to system-vault data, but requires paid
provisioning to register, and is independently blocked by Ladybird's missing macOS AutoFill XPC
frontend (#15551). Its shape informs the `SystemVaultSource` adapter and capability negotiation
so a provider extension can be added without redesign (M12 spike).

## 6. Architecture (MVP)

All components live in the `randomm/ladybird-keychain-bridge` repo; the ones that physically
live inside Ladybird trees are developed against a **pinned Ladybird submodule/fork at HEAD
`09fa4834`** with a documented patch-set workflow (corrected per feasibility-check: M4–M8 cannot
build outside a Ladybird tree).

1. **KeychainBackend** — single seam to Security.framework.
   `ErrorOr<ByteBuffer> read_master_key()`, `write_master_key(…)`, `bool is_available()`.
   `SecItemKeychainBackend` (ObjC++, APPLE-only): `kSecClassGenericPassword`, service
   `"Ladybird Safe Storage"`, account `"Ladybird"`, 128-bit key, typed error mapping
   (`errSecInteractionNotAllowed` → explicit "keychain unavailable" UI state with retry;
   `errSecItemNotFound` → create-on-first-use). `FakeKeychainBackend` (in-memory) backs **all**
   tests and Linux CI. `scripts/real_keychain_smoke.sh` exists but is owner-run, never in CI.
   Master-key item is created with an explicit `SecAccessCreate` trusted-application list pinned
   to the designated requirement of the shipping binary (§7).

2. **Crypto layer** — OpenSSL::Crypto EVP: AES-256-GCM per-record encryption, HKDF,
   HMAC-SHA-256, ECDH (helper-era). Codecs are pure logic and separate fuzz targets.

3. **VaultStore** — records (origin(scheme+host+port), username, secret, timestamps, form meta,
   never-save markers) in SQLite via **Libraries/LibDatabase**; encrypted at rest per record;
   dedup/merge, update-on-change. Origin matching is **exact scheme+host+port** (§7); a
   registrable-domain grouping exists only for settings-page display.

4. **CredentialService** — policy + future CredentialSource router: save/update/delete
   decisions, never-for-this-site list, CSV import/export orchestration, capability report.
   **Enforces** re-auth gating itself (§7), not the UI page.

5. **LoginFormDetector (LibWeb)** — new consumer of `AutocompleteElement::parse_autocomplete_attribute()`;
   fires once per submit from `submit_form()/implicitly_submit_form()` (new page-client hook,
   mirroring `page_did_request_context_menu`). Emits
   `did_request_save_credentials(top_level_origin, frame_origin, submit_action_origin,
   username, secret, field_scope, frame_id)` — **all three origins** (§7). Headless tests at the
   hook boundary.

6. **IPC plumbing** — new `Credentials` messages in `WebContentClient.ipc`/`HubClient.ipc`
   (LibIPC codegen), routed by `PageId`, mirroring the spell-check round-trip. Payload struct
   defined in the detection milestone so its tests can assert it (ordering fix).

7. **CredentialClient (LibWebView) + UI/Qt/CredentialClientMac.mm** — UI-process client
   abstraction (SpellChecker shape). Drives Save / Not now / Never-for-this-site prompt
   (`PermissionPromptRequest` pattern) and the field-anchored autofill popup (Omnibox
   scripted-provider pattern for offline tests). Injection goes through an **extended**
   `TextEditingCommand` (new insert-text case) that fires site-visible `input`/`change`
   events, gated on user activation and a UI-process hit-test (§7).

8. **CredentialsContainer completion (Rust)** — implement `store()/get()/preventSilentAccess()`
   against CredentialService (replacing verified `NotImplemented` stubs); `get()` matching is
   **exact-origin**, no silent cross-subdomain fill.

9. **CredentialSettingsWebUI** — management page via `LibWebView/WebUI`: view/edit/delete/search
   (re-auth-gated by CredentialService), CSV import/export bidirectionally compatible with the
   Passwords app's documented CSV layout; golden-file round-trip tests; importer hardening (§7).

10. **SystemVaultSource (feature-probe adapter)** — probes for `ASAuthorizationPasswordProvider`
    per-site autofill, CXP managers, delivered-OTP, passkey readiness; availability enum
    `available / unvalidated_adhoc / unavailable_system_version / unavailable_unsigned`;
    unsigned builds degrade explicitly; probes validated on the owner-run signed matrix before
    any state is hardcoded.

11. **bridge_proto (codec + handshake lib)** — pure-logic framing/handshake for the **future**
    PasswordsServer helper (RFC 8785 JCS canonicalization or binary frames, sequence-numbered
    HMAC with domain separation, key confirmation, transcript binding to peer audit token — §7).
    Ships as a tested library in the MVP; **no socket is opened by the MVP**.

## 7. Security model (post-refutation; these were material findings)

**MVP (in-process; no external credential socket exists — deliberate):**
- No network listener, no world-readable socket. The only transports are Ladybird's own Mach IPC
  between processes the Hub itself exec'd. §6.11's handshake/peer-auth hardening is **helper-era
  (PasswordsServer extraction) work**, not MVP — recorded so it can never be skipped when B lands.
- **Fail-closed caller policy for the helper era:** pin designated requirements (cdhash+cert,
  which works for a stable local dev identity), abort credential-service startup when caller
  identity cannot be cryptographically verified; never silently skip `SecCodeCheckValidity`;
  log audit-token identity (pid, uid, cdhash, verdict) of every connect and rejection.
- **Origin keying (anti-harvesting):** credentials are stored keyed to the **frame origin that
  owns the fields**, and saving is offered only when the form's submit/action origin matches the
  frame origin; autofill and `credentials.get()` match the **exact stored (scheme, host, port)**
  of the requesting frame; `http` is never stored/returned except an explicit localhost+port
  opt-in. Registrable-domain logic never enables fill.
- **Origin stamped inside the trusted boundary** (LibWeb), never accepted from JS; the Hub
  cross-checks the LibWeb-stamped origin against its own tracked committed origin for the page
  (defense-in-depth against a compromised WebContent).
- **Re-auth enforced in CredentialService**: `list/export_csv/import_csv/delete_bulk` require a
  short-TTL capability token minted by LocalAuthentication (password-prompt fallback); if the LA
  probe is unavailable those methods **fail closed**. Lookups are rate-limited per page and bound
  to a Hub-minted page token (no username enumeration).
- **Autofill popup = explicit click only**: dismiss on scroll/blur/focus-loss/navigation;
  UI-process hit-test against the last-committed layout; reject synthetic events; injection
  requires user activation.
- **Secret hygiene (CI-checkable rules):** master key/secrets in zeroized, mlocked buffers where
  feasible; secrets banned from crash-report fields and persisted raw IPC buffers; the existing
  crash-report outbox must prove secret-free before release; document ReportCrash
  (`~/Library/Logs/DiagnosticReports`) exposure of the keychain-holding process and advise
  encrypted disk/swap; telemetry carries only counts/lengths/error codes.
- **Keychain ACL integrity:** master-key item gets a `SecAccessCreate` trusted-apps list pinned
  to the shipping designated requirement, re-pinned on update. Dev builds sign with a stable
  local identity whose private key is protected from unprivileged `codesign` use; "Always Allow"
  is documented but never relied on in CI. CI uses a **dedicated keychain** (never the user's
  login keychain) with `unlock-keychain` + `set-key-partition-list` scoped to it only.
  Never move the master key out of the keychain.
- **CSV hardening:** export warns plaintext secrets are being written to disk and suggests
  secure-delete afterwards (Apple's own guidance); formula-injection escaping (`=`, `+`, `-`,
  `@` prefixes); row/field/size caps; never auto-open or watch the path; import never auto-submits
  or fetches from field values.
- Sandboxing doctrine unchanged: Seatbelt helpers never get keychain access; credential I/O
  stays in the unsandboxed UI process (same as history/cookies today).

## 8. Milestones (each ≤ one-PR sized; splits from feasibility check)

- **M0** — Repo scaffold + CI + RFC: CMake/ctest presets (Linux+macOS jobs, mirroring Ladybird
  CI), LibTest scaffolding, clang-format/lint, README/CONTRIBUTING (offline-test rule),
  pinned-Ladybird submodule + patch-set workflow, design posted on #15541 cross-linking
  #751/#14821.
- **M1** — KeychainBackend seam: interface + Fake + SecItem adapter (APPLE-only) + typed errors
  + `real_keychain_smoke.sh` (owner-run).
- **M2a** AES-GCM codec + fuzz targets · **M2b** LibDatabase store + CRUD · **M2c** dedup/merge
  + update-on-change.
- **M3** — bridge_proto: framing, handshake, replay-window, golden vectors + fuzzing (library
  only; no socket in MVP).
- **M4** — LoginFormDetector + payload struct + page-client hook; headless assertions at the
  hook boundary (incl. regression cover for the autocomplete IDL getter).
- **M5** — IPC plumbing: Credentials messages in `WebContentClient.ipc`/`HubClient.ipc`,
  codegen, headless end-to-end submit → save-request to scripted UI client.
- **M6** — Save prompt: Qt Save/Not now/Never-for-this-site on the PermissionPromptRequest
  pattern; never-list persisted; decision tests.
- **M7a** scripted provider + field-anchored popup · **M7b** TextEditingCommand extension +
  site-visible events + hit-test/user-activation rules.
- **M8** — Credential Management API in Rust bindings + WPT-style tests (exact-origin get()).
- **M9a** re-auth-gated management list · **M9b** CSV import (hardening) · **M9c** CSV export
  (golden-file compat with Passwords app layout).
- **M10** — SystemVaultSource probes + capability negotiation; CI asserts degradation; empirical
  ad-hoc-build probe results recorded before any state is hardcoded.
- **M11** (owner-run) — passkey spike: ASAuthorizationWebBrowserPublicKeyCredentialManager on a
  Developer-ID-signed build → written report + reserved `webauthn_*` method shapes; no production
  credential code. Coordinate with #751/#14821.
- **M12** (owner-run) — CXP / AutoFill provider-extension paid-account feasibility spike →
  go/no-go doc + stub Info.plist (answers: does Mac Passwords app pair via CXP? can Developer ID
  builds register a provider?).

MVP = M0–M9 (+M10 probes).

## 9. Decisions made by the builder (owner may veto while reading)

1. **Chrome model in-browser (approach A) for MVP**, helper extraction deferred; rejected C is a
   spike. (Feasibility-verified seams; §5.)
2. **Repo layout:** standalone public repo, components as upstream-portable libraries against a
   pinned-Ladybird submodule; PRs upstream as appetite confirms on #15541; **no permanent fork**.
3. **Crypto:** OpenSSL EVP (already vendored by Ladybird) — no hand-rolled AES/GCM/HKDF.
4. **Storage:** LibDatabase (SQLite) + per-record AES-GCM; codec fuzzable independently of SQL.
5. **Master key:** 128-bit like Chrome; `kSecAttrAccessibleWhenUnlocked` set but documented as
   no-op on the file keychain (honest docs, per TN3137).
6. **Passkeys:** probes + owner spike only; WebAuthn web-platform stays with #14821.
7. **CSV-only for MVP**; KDBX reader is a later isolated plugin (the #15541 KDBX request).
8. **OTP:** `oneTimeCode` autocomplete affordance only until M11 empirics on
   ASDeliveredVerificationCodesManager.
9. **License: BSD-2-Clause** (Ladybird parity, cleanest upstream path; GPL projects stay
   behavioral reference only).
10. **Naming:** service `"Ladybird Safe Storage"`, account `"Ladybird"` (Chrome-parity, keeps the
    model recognizable to reviewers and users migrating from Chrome).
11. **`autocomplete="off"` is ignored for credential fields** (Chrome-like — the token is
    widely abused by sites as anti-UX; autofill of saved credentials still offers), while
    `new-password` semantics are honored (drives generation prompts). Builder call.
12. **CSV round-trip fidelity:** columns the vault schema does not model (TOTP secret, Notes,
    verified, created/modified) are **preserved verbatim** in an opaque per-record
    `extra_fields` blob and re-emitted on export — never silently dropped; imported TOTP
    secrets are stored but never surfaced to autofill until the OTP decision (decision 8) lands.
    Builder call; the golden-file fixture awaits a real export sample from the owner (§10.6).

## 10. Open for the owner (needs a ruling, not a guess)

1. **Login-flow coverage MVP must work on** — pinned detection is form-submit only; split-page
   two-step logins (Google/Microsoft/Apple account style) and form-less fetch/XHR logins are
   unaddressed. Options: (a) submit-only, documented limitation; (b) + password-field
   blur/Enter heuristic milestone M4b (catches most split-page password pages, Chrome-style
   heuristics, ~+1 PR on M4/M6/M7 policy); (c) + fetch/XHR interception (much larger).
   (Recommendation: (b) — split-page is the dominant real-world flow and (a) would fail the
   stated "easy" goal on the biggest sites.) Changes milestone sizing across M2c/M4/M6/M7.
2. **Upstreaming venue** — OK to post the design to Ladybird #15541 and send per-milestone PRs as
   appetite allows? (Recommendation: yes; fork is the failure mode.)
3. **Signing for the signed spikes (M11/M12)** — do you have / will you create a paid Apple
   Developer identity used solely for owner-run spikes? MVP needs none. (Recommendation: yes for
   spikes, nothing in CI.)
4. **Scope confirmation** — MVP = passwords only (§2); passkeys deliberately deferred to #14821
   coordination. (Recommendation: confirm.)
5. **Acceptance gate for owner-run tests** — CI can never touch a real keychain, so the SecItem
   adapter (M1) and probe states (M10) need owner-executed `real_keychain_smoke.sh` + probe
   matrix. Is "offline-green + unvalidated probes" an acceptable MVP ship state (gating only the
   release tag, not merges), or does MVP acceptance block on the owner runs? What cadence can
   you commit to? (Recommendation: gate release-tag only; owner runs per milestone batch.)
6. **CSV golden fixture** — Apple documents no column spec; please provide a `File > Export
   All Passwords` CSV sample from your Mac (its values will be scrubbed/redacted before
   committing, only the column shape is needed) so M9's round-trip tests match the real format.

## 11. Risks

- Maintainer appetite on #15541 decides upstream pace (mitigation: libraries-first, patch-set
  workflow, no fork).
- Ad-hoc-signing ACL churn (mitigation: stable dev identity, dedicated CI keychain; §7).
- "Unavailable" states for system APIs are inferences until the signed spikes run (mitigation:
  probes report `unvalidated_adhoc` honestly; nothing half-works silently).
- Qt AutoFill XPC (#15551) gates approach C entirely — Phase 2, owner spike decides.

## 12. Sources (key)

developer.apple.com: TN3137 (keychain implementations/APIs); Keychain Services (SecItem);
Access Control Lists; Sharing Access to Keychain Items; keychain-access-groups entitlement;
ASAuthorizationPasswordProvider / ASPasswordCredential; ASCredentialExportManager/
ASCredentialImportManager + ASCredentialProviderExtensionCapabilities (CXP, macOS 26.0+);
ASAuthorizationWebBrowserPublicKeyCredentialManager (macOS 13.3+); ASDeliveredVerificationCodesManager
(macOS 27.0); ASCredentialDataManager (26.2+); autofill-credential-provider entitlement.
github.com/LadybirdBrowser/ladybird @ 09fa4834: files cited in §4; issues #15541, #15551,
#14821, #751. google/chromium `keychain_password_mac.mm` (Chrome Safe Storage model).
KeePassXC (QLocalServer + crypto_box), Bitwarden desktop (native messaging host + ECDH
handshake), 1Password 8 (Mach IPC) — behavioral reference; 1Password onepassword-ipc-client
Apache-2.0 (optional helper-era dep); KeePassXC/Bitwarden GPL-3.0 reference-only.
