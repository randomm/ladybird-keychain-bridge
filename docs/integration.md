# Building Ladybird with the credentials bridge

The bridge ships as (a) portable libraries in this repo and (b) a nine-patch
stack applied to the pinned Ladybird tree. The browser only becomes a password
manager when the Qt UI process links the libraries — patch 0009 wires that
behind `-DLKB_BRIDGE_DIR`.

## Steps (owner-run build; CI never compiles the browser)

```sh
sh scripts/sync_ladybird.sh                       # pinned tree at ../ladybird-pinned
cd ../ladybird-pinned
for p in ../ladybird-keychain-bridge/patches/ladybird/000*.patch; do git apply "$p"; done

# Configure the browser against the bridge checkout (flag through your tree's
# usual configure procedure; the bridge-specific part is just the define):
cmake -S . -B ../ladybird-build <your usual flags> \
      -DLKB_BRIDGE_DIR="$PWD/../ladybird-keychain-bridge"
cmake --build ../ladybird-build --target ladybird
```

(Match the configure flags to your Ladybird tree's documented build procedure;
the only bridge-specific flag is `-DLKB_BRIDGE_DIR`.)

## What the flag does

- **With `-DLKB_BRIDGE_DIR`**: `UI/Qt/CredentialsBridgeHost.cpp` compiles its
  real body — it opens the master key (keychain item service
  `Ladybird Safe Storage`, account `Ladybird`), opens
  `$(data_directory)/ladybird-credentials-vault.db`, and registers the
  concrete `CredentialsBridgeDelegate`. Save prompts, the autofill popup,
  `navigator.credentials` and `about:credentials` become live.
- **Without it** (or off macOS): the same file compiles to explicit declines.
  No prompts, no popup, `navigator.credentials.get()` resolves `null`,
  `about:credentials` is empty. Nothing half-works silently.
- **Bootstrap failure** (keychain locked, vault corrupt): the host logs one
  capability line and registers nothing — identical degradation. Error text
  never contains secret material.

## Admin re-auth in the MVP host

`CredentialService` enforces the admin gate itself: every list/delete/export
call consumes a fresh single-use, 60-second `CapabilityToken`. The in-tree host
mints tokens from a local entropy source (`LocalEchoAuth`) and the two bulk
actions (CSV export, delete-all-for-site) additionally require a genuine user
click on the page (`consume_user_activation`) and, for delete-all, a confirm.
Pointing the host at a real redis-backed confirmation endpoint means replacing
that one class in `UI/Qt/CredentialsBridgeHost.cpp` — the service contract is
unchanged.

## Never

- Never point the browser build at the login keychain via a `--keychain`-style
  path; the dedicated-keychain mode exists for the owner-run probe/smoke tools
  only.
- CI never builds the browser (offline doctrine); `check_patches.sh` proves the
  stack applies, `run_tests.sh` proves the libraries, and
  `scripts/syntax_check_ui.sh` (wired into `run_tests.sh`) proves the patched
  UI translation units COMPILE against the pinned tree — the browser build
  itself remains the owner's release step.
