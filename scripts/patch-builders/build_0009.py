#!/usr/bin/env python3
"""Build patches/ladybird/0009-bridge-host.patch: the concrete
CredentialsBridgeDelegate (thin Qt type-converter over lkb::BridgeHost), its
Application wiring, and the LKB_BRIDGE_DIR-guarded CMake integration.

Same machinery as build_0708: restore the pinned tree, stack 0001..0008,
verify anchors, snapshot-diff, write the patch, restore clean."""
import os
import subprocess
import sys

import os as _os
BRIDGE_DEFAULT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
TREE = _os.environ.get("LKB_LADYBIRD_DIR", _os.path.join(_os.path.dirname(BRIDGE_DEFAULT), "ladybird-pinned"))
BRIDGE = BRIDGE_DEFAULT
PATCHES = os.path.join(BRIDGE, "patches/ladybird")
BASELINE = "/tmp/lkb-0009-baseline"


def sh(*args):
    r = subprocess.run(args, cwd=TREE, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"command failed: {args}\n{r.stdout}\n{r.stderr}")
    return r.stdout


sh("git", "checkout", "--", ".")
sh("git", "clean", "-fdq", "-e", ".codegraph")
if sh("git", "status", "--porcelain").strip():
    sys.exit("pinned tree is not clean")
for p in sorted(os.listdir(PATCHES)):
    if p.endswith(".patch") and p[:4] <= "0008":
        sh("git", "apply", os.path.join(PATCHES, p))

NEW_FILES = {}
EDITS = {}


def edit(path, old, new, owner="0009"):
    EDITS.setdefault(path, []).append((old, new, owner))


# ---------------- new files ----------------

NEW_FILES["UI/Qt/CredentialsBridgeHost.h"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/OwnPtr.h>
#include <UI/Qt/CredentialsPrompt.h>

namespace Ladybird {

// ladybird-keychain-bridge (M4-M9 host): the concrete delegate behind the save
// prompt, the autofill popup, navigator.credentials and about:credentials.
// Every vault decision lives in the bridge library's lkb::BridgeHost; this
// class only converts Ladybird types. Secrets follow the delegate contract:
// they never appear in suggestions or rows, and leave it only through
// secret_for() and a js_get answer — after the user chose them.
//
// try_create() returns null — explicitly, not silently — when the bridge
// library is not linked (configure without -DLKB_BRIDGE_DIR) or the
// keychain/vault cannot be opened; the UI then degrades by the defaults
// CredentialsBridgeDelegate already declares (no prompts, no autofill, an
// empty management page).
class CredentialsBridgeHost final : public CredentialsBridgeDelegate {
public:
    static OwnPtr<CredentialsBridgeHost> try_create();
    virtual ~CredentialsBridgeHost() override;

    virtual bool should_offer(Web::CredentialsSaveRequestPayload const&) override;
    virtual void did_decide(Web::CredentialsSaveRequestPayload const&, CredentialsPromptOutcome) override;

    virtual Vector<WebView::CredentialSuggestion> suggestions_for(Utf16String const&, Utf16String const&) override;
    virtual Utf16String secret_for(u64) override;

    virtual void js_get_credentials(Utf16String const& origin, bool allow_silent, bool password_requested,
                                    Function<void(bool found, Utf16String username, Utf16String secret)> on_complete) override;
    virtual void js_store_credentials(Utf16String const& origin, Utf16String const& username, Utf16String const& secret) override;
    virtual void js_prevent_silent_access(Utf16String const& origin, bool prevent) override;

    virtual Vector<CredentialRow> credentials_rows() override;
    virtual bool credentials_delete(u64) override;
    virtual bool credentials_delete_all(Utf16String const&) override;
    virtual Utf16String credentials_export_csv() override;

private:
    CredentialsBridgeHost();
    struct Impl;
    OwnPtr<Impl> m_impl; // null => bridge not linked; every method declines
};

}
'''

NEW_FILES["UI/Qt/CredentialsBridgeHost.cpp"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <UI/Qt/CredentialsBridgeHost.h>

#include <AK/ByteString.h>
#include <AK/Format.h>
#include <AK/Platform.h>
#include <AK/Utf16String.h>
#include <LibCore/StandardPaths.h>

#if defined(HAVE_LKB_BRIDGE) && defined(AK_OS_MACOS)
#    include "BridgeHost.h"
#    include "MasterKey.h"
#    include "SecItemKeychainBackend.h"

#    include <stdlib.h>
#endif

namespace Ladybird {

#if defined(HAVE_LKB_BRIDGE) && defined(AK_OS_MACOS)

namespace {

// The MVP host proves admin intent locally: the single-use/60 s TTL token
// contract is enforced inside CredentialService itself, and the two bulk
// actions additionally require a real click (consume_user_activation) on the
// page. Wiring a real redis-backed endpoint replaces this class only.
class LocalEchoAuth final : public lkb::RedisAuthCallback {
public:
    virtual lkb::ErrorOr<std::string> request_token() override
    {
        char buf[16];
        arc4random_buf(buf, sizeof(buf));
        ByteString hex;
        for (auto byte : ReadonlyBytes { reinterpret_cast<u8 const*>(buf), sizeof(buf) })
            hex = ByteString::formatted("{}{:02x}", hex, byte).release_value_but_fixme_should_propagate_errors();
        return lkb::ErrorOr<std::string>::ok(std::string(hex.characters()));
    }
};

ByteString to_bs(Utf16String const& s) { return s.to_byte_string(); }
Utf16String to_u16(std::string const& s) { return Utf16String::from_utf8(s); }

}

struct CredentialsBridgeHost::Impl {
    Impl(lkb::SecItemKeychainBackend backend, lkb::VaultStore vault)
        : backend(move(backend))
        , vault(move(vault))
        , service(this->vault, clock)
        , host(service, auth, clock)
    {
    }

    lkb::SecItemKeychainBackend backend;
    lkb::VaultStore vault;
    LocalEchoAuth auth;
    lkb::SystemClock clock;
    lkb::CredentialService service;
    lkb::BridgeHost host;
};

OwnPtr<CredentialsBridgeHost> CredentialsBridgeHost::try_create()
{
    // Chrome-parity naming (spec §9): the master key item is
    // service "Ladybird Safe Storage", account "Ladybird", in the default
    // keychain. A failure here is logged as a capability state, never a hint
    // at secret material.
    auto backend = lkb::SecItemKeychainBackend::create("Ladybird Safe Storage", "Ladybird", std::nullopt);
    if (backend.is_error()) {
        dbgln("ladybird-keychain-bridge: keychain unavailable ({}); credentials stay off",
              backend.error().message);
        return nullptr;
    }
    auto key = lkb::master_key_or_create(backend.value(), lkb::default_master_key_rng);
    if (key.is_error()) {
        dbgln("ladybird-keychain-bridge: master key unavailable ({}); credentials stay off",
              key.error().message);
        return nullptr;
    }
    auto db_path = ByteString::formatted("{}/ladybird-credentials-vault.db", Core::StandardPaths::data_directory());
    auto vault = lkb::VaultStore::open(std::string(db_path.to_byte_string().characters()), key.value());
    if (vault.is_error()) {
        dbgln("ladybird-keychain-bridge: vault unavailable ({}); credentials stay off",
              vault.error().message);
        return nullptr;
    }
    auto host = make<CredentialsBridgeHost>();
    host->m_impl = make<Impl>(backend.release_value(), vault.release_value());
    return host;
}

CredentialsBridgeHost::CredentialsBridgeHost() = default;
CredentialsBridgeHost::~CredentialsBridgeHost() = default;

bool CredentialsBridgeHost::should_offer(Web::CredentialsSaveRequestPayload const& payload)
{
    if (!m_impl)
        return false;
    return m_impl->host.should_offer(to_bs(payload.frame_origin), to_bs(payload.submit_action_origin),
                                     to_bs(payload.username));
}

void CredentialsBridgeHost::did_decide(Web::CredentialsSaveRequestPayload const& payload,
                                       CredentialsPromptOutcome outcome)
{
    if (!m_impl)
        return;
    // Dismissed leaves the vault untouched: NotNow is the service's no-op
    // route; only NeverForSite writes anything (the never-list).
    auto mapped = outcome == CredentialsPromptOutcome::Saved
        ? lkb::BridgeHost::Outcome::Save
        : outcome == CredentialsPromptOutcome::NeverForSite ? lkb::BridgeHost::Outcome::NeverForSite
                                                            : lkb::BridgeHost::Outcome::NotNow;
    m_impl->host.did_decide(to_bs(payload.frame_origin), to_bs(payload.top_level_origin),
                            to_bs(payload.submit_action_origin), to_bs(payload.username),
                            to_bs(payload.secret), mapped);
}

Vector<WebView::CredentialSuggestion> CredentialsBridgeHost::suggestions_for(Utf16String const& origin,
                                                                             Utf16String const&)
{
    Vector<WebView::CredentialSuggestion> out;
    if (!m_impl)
        return out;
    for (auto const& suggestion : m_impl->host.suggestions_for(to_bs(origin)))
        out.append(WebView::CredentialSuggestion { static_cast<u64>(suggestion.id),
                                                   to_u16(suggestion.username), to_u16(suggestion.label) });
    return out;
}

Utf16String CredentialsBridgeHost::secret_for(u64 id)
{
    if (!m_impl)
        return {};
    auto secret = m_impl->host.take_secret(id);
    return secret.has_value() ? to_u16(*secret) : Utf16String {};
}

void CredentialsBridgeHost::js_get_credentials(Utf16String const& origin, bool allow_silent,
                                               bool password_requested,
                                               Function<void(bool, Utf16String, Utf16String)> on_complete)
{
    if (!m_impl) {
        on_complete(false, {}, {});
        return;
    }
    auto hit = m_impl->host.js_get(to_bs(origin), allow_silent, password_requested);
    if (!hit.has_value()) {
        on_complete(false, {}, {});
        return;
    }
    on_complete(true, to_u16(hit->first), to_u16(hit->second));
}

void CredentialsBridgeHost::js_store_credentials(Utf16String const& origin, Utf16String const& username,
                                                 Utf16String const& secret)
{
    if (m_impl)
        m_impl->host.js_store(to_bs(origin), to_bs(username), to_bs(secret));
}

void CredentialsBridgeHost::js_prevent_silent_access(Utf16String const& origin, bool prevent)
{
    if (m_impl)
        m_impl->host.js_prevent_silent(to_bs(origin), prevent);
}

Vector<CredentialsBridgeHost::CredentialRow> CredentialsBridgeHost::credentials_rows()
{
    Vector<CredentialRow> out;
    if (!m_impl)
        return out;
    for (auto const& row : m_impl->host.rows())
        out.append(CredentialRow { to_u16(row.origin), to_u16(row.username), static_cast<u64>(row.id) });
    return out;
}

bool CredentialsBridgeHost::credentials_delete(u64 id)
{
    return m_impl && m_impl->host.remove(static_cast<i64>(id));
}

bool CredentialsBridgeHost::credentials_delete_all(Utf16String const& origin)
{
    return m_impl && m_impl->host.remove_all(to_bs(origin));
}

Utf16String CredentialsBridgeHost::credentials_export_csv()
{
    if (!m_impl)
        return {};
    auto csv = m_impl->host.export_csv();
    return csv.has_value() ? to_u16(*csv) : Utf16String {};
}

#else // no bridge linked (or not macOS): explicit, silent-by-default declines

struct CredentialsBridgeHost::Impl { };

OwnPtr<CredentialsBridgeHost> CredentialsBridgeHost::try_create() { return nullptr; }

CredentialsBridgeHost::CredentialsBridgeHost() = default;
CredentialsBridgeHost::~CredentialsBridgeHost() = default;

bool CredentialsBridgeHost::should_offer(Web::CredentialsSaveRequestPayload const&) { return false; }

void CredentialsBridgeHost::did_decide(Web::CredentialsSaveRequestPayload const&, CredentialsPromptOutcome) { }

Vector<WebView::CredentialSuggestion> CredentialsBridgeHost::suggestions_for(Utf16String const&, Utf16String const&)
{
    return {};
}

Utf16String CredentialsBridgeHost::secret_for(u64) { return {}; }

void CredentialsBridgeHost::js_get_credentials(Utf16String const&, bool, bool,
                                               Function<void(bool, Utf16String, Utf16String)> on_complete)
{
    on_complete(false, {}, {});
}

void CredentialsBridgeHost::js_store_credentials(Utf16String const&, Utf16String const&, Utf16String const&) { }

void CredentialsBridgeHost::js_prevent_silent_access(Utf16String const&, bool) { }

Vector<CredentialsBridgeHost::CredentialRow> CredentialsBridgeHost::credentials_rows() { return {}; }

bool CredentialsBridgeHost::credentials_delete(u64) { return false; }

bool CredentialsBridgeHost::credentials_delete_all(Utf16String const&) { return false; }

Utf16String CredentialsBridgeHost::credentials_export_csv() { return {}; }

#endif

}
'''

# ---------------- Application wiring ----------------

edit("UI/Qt/Application.cpp",
     "#include <UI/Qt/CredentialSettingsPage.h>",
     "#include <UI/Qt/CredentialSettingsPage.h>\n#include <UI/Qt/CredentialsBridgeHost.h>")

edit("UI/Qt/Application.cpp",
     """    m_web_ui_pages->register_page("credentials"_string, "Credentials"_string, [](u64 web_ui_id, WebView::IsPrivate) -> NonnullOwnPtr<WebUIPage> {
        return make<CredentialSettingsPage>(web_ui_id);
    });""",
     """    m_web_ui_pages->register_page("credentials"_string, "Credentials"_string, [](u64 web_ui_id, WebView::IsPrivate) -> NonnullOwnPtr<WebUIPage> {
        return make<CredentialSettingsPage>(web_ui_id);
    });

    // ladybird-keychain-bridge: register the vault-backed delegate. A null
    // host (no bridge linked, or the keychain/vault refused us) leaves every
    // UI surface at its declared default — nothing half-works silently.
    m_credentials_host = CredentialsBridgeHost::try_create();
    if (m_credentials_host)
        set_credentials_bridge_delegate(m_credentials_host.ptr());""")

edit("UI/Qt/Application.h",
     "#include <UI/Qt/ApplicationActions.h>",
     "namespace Ladybird { class CredentialsBridgeHost; }\n\n#include <UI/Qt/ApplicationActions.h>")

edit("UI/Qt/Application.h",
     "    OwnPtr<WebUIPages> m_web_ui_pages;",
     "    OwnPtr<WebUIPages> m_web_ui_pages;\n    OwnPtr<CredentialsBridgeHost> m_credentials_host; // ladybird-keychain-bridge")

# ---------------- CMake: sources + guarded library link ----------------

edit("UI/Qt/CMakeLists.txt",
     "    CredentialSettingsPage.cpp\n    HistoryPage.cpp",
     "    CredentialBridgeHost.cpp\n    CredentialSettingsPage.cpp\n    HistoryPage.cpp")

edit("UI/Qt/CMakeLists.txt",
     "target_link_libraries(ladybird_impl PRIVATE LibDatabase LibFileSystem LibUnicode)",
     """target_link_libraries(ladybird_impl PRIVATE LibDatabase LibFileSystem LibUnicode)

# ladybird-keychain-bridge host: link the vault libraries from a bridge checkout
# (docs/integration.md) and let CredentialsBridgeHost.cpp compile its real body.
# Without -DLKB_BRIDGE_DIR the file compiles to explicit declines.
if(DEFINED LKB_BRIDGE_DIR)
    add_subdirectory(${LKB_BRIDGE_DIR} ${CMAKE_BINARY_DIR}/lkb-bridge EXCLUDE_FROM_ALL)
    target_compile_definitions(ladybird_impl PRIVATE HAVE_LKB_BRIDGE=1)
    target_link_libraries(ladybird_impl PRIVATE lkb_bridgehost)
    if(APPLE)
        target_link_libraries(ladybird_impl PRIVATE lkb_secitem)
    endif()
endif()""")

# ---------------- verify ALL anchors ----------------
for path, pairs in EDITS.items():
    full = os.path.join(TREE, path)
    if not os.path.exists(full):
        sys.exit(f"missing file {path}")
    text = open(full).read()
    for old, new, owner in pairs:
        n = text.count(old)
        if n != 1:
            sys.exit(f"anchor count {n} (want 1) in {path} owner {owner}: {old[:80]!r}")
        text = text.replace(old, new, 1)
print("anchors OK:", sum(len(v) for v in EDITS.values()), "edits across", len(EDITS), "files")

# ---------------- snapshot, apply, diff, write ----------------
subprocess.run(["rm", "-rf", BASELINE], check=True)
os.makedirs(BASELINE)
for path in list(EDITS) + list(NEW_FILES):
    src = os.path.join(TREE, path)
    if os.path.exists(src):
        dst = os.path.join(BASELINE, path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        subprocess.run(["cp", src, dst], check=True)

for path, pairs in EDITS.items():
    full = os.path.join(TREE, path)
    text = open(full).read()
    for old, new, _ in pairs:
        text = text.replace(old, new, 1)
    open(full, "w").write(text)

for path, content in NEW_FILES.items():
    full = os.path.join(TREE, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    open(full, "w").write(content)
    sh("git", "add", "-N", "--", path)

import tempfile


def hunks_between(prev_text, next_text):
    if prev_text == next_text:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".a", delete=False) as fa, \
            tempfile.NamedTemporaryFile("w", suffix=".b", delete=False) as fb:
        fa.write(prev_text)
        fb.write(next_text)
        pa, pb = fa.name, fb.name
    r = subprocess.run(["diff", "-u", "-U3", pa, pb], capture_output=True, text=True)
    os.unlink(pa)
    os.unlink(pb)
    lines = r.stdout.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.startswith("@@"):
            start = i
            break
    else:
        return []
    out, cur = [], None
    for ln in lines[start:]:
        if ln.startswith("@@"):
            if cur is not None:
                out.append(cur)
            cur = [ln]
        elif cur is not None:
            cur.append(ln)
    if cur is not None:
        out.append(cur)
    return out


body = []
for path in sorted(list(EDITS) + list(NEW_FILES)):
    final_text = open(os.path.join(TREE, path)).read()
    baseline_path = os.path.join(BASELINE, path)
    base_text = open(baseline_path).read() if os.path.exists(baseline_path) else None
    hunks = hunks_between(base_text if base_text is not None else "", final_text)
    if not hunks:
        continue
    if base_text is None:
        header = ["diff --git a/%s b/%s\n" % (path, path),
                  "new file mode 100644\n", "--- /dev/null\n", "+++ b/%s\n" % path]
    else:
        header = ["diff --git a/%s b/%s\n" % (path, path),
                  "--- a/%s\n" % path, "+++ b/%s\n" % path]
    body.append("".join(header) + "".join("".join(h) for h in hunks))

header = ("From ladybird-keychain-bridge patch-set — apply with `git apply` "
          "on the pinned Ladybird tree (09fa4834) as a stack, in numeric order.\n"
          "0009: the concrete vault delegate — CredentialsBridgeHost, Application registration, CMake (M4-M9 host).\n\n")
with open(os.path.join(PATCHES, "0009-bridge-host.patch"), "w") as f:
    f.write(header + "".join(body))
print("wrote 0009-bridge-host.patch files:", sum(b.count("diff --git") for b in body))

sh("git", "reset")
sh("git", "checkout", "--", ".")
sh("git", "clean", "-fdq", "-e", ".codegraph")
assert sh("git", "status", "--porcelain").strip() == "", "tree not clean after restore"
print("tree restored clean")
