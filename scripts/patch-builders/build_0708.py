#!/usr/bin/env python3
"""Build patches 0007-credentials-container + 0008-credential-settings-webui
against the pinned Ladybird tree. Stack 0001..0006, verify ALL anchors, apply,
snapshot-diff per file, classify hunks by edit owner, write the two patch files,
restore the tree clean."""
import os
import subprocess
import sys

import os as _os
BRIDGE_DEFAULT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
TREE = _os.environ.get("LKB_LADYBIRD_DIR", _os.path.join(_os.path.dirname(BRIDGE_DEFAULT), "ladybird-pinned"))
BRIDGE = BRIDGE_DEFAULT
PATCHES = os.path.join(BRIDGE, "patches/ladybird")
BASELINE = "/tmp/lkb-0708-baseline"


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
    if p.endswith(".patch") and p[:4] <= "0006":
        sh("git", "apply", os.path.join(PATCHES, p))

NEW_FILES = {}      # path -> content (created, then git add -N)
EDITS = {}


def edit(path, old, new, owner):
    EDITS.setdefault(path, []).append((old, new, owner))


# ===================== 0007: navigator.credentials (Rust) =====================

CONTAINER_NEW = r'''/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! CredentialsContainer, https://w3c.github.io/webappsec-credential-management/#credentialscontainer

use core::cell::RefCell;
use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ak::Utf16String;
use libjs_rust::api::{ErrorKind, ErrorType, GcWeak, PromiseCapability, Trace, Value, Vm};
use liburl_rust::origin::Origin;

use super::credential::{AnyCredential, CredentialData, CredentialMediationRequirement};
use super::federated_credential::{FederatedCredentialInit, FederatedCredentialRequestOptions};
use super::password_credential::{PasswordCredentialData, PasswordCredentialInit};
use super::password_credential_operations::create_password_credential_from_data;
use crate::bindings::conversions::UsvString;
use crate::bindings::environment_settings_object::relevant_settings_object;
use crate::bindings::interface::{Ref, Wrappable, allocate, cell_into_abi};
use crate::bindings::promise::{WebIdlPromise, reject_promise_with_exception, resolve_promise};
use crate::bindings::{CallContext, Exception, WebIdlResult};
use crate::dom::abort_signal::AbortSignal;

/// https://w3c.github.io/webappsec-credential-management/#dictdef-credentialrequestoptions
#[expect(dead_code, reason = "get() does not read the options yet")]
pub(crate) struct CredentialRequestOptions {
    pub(crate) federated: Option<FederatedCredentialRequestOptions>,
    pub(crate) mediation: CredentialMediationRequirement,
    pub(crate) password: bool,
    pub(crate) signal: Option<Ref<AbortSignal>>,
}

/// https://w3c.github.io/webappsec-credential-management/#dictdef-credentialcreationoptions
#[expect(dead_code, reason = "create() does not read the options yet")]
pub(crate) struct CredentialCreationOptions {
    pub(crate) federated: Option<FederatedCredentialInit>,
    pub(crate) mediation: CredentialMediationRequirement,
    pub(crate) password: Option<PasswordCredentialInit>,
    pub(crate) signal: Option<Ref<AbortSignal>>,
}

thread_local! {
    /// In-flight get() promises awaiting the vault-backed answer that the UI process hands over
    /// through resolve_js_get_credentials. Held weakly: if the page (and with it the promise)
    /// is collected before the answer arrives, the entry settles itself on the next prune.
    static PENDING_GET: RefCell<HashMap<u64, (GcWeak<PromiseCapability>, Origin)>> = RefCell::new(HashMap::new());
}
static NEXT_GET_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" {
    /// Sends the get() request to the UI process; the answer arrives on the main thread and calls
    /// web_rust_credentials_get_resolved.
    fn lkb_bridge_request_credentials_get(request_id: u64, password_requested: bool, allow_silent: bool);

    /// Sends a store() credential to the UI process; store() resolves without an answer. The
    /// strings cross the boundary as UTF-8 — AK compacts ASCII to one byte per unit, so raw
    /// code-unit pointers are not a sound FFI representation.
    fn lkb_bridge_store_credentials(
        username_utf8: *const u8,
        username_bytes: usize,
        secret_utf8: *const u8,
        secret_bytes: usize,
    );

    /// Records that this origin no longer allows silent access.
    fn lkb_bridge_prevent_silent_access();
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct CredentialsContainer;

impl Wrappable for CredentialsContainer {}

fn reject_not_implemented_promise(vm: &Vm, promise: WebIdlPromise, operation: &str) {
    let throw = vm
        .throw_completion::<()>(ErrorKind::InternalError, ErrorType::NotImplemented, &[&operation])
        .expect_err("throwing a completion throws");
    reject_promise_with_exception(vm, promise, Exception::from(throw));
}

impl CredentialsContainer {
    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get
    pub(crate) fn get(
        &self,
        cx: &mut CallContext,
        promise: WebIdlPromise,
        options: CredentialRequestOptions,
    ) -> WebIdlResult<()> {
        // The only credential type this bridge answers for is password; a get()
        // that did not ask for password credentials resolves null without
        // touching the vault (spec step: skip password credentials).
        if !options.password {
            resolve_promise(cx.vm(), promise, Value::NULL);
            return Ok(());
        }
        // The answer comes from the vault in the UI process; mediation: silent is the only
        // requirement that suppresses it, and matching is exact-origin there.
        let request_id = NEXT_GET_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let origin = relevant_settings_object(cx.realm().global_object()).origin();
        let allow_silent = !matches!(options.mediation, CredentialMediationRequirement::Silent);
        let weak = GcWeak::new(cx.vm().heap(), promise);
        PENDING_GET.with(|pending| {
            let mut pending = pending.borrow_mut();
            // Answers that never arrive (a view that died mid-flight) must not
            // grow this map: past a bound, drop entries whose promise is gone.
            if pending.len() > 64 {
                pending.retain(|_, (weak, _)| weak.get().is_some());
            }
            pending.insert(request_id, (weak, origin));
        });
        // SAFETY: The request carries only integers.
        unsafe { lkb_bridge_request_credentials_get(request_id, options.password, allow_silent) };
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-store
    pub(crate) fn store(&self, cx: &mut CallContext, promise: WebIdlPromise, credential: AnyCredential) -> WebIdlResult<()> {
        let AnyCredential::PasswordCredential(password_credential) = credential else {
            let throw = cx
                .vm()
                .throw_completion_with_utf16_message::<()>(
                    ErrorKind::TypeError,
                    Utf16String::from_utf8("only password credentials can be stored"),
                )
                .expect_err("throwing a completion throws");
            reject_promise_with_exception(cx.vm(), promise, Exception::from(throw));
            return Ok(());
        };
        // UTF-8 across the boundary: AK's compact storage has no stable
        // code-unit pointer, and UTF-8 is the one encoding both sides agree on.
        let username = password_credential.bridge_username().to_utf8();
        let secret = password_credential.bridge_password().to_utf8();
        // SAFETY: The UTF-8 buffers are alive for the duration of the call.
        unsafe {
            lkb_bridge_store_credentials(
                username.as_ptr(),
                username.len(),
                secret.as_ptr(),
                secret.len(),
            )
        };
        resolve_promise(cx.vm(), promise, Value::UNDEFINED);
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create
    pub(crate) fn create(
        &self,
        cx: &mut CallContext,
        promise: WebIdlPromise,
        _: CredentialCreationOptions,
    ) -> WebIdlResult<()> {
        reject_not_implemented_promise(cx.vm(), promise, "create");
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-preventsilentaccess
    pub(crate) fn prevent_silent_access(&self, cx: &mut CallContext, promise: WebIdlPromise) -> WebIdlResult<()> {
        // SAFETY: The request carries no borrowed data.
        unsafe { lkb_bridge_prevent_silent_access() };
        resolve_promise(cx.vm(), promise, Value::UNDEFINED);
        Ok(())
    }
}

/// Called by Libraries/LibWeb/CredentialManagement/CredentialsContainerBridge.cpp when the UI
/// process answers a get() request. Runs on the WebContent main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_rust_credentials_get_resolved(
    vm: &Vm,
    request_id: u64,
    found: bool,
    username_utf8: *const u8,
    username_bytes: usize,
    secret_utf8: *const u8,
    secret_bytes: usize,
) {
    let Some((weak_promise, origin)) = PENDING_GET.with(|pending| pending.borrow_mut().remove(&request_id)) else {
        return; // the page went away; nobody awaits this answer
    };
    let Some(promise) = weak_promise.get() else {
        return; // the promise was collected before the answer landed
    };
    if !found {
        resolve_promise(vm, promise, Value::NULL);
        return;
    }
    // SAFETY: The C++ buffers outlive the synchronous call and carry UTF-8.
    let username = unsafe { core::str::from_utf8(core::slice::from_raw_parts(username_utf8, username_bytes)) };
    let secret = unsafe { core::str::from_utf8(core::slice::from_raw_parts(secret_utf8, secret_bytes)) };
    let (Ok(username), Ok(secret)) = (username, secret) else {
        resolve_promise(vm, promise, Value::NULL); // defensive: the bridge always sends UTF-8
        return;
    };
    if username.is_empty() {
        resolve_promise(vm, promise, Value::NULL); // a password credential needs an id
        return;
    }
    let data = PasswordCredentialData {
        parent: CredentialData { id: UsvString::from_utf8(username) },
        icon_url: None,
        name: Some(UsvString::from_utf8(username)),
        password: UsvString::from_utf8(secret),
    };
    match create_password_credential_from_data(vm, data, origin) {
        Ok(credential) => resolve_promise(vm, promise, Value::from_object(credential)),
        Err(exception) => reject_promise_with_exception(vm, promise, exception),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn web_rust_credentials_container_create(vm: &Vm) -> *mut c_void {
    cell_into_abi(allocate(vm, |_| CredentialsContainer))
}
'''

CONTAINER_OLD = open(os.path.join(TREE, "Libraries/LibWeb/Bindings/Rust/src/credential_management/credentials_container.rs")).read()
edit("Libraries/LibWeb/Bindings/Rust/src/credential_management/credentials_container.rs",
     CONTAINER_OLD, CONTAINER_NEW, "0007")

# PasswordCredential / Credential accessors for the bridge.
edit("Libraries/LibWeb/Bindings/Rust/src/credential_management/password_credential.rs",
     """impl Wrappable for PasswordCredential {}""",
     """impl PasswordCredential {
    /// Plain (non-IDL) reads for the credential bridge; the IDL getters need a CallContext.
    pub(crate) fn bridge_username(&self) -> &UsvString {
        self.credential.bridge_id()
    }

    pub(crate) fn bridge_password(&self) -> &UsvString {
        &self.password
    }
}

impl Wrappable for PasswordCredential {}""", "0007")

edit("Libraries/LibWeb/Bindings/Rust/src/credential_management/credential.rs",
     """impl Wrappable for Credential {}""",
     """impl Credential {
    /// Plain (non-IDL) read of [[id]] for the credential bridge.
    pub(crate) fn bridge_id(&self) -> &UsvString {
        &self.id
    }
}

impl Wrappable for Credential {}""", "0007")

# (No conversions.rs edit: UsvString::from_utf8 / to_utf8 already exist — the
# bridge crosses the FFI boundary in UTF-8 instead of raw code units.)

NEW_FILES["Libraries/LibWeb/CredentialManagement/CredentialsContainerBridge.cpp"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Utf16String.h>
#include <LibJS/HostClassBuilder.h>
#include <LibWeb/Bindings/MainThreadVM.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/Page/Page.h>

namespace Web::CredentialManagement {

extern "C" {
// Defined in Bindings/Rust/src/credential_management/credentials_container.rs. Strings cross as
// UTF-8: AK's compact Utf16String has no stable code-unit pointer to hand over.
void web_rust_credentials_get_resolved(JSVM*, u64 request_id, bool found, char const* username_utf8,
                                       size_t username_bytes, char const* secret_utf8, size_t secret_bytes);
}

namespace {

// The document whose script called the CredentialsContainer; WebContent runs one VM on the main
// thread, and these calls arrive synchronously from a running script.
HTML::Document* current_credentials_document()
{
    auto& realm = *Bindings::main_thread_vm().active_realm();
    auto* window = as_if<HTML::Window>(&realm.global_object());
    if (!window)
        return nullptr;
    return window->document();
}

Utf16String utf16_from_utf8_ffi(char const* data, size_t bytes)
{
    if (!data || bytes == 0)
        return {};
    return Utf16String::from_utf8_with_replacement_character(StringView { data, bytes });
}

}

extern "C" {

void lkb_bridge_request_credentials_get(u64 request_id, bool password_requested, bool allow_silent)
{
    auto* document = current_credentials_document();
    if (!document) {
        auto& vm = Bindings::main_thread_vm();
        web_rust_credentials_get_resolved(JS::HostABI::vm_to_abi(vm), request_id, false, nullptr, 0, nullptr, 0);
        return;
    }
    document->page().did_request_js_get_credentials(request_id,
        Utf16String::from_utf8(document->origin().serialize()), allow_silent, password_requested);
}

void lkb_bridge_store_credentials(char const* username_utf8, size_t username_bytes,
                                  char const* secret_utf8, size_t secret_bytes)
{
    auto* document = current_credentials_document();
    if (!document)
        return;
    document->page().did_request_js_store_credentials(
        Utf16String::from_utf8(document->origin().serialize()),
        utf16_from_utf8_ffi(username_utf8, username_bytes),
        utf16_from_utf8_ffi(secret_utf8, secret_bytes));
}

void lkb_bridge_prevent_silent_access()
{
    auto* document = current_credentials_document();
    if (!document)
        return;
    document->page().did_request_js_prevent_silent_access(Utf16String::from_utf8(document->origin().serialize()));
}

void lkb_bridge_on_js_get_resolved(u64 request_id, bool found, Utf16String const& username, Utf16String const& secret)
{
    auto& vm = Bindings::main_thread_vm();
    auto username_utf8 = username.to_byte_string(AllowLonelySurrogates::Yes);
    auto secret_utf8 = secret.to_byte_string(AllowLonelySurrogates::Yes);
    web_rust_credentials_get_resolved(JS::HostABI::vm_to_abi(vm), request_id, found,
        username_utf8.characters(), username_utf8.byte_count(),
        secret_utf8.characters(), secret_utf8.byte_count());
}

}

}
'''

edit("Libraries/LibWeb/CMakeLists.txt",
     "    CredentialManagement/CredentialsContainer.cpp",
     "    CredentialManagement/CredentialsContainer.cpp\n    CredentialManagement/CredentialsContainerBridge.cpp", "0007")

# Page hooks.
edit("Libraries/LibWeb/Page/Page.h",
     """    virtual void page_did_request_credential_suggestions([[maybe_unused]] URL::Origin origin, [[maybe_unused]] HTML::CrossProcessId local_root_id, [[maybe_unused]] Web::CSSPixelPoint content_position, [[maybe_unused]] Web::CSSPixels minimum_width, [[maybe_unused]] Utf16String field_kind, [[maybe_unused]] u64 fill_token) { }""",
     """    virtual void page_did_request_credential_suggestions([[maybe_unused]] URL::Origin origin, [[maybe_unused]] HTML::CrossProcessId local_root_id, [[maybe_unused]] Web::CSSPixelPoint content_position, [[maybe_unused]] Web::CSSPixels minimum_width, [[maybe_unused]] Utf16String field_kind, [[maybe_unused]] u64 fill_token) { }

    virtual void page_did_request_js_get_credentials([[maybe_unused]] u64 request_id, [[maybe_unused]] Utf16String origin, [[maybe_unused]] bool allow_silent, [[maybe_unused]] bool password_requested) { }
    virtual void page_did_request_js_store_credentials([[maybe_unused]] Utf16String origin, [[maybe_unused]] Utf16String username, [[maybe_unused]] Utf16String secret) { }
    virtual void page_did_request_js_prevent_silent_access([[maybe_unused]] Utf16String origin) { }""", "0007")

edit("Libraries/LibWeb/Page/Page.h",
     "    void did_request_credential_suggestions(GC::Weak<HTML::HTMLElement> target, HTML::CrossProcessId local_root_id, URL::Origin origin, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind);",
     """    void did_request_credential_suggestions(GC::Weak<HTML::HTMLElement> target, HTML::CrossProcessId local_root_id, URL::Origin origin, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind);

    void did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested);
    void did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret);
    void did_request_js_prevent_silent_access(Utf16String origin);""", "0007")

edit("Libraries/LibWeb/Page/Page.cpp",
     """    m_pending_credential_fills.set(fill_token, PendingCredentialFill { .element = move(target), .kind = field_kind });
    m_client->page_did_request_credential_suggestions(move(origin), local_root_id, content_position, minimum_width,
                                                       move(field_kind), fill_token);
}""",
     """    m_pending_credential_fills.set(fill_token, PendingCredentialFill { .element = move(target), .kind = field_kind });
    m_client->page_did_request_credential_suggestions(move(origin), local_root_id, content_position, minimum_width,
                                                       move(field_kind), fill_token);
}

void Page::did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested)
{
    m_client->page_did_request_js_get_credentials(request_id, move(origin), allow_silent, password_requested);
}

void Page::did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret)
{
    m_client->page_did_request_js_store_credentials(move(origin), move(username), move(secret));
}

void Page::did_request_js_prevent_silent_access(Utf16String origin)
{
    m_client->page_did_request_js_prevent_silent_access(move(origin));
}""", "0007")

# WebContent PageClient overrides.
edit("Services/WebContent/PageClient.h",
     "    virtual void page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token) override;",
     """    virtual void page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token) override;
    virtual void page_did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) override;
    virtual void page_did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret) override;
    virtual void page_did_request_js_prevent_silent_access(Utf16String origin) override;""", "0007")

edit("Services/WebContent/PageClient.cpp",
     """void PageClient::page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token)
{
    client().async_did_request_credential_suggestions(m_id, move(origin), local_root_id, page().css_to_device_point(content_position).to_type<int>(), minimum_width * device_pixels_per_css_pixel(), move(field_kind), fill_token);
}""",
     """void PageClient::page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token)
{
    client().async_did_request_credential_suggestions(m_id, move(origin), local_root_id, page().css_to_device_point(content_position).to_type<int>(), minimum_width * device_pixels_per_css_pixel(), move(field_kind), fill_token);
}

void PageClient::page_did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested)
{
    client().async_did_request_js_get_credentials(m_id, request_id, move(origin), allow_silent, password_requested);
}

void PageClient::page_did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret)
{
    client().async_did_request_js_store_credentials(m_id, move(origin), move(username), move(secret));
}

void PageClient::page_did_request_js_prevent_silent_access(Utf16String origin)
{
    client().async_did_request_js_prevent_silent_access(m_id, move(origin));
}""", "0007")

# ipc messages.
edit("Services/WebContent/WebContentClient.ipc",
     "    did_request_credential_suggestions(Web::PageId page_id, URL::Origin origin, Web::HTML::CrossProcessId frame_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|",
     """    did_request_credential_suggestions(Web::PageId page_id, URL::Origin origin, Web::HTML::CrossProcessId frame_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|
    did_request_js_get_credentials(Web::PageId page_id, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) =|
    did_request_js_store_credentials(Web::PageId page_id, Utf16String origin, Utf16String username, Utf16String secret) =|
    did_request_js_prevent_silent_access(Web::PageId page_id, Utf16String origin) =|""", "0007")

edit("Services/WebContent/WebContentServer.ipc",
     "    insert_text(Web::PageId page_id, Web::TextEditingCommand command) =|",
     "    insert_text(Web::PageId page_id, Web::TextEditingCommand command) =|\n    resolve_js_get_credentials(Web::PageId page_id, u64 request_id, bool found, Utf16String username, Utf16String secret) =|", "0007")

edit("Services/WebContent/ConnectionFromClient.h",
     "    virtual void credential_selected(Web::PageId page_id, u64 suggestion_id) override;",
     """    virtual void credential_selected(Web::PageId page_id, u64 suggestion_id) override;
    virtual void resolve_js_get_credentials(Web::PageId page_id, u64 request_id, bool found, Utf16String username, Utf16String secret) override;""", "0007")

edit("Services/WebContent/ConnectionFromClient.cpp",
     """void ConnectionFromClient::credential_selected(Web::PageId page_id, u64 suggestion_id)
{
    // The UI committed to a suggestion; the fill itself rides insert_text.
    // Nothing else to do in WebContent — an unknown page is dropped by design.
    (void)page_id;
    (void)suggestion_id;
}""",
     """void ConnectionFromClient::credential_selected(Web::PageId page_id, u64 suggestion_id)
{
    // The UI committed to a suggestion; the fill itself rides insert_text.
    // Nothing else to do in WebContent — an unknown page is dropped by design.
    (void)page_id;
    (void)suggestion_id;
}

void ConnectionFromClient::resolve_js_get_credentials(Web::PageId page_id, u64 request_id, bool found, Utf16String username, Utf16String secret)
{
    // M8: the vault answer to a page's navigator.credentials.get().
    (void)page_id;
    CredentialManagement::lkb_bridge_on_js_get_resolved(request_id, found, username, secret);
}""", "0007")

# forward declaration of the bridge entry in ConnectionFromClient.cpp
edit("Services/WebContent/ConnectionFromClient.cpp",
     "#include <LibWebCommon/Page/TextEditingCommand.h>",
     """#include <LibWebCommon/Page/TextEditingCommand.h>

namespace Web::CredentialManagement {
extern "C" void lkb_bridge_on_js_get_resolved(u64 request_id, bool found, Utf16String const& username, Utf16String const& secret);
}""", "0007")

# hub-side stub + ViewImplementation + hub chain.
edit("Libraries/LibWebView/WebContentPage.h",
     "    virtual void did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;",
     """    virtual void did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;
    virtual void did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) override;
    virtual void did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret) override;
    virtual void did_request_js_prevent_silent_access(Utf16String origin) override;""", "0007")

edit("Libraries/LibWebView/WebContentPage.cpp",
     """void WebContentPage::did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    if (auto target = view_position(local_root_id, content_position); target.has_value())
        target->view.did_request_credential_suggestions({}, *this, move(origin), target->position, minimum_width, move(field_kind), fill_token);
}""",
     """void WebContentPage::did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    if (auto target = view_position(local_root_id, content_position); target.has_value())
        target->view.did_request_credential_suggestions({}, *this, move(origin), target->position, minimum_width, move(field_kind), fill_token);
}

void WebContentPage::did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested)
{
    view().did_request_js_get_credentials({}, *this, request_id, move(origin), allow_silent, password_requested);
}

void WebContentPage::did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret)
{
    view().did_request_js_store_credentials({}, *this, move(origin), move(username), move(secret));
}

void WebContentPage::did_request_js_prevent_silent_access(Utf16String origin)
{
    view().did_request_js_prevent_silent_access({}, *this, move(origin));
}""", "0007")

edit("Libraries/LibWebView/ViewImplementation.h",
     "    Function<void(URL::Origin const&, Gfx::IntPoint, i32, Utf16String const&, u64)> on_request_credential_suggestions;",
     """    Function<void(URL::Origin const&, Gfx::IntPoint, i32, Utf16String const&, u64)> on_request_credential_suggestions;
    Function<void(u64, Utf16String const&, bool, bool)> on_request_js_get_credentials;
    Function<void(Utf16String const&, Utf16String const&, Utf16String const&)> on_request_js_store_credentials;
    Function<void(Utf16String const&)> on_request_js_prevent_silent_access;""", "0007")

edit("Libraries/LibWebView/ViewImplementation.h",
     "    void select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token);",
     """    void select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token);
    void did_request_js_get_credentials(Badge<WebContentPage>, WebContentPage&, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested);
    void did_request_js_store_credentials(Badge<WebContentPage>, WebContentPage&, Utf16String origin, Utf16String username, Utf16String secret);
    void did_request_js_prevent_silent_access(Badge<WebContentPage>, WebContentPage&, Utf16String origin);
    void resolve_js_get_credentials(u64 request_id, bool found, Utf16String username, Utf16String secret);""", "0007")

edit("Libraries/LibWebView/ViewImplementation.cpp",
     """void ViewImplementation::select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    page().async_credential_selected(suggestion_id);

    Web::TextEditingCommand command;
    command.type = Web::TextEditingCommand::Type::InsertText;
    command.text = move(secret);
    command.fill_token = fill_token;
    page().async_insert_text(command);
}""",
     """void ViewImplementation::select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    page().async_credential_selected(suggestion_id);

    Web::TextEditingCommand command;
    command.type = Web::TextEditingCommand::Type::InsertText;
    command.text = move(secret);
    command.fill_token = fill_token;
    page().async_insert_text(command);
}

void ViewImplementation::did_request_js_get_credentials(Badge<WebContentPage>, WebContentPage&, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested)
{
    if (on_request_js_get_credentials)
        on_request_js_get_credentials(request_id, origin, allow_silent, password_requested);
}

void ViewImplementation::did_request_js_store_credentials(Badge<WebContentPage>, WebContentPage&, Utf16String origin, Utf16String username, Utf16String secret)
{
    if (on_request_js_store_credentials)
        on_request_js_store_credentials(origin, username, secret);
}

void ViewImplementation::did_request_js_prevent_silent_access(Badge<WebContentPage>, WebContentPage&, Utf16String origin)
{
    if (on_request_js_prevent_silent_access)
        on_request_js_prevent_silent_access(origin);
}

void ViewImplementation::resolve_js_get_credentials(u64 request_id, bool found, Utf16String username, Utf16String secret)
{
    page().async_resolve_js_get_credentials(request_id, found, move(username), move(secret));
}""", "0007")

edit("Services/Hub/View.cpp",
     """        on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_credential_suggestions(view_id(), origin, content_position, minimum_width, field_kind, fill_token);
        };""",
     """        on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_credential_suggestions(view_id(), origin, content_position, minimum_width, field_kind, fill_token);
        };

        on_request_js_get_credentials = [this](u64 request_id, Utf16String const& origin, bool allow_silent, bool password_requested) {
            if (auto* ui = ConnectionFromUI::the()) {
                ui->async_view_request_js_get_credentials(view_id(), request_id, origin, allow_silent, password_requested);
                return;
            }
            // No UI process to answer: settle the page's promise now (found=false)
            // rather than leaving navigator.credentials.get() pending forever.
            resolve_js_get_credentials(request_id, false, {}, {});
        };

        on_request_js_store_credentials = [this](Utf16String const& origin, Utf16String const& username, Utf16String const& secret) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_js_store_credentials(view_id(), origin, username, secret);
        };

        on_request_js_prevent_silent_access = [this](Utf16String const& origin) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_js_prevent_silent_access(view_id(), origin);
        };""", "0007")

edit("Services/Hub/HubClient.ipc",
     "    view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|",
     """    view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|
    view_request_js_get_credentials(u64 view_id, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) =|
    view_request_js_store_credentials(u64 view_id, Utf16String origin, Utf16String username, Utf16String secret) =|
    view_request_js_prevent_silent_access(u64 view_id, Utf16String origin) =|""", "0007")

edit("Services/Hub/HubServer.ipc",
     "    view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) =|",
     """    view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) =|
    view_answer_js_get_credentials(u64 view_id, u64 request_id, bool found, Utf16String username, Utf16String secret) =|""", "0007")

edit("Services/Hub/ConnectionFromUI.h",
     "    virtual void view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) override;",
     """    virtual void view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) override;
    virtual void view_answer_js_get_credentials(u64 view_id, u64 request_id, bool found, Utf16String username, Utf16String secret) override;""", "0007")

edit("Services/Hub/ConnectionFromUI.cpp",
     """void ConnectionFromUI::view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    if (auto* view = find_view(view_id))
        view->select_credential(suggestion_id, move(secret), fill_token);
}""",
     """void ConnectionFromUI::view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    if (auto* view = find_view(view_id))
        view->select_credential(suggestion_id, move(secret), fill_token);
}

void ConnectionFromUI::view_answer_js_get_credentials(u64 view_id, u64 request_id, bool found, Utf16String username, Utf16String secret)
{
    if (auto* view = find_view(view_id))
        view->resolve_js_get_credentials(request_id, found, move(username), move(secret));
}""", "0007")

edit("UI/Qt/RemoteView.h",
     "    decltype(Hub::View::on_request_credential_suggestions) on_request_credential_suggestions;",
     """    decltype(Hub::View::on_request_credential_suggestions) on_request_credential_suggestions;
    decltype(Hub::View::on_request_js_get_credentials) on_request_js_get_credentials;
    decltype(Hub::View::on_request_js_store_credentials) on_request_js_store_credentials;
    decltype(Hub::View::on_request_js_prevent_silent_access) on_request_js_prevent_silent_access;""", "0007")

edit("UI/Qt/HubConnection.h",
     "    virtual void view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;",
     """    virtual void view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;
    virtual void view_request_js_get_credentials(u64 view_id, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) override;
    virtual void view_request_js_store_credentials(u64 view_id, Utf16String origin, Utf16String username, Utf16String secret) override;
    virtual void view_request_js_prevent_silent_access(u64 view_id, Utf16String origin) override;""", "0007")

edit("UI/Qt/HubConnection.cpp",
     """void HubConnection::view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_credential_suggestions)
        return;
    view->on_request_credential_suggestions(origin, content_position, minimum_width, field_kind, fill_token);
}""",
     """void HubConnection::view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_credential_suggestions)
        return;
    view->on_request_credential_suggestions(origin, content_position, minimum_width, field_kind, fill_token);
}

void HubConnection::view_request_js_get_credentials(u64 view_id, u64 request_id, Utf16String origin, bool allow_silent, bool password_requested)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_js_get_credentials) {
        // The answer contract with the page: every request is settled. A dead
        // view cannot answer, so the Hub settles it here as not-found.
        async_view_answer_js_get_credentials(view_id, request_id, false, Utf16View {}, Utf16View {});
        return;
    }
    view->on_request_js_get_credentials(request_id, origin, allow_silent, password_requested);
}

void HubConnection::view_request_js_store_credentials(u64 view_id, Utf16String origin, Utf16String username, Utf16String secret)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_js_store_credentials)
        return;
    view->on_request_js_store_credentials(origin, username, secret);
}

void HubConnection::view_request_js_prevent_silent_access(u64 view_id, Utf16String origin)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_js_prevent_silent_access)
        return;
    view->on_request_js_prevent_silent_access(origin);
}""", "0007")

# delegate (0007 part) + Tab wiring (0007 part).
edit("UI/Qt/CredentialsPrompt.h",
     "class QWidget;",
     """#include <AK/Function.h>

class QWidget;""", "0007")

edit("UI/Qt/CredentialsPrompt.h",
     """    virtual Vector<WebView::CredentialSuggestion> suggestions_for(Utf16String const&, Utf16String const&) { return {}; }
    virtual Utf16String secret_for(u64) { return {}; }
};""",
     """    virtual Vector<WebView::CredentialSuggestion> suggestions_for(Utf16String const&, Utf16String const&) { return {}; }
    virtual Utf16String secret_for(u64) { return {}; }

    // navigator.credentials (M8): the vault-backed answers. Defaults decline, so a
    // bridge that has not wired the service changes nothing for pages.
    virtual void js_get_credentials(Utf16String const& origin, bool allow_silent, bool password_requested,
                                    Function<void(bool found, Utf16String username, Utf16String secret)> on_complete)
    {
        (void)origin;
        (void)allow_silent;
        (void)password_requested;
        on_complete(false, {}, {});
    }
    virtual void js_store_credentials(Utf16String const& origin, Utf16String const& username, Utf16String const& secret)
    {
        (void)origin;
        (void)username;
        (void)secret;
    }
    virtual void js_prevent_silent_access(Utf16String const& origin, bool prevent)
    {
        (void)origin;
        (void)prevent;
    }
};""", "0007")

edit("UI/Qt/Tab.cpp",
     """    view().on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {""",
     """    view().on_request_js_get_credentials = [this](u64 request_id, Utf16String const& origin, bool allow_silent, bool password_requested) {
        // Same-origin rule as the popup and the save prompt: only answer for the
        // page this tab actually shows.
        if (Utf16String::from_utf8(view().url().origin().serialize()) != origin) {
            HubConnection::the().async_view_answer_js_get_credentials(view().view_id(), request_id, false, Utf16View {}, Utf16View {});
            return;
        }
        auto* delegate = Ladybird::credentials_bridge_delegate();
        if (!delegate) {
            HubConnection::the().async_view_answer_js_get_credentials(view().view_id(), request_id, false, Utf16View {}, Utf16View {});
            return;
        }
        delegate->js_get_credentials(origin, allow_silent, password_requested, [this, request_id](bool found, Utf16String username, Utf16String secret) {
            HubConnection::the().async_view_answer_js_get_credentials(view().view_id(), request_id, found, move(username), move(secret));
        });
    };

    view().on_request_js_store_credentials = [this](Utf16String const& origin, Utf16String const& username, Utf16String const& secret) {
        auto* delegate = Ladybird::credentials_bridge_delegate();
        if (delegate)
            delegate->js_store_credentials(origin, username, secret);
    };

    view().on_request_js_prevent_silent_access = [this](Utf16String const& origin) {
        auto* delegate = Ladybird::credentials_bridge_delegate();
        if (delegate)
            delegate->js_prevent_silent_access(origin, true);
    };

    view().on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {""", "0007")

# headless test for the Page/UI boundary.
NEW_FILES["Tests/LibWeb/TestCredentialsContainer.cpp"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Utf16View.h>
#include <LibCore/AnonymousBuffer.h>
#include <LibGC/CellAllocator.h>
#include <LibJS/Runtime/Realm.h>
#include <LibJS/Runtime/VM.h>
#include <LibTest/TestCase.h>
#include <LibWeb/Bindings/MainThreadVM.h>
#include <LibWeb/Bindings/PrincipalHostDefined.h>
#include <LibWeb/HTML/LocalTraversableNavigable.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/Loader/ContentBlocker.h>
#include <LibWeb/Page/Page.h>
#include <LibWeb/Platform/FontPlugin.h>

namespace {

class TestPageClient final : public Web::PageClient {
    GC_CELL(TestPageClient, Web::PageClient);
    GC_DECLARE_ALLOCATOR(TestPageClient);

public:
    TestPageClient()
        : m_palette(Gfx::PaletteImpl::create_with_anonymous_buffer(MUST(Core::AnonymousBuffer::create_with_size(sizeof(Gfx::SystemTheme)))))
    {
    }

    virtual Web::PageId id() const override { return Web::PageId { 1 }; }
    virtual Web::Page& page() override { return *m_page; }
    virtual Web::Page const& page() const override { return *m_page; }
    virtual bool is_connection_open() const override { return true; }
    virtual Gfx::Palette palette() const override { return m_palette; }
    virtual Web::DevicePixelRect screen_rect() const override { return {}; }
    virtual double zoom_level() const override { return 1; }
    virtual double device_pixel_ratio() const override { return 1; }
    virtual double device_pixels_per_css_pixel() const override { return 1; }
    virtual Web::CSS::PreferredColorScheme preferred_color_scheme() const override { return Web::CSS::PreferredColorScheme::Auto; }
    virtual Web::CSS::PreferredContrast preferred_contrast() const override { return Web::CSS::PreferredContrast::Auto; }
    virtual Web::CSS::PreferredMotion preferred_motion() const override { return Web::CSS::PreferredMotion::NoPreference; }
    virtual size_t screen_count() const override { return 1; }
    virtual Queue<Web::QueuedInputEvent>& input_event_queue() override { VERIFY_NOT_REACHED(); }
    virtual void report_finished_handling_input_event(Web::PageId, u64, Web::EventResult) override { }
    virtual Web::HTML::CrossProcessId allocate_cross_process_id() override { return { 1, m_next_cross_process_id++ }; }
    virtual void request_frame() override { }
    virtual void request_file(Web::FileRequest) override { }
    virtual bool is_headless() const override { return true; }

    // The M8 boundary: navigator.credentials calls must reach the UI process carrying
    // the exact origin string, so the vault can match it without parsing a URL.
    virtual void page_did_request_js_get_credentials(u64 request_id, Utf16String origin, bool allow_silent, bool password_requested) override
    {
        m_last_get_request_id = request_id;
        m_last_get_origin = move(origin);
        m_last_allow_silent = allow_silent;
        m_last_password_requested = password_requested;
    }
    virtual void page_did_request_js_store_credentials(Utf16String origin, Utf16String username, Utf16String secret) override
    {
        m_last_store_origin = move(origin);
        m_last_store_username = move(username);
        m_last_store_secret_length = secret.length();
    }
    virtual void page_did_request_js_prevent_silent_access(Utf16String origin) override
    {
        m_last_prevent_origin = move(origin);
    }

    u64 m_last_get_request_id { 0 };
    Utf16String m_last_get_origin;
    bool m_last_allow_silent { false };
    Utf16String m_last_store_origin;
    Utf16String m_last_store_username;
    size_t m_last_store_secret_length { 0 };
    Utf16String m_last_prevent_origin;
    bool m_last_password_requested { false };

    virtual void visit_edges(Visitor& visitor) override
    {
        Base::visit_edges(visitor);
        visitor.visit(m_page);
    }

    Gfx::Palette m_palette;
    GC::Ptr<Web::Page> m_page;
    u64 m_next_cross_process_id { 1 };
};

GC_DEFINE_ALLOCATOR(TestPageClient);

static void install_font_plugin()
{
    static bool installed = [] {
        static Web::Platform::FontPlugin font_plugin(false);
        Web::Platform::FontPlugin::install(font_plugin);
        return true;
    }();
    VERIFY(installed);
}

static GC::Ref<Web::DOM::Document> make_document(Web::PageClient& client)
{
    auto principal_realm = Web::Bindings::create_a_principal_javascript_realm();
    VERIFY(principal_realm.ptr());
    auto page = Web::Page::create(client);
    static_cast<TestPageClient&>(client).m_page = page.ptr();
    auto traversable = Web::HTML::LocalTraversableNavigable::create_a_new_top_level_traversable(page, nullptr, {});
    page->set_top_level_traversable(traversable);
    return GC::Ref { *traversable->active_document() };
}

}

TEST_CASE(js_credentials_requests_reach_the_page_client)
{
    install_font_plugin();
    auto client = Web::Bindings::main_thread_vm().heap().allocate<TestPageClient>();
    auto document = make_document(*client);

    document->page().did_request_js_get_credentials(7, "https://login.example"_utf16, true, true);
    EXPECT_EQ(client->m_last_get_request_id, static_cast<u64>(7));
    EXPECT_EQ(client->m_last_get_origin.to_byte_string(), "https://login.example"sv);
    EXPECT(client->m_last_allow_silent);
    EXPECT(client->m_last_password_requested);

    document->page().did_request_js_get_credentials(8, "https://login.example"_utf16, false, false);
    EXPECT(!client->m_last_allow_silent); // mediation: silent is honored at the boundary
    EXPECT(!client->m_last_password_requested); // and so is the type filter: no password ask, no vault read

    document->page().did_request_js_store_credentials(
        "https://login.example"_utf16, "erin"_utf16, "sup3r-s3cr3t"_utf16);
    EXPECT_EQ(client->m_last_store_username.to_byte_string(), "erin"sv);
    EXPECT_EQ(client->m_last_store_secret_length, static_cast<size_t>(11)); // length only, as ever

    document->page().did_request_js_prevent_silent_access("https://login.example"_utf16);
    EXPECT_EQ(client->m_last_prevent_origin.to_byte_string(), "https://login.example"sv);
}
'''

edit("Tests/LibWeb/CMakeLists.txt",
     "    TestLoginFormDetection.cpp",
     "    TestLoginFormDetection.cpp\n    TestCredentialsContainer.cpp", "0007")

# ===================== 0008: about:credentials management page =====================

NEW_FILES["Base/res/ladybird/about-pages/credentials.html"] = r'''<!doctype html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="color-scheme" content="light dark" />
        <title>Credentials</title>
        <link rel="stylesheet" type="text/css" href="resource://ladybird/ladybird.css" />
        <style>
            body {
                font-family: system-ui, sans-serif;
                margin: 24px;
            }
            table {
                border-collapse: collapse;
                width: 100%;
            }
            th, td {
                text-align: left;
                padding: 6px 10px;
                border-bottom: 1px solid rgba(128, 128, 128, 0.3);
            }
            #search {
                margin-bottom: 12px;
                padding: 4px 8px;
                width: 320px;
            }
            #empty {
                color: gray;
            }
        </style>
    </head>
    <body>
        <h1>Credentials</h1>
        <input id="search" placeholder="Search by site or username" />
        <table>
            <thead>
                <tr>
                    <th>Site</th>
                    <th>Username</th>
                    <th></th>
                </tr>
            </thead>
            <tbody id="rows"></tbody>
        </table>
        <p id="empty" hidden>No stored credentials.</p>
        <p>
            <button id="export">Export CSV</button>
            <button id="delete-all">Delete all for this site</button>
        </p>
        <script>
            let rows = [];
            let searchValue = "";

            function render() {
                const tbody = document.getElementById("rows");
                tbody.replaceChildren();
                const visible = rows.filter(row =>
                    row.origin.includes(searchValue) || row.username.includes(searchValue));
                for (const row of visible) {
                    const tr = document.createElement("tr");
                    const origin = document.createElement("td");
                    origin.textContent = row.origin;
                    const username = document.createElement("td");
                    username.textContent = row.username;
                    const action = document.createElement("td");
                    const remove = document.createElement("button");
                    remove.textContent = "Delete";
                    remove.addEventListener("click", () => ladybird.sendMessage("deleteCredential", row.id));
                    action.appendChild(remove);
                    tr.append(origin, username, action);
                    tbody.appendChild(tr);
                }
                document.getElementById("empty").hidden = visible.length > 0;
            }

            document.getElementById("search").addEventListener("input", event => {
                searchValue = event.target.value;
                render();
            });

            document.getElementById("export").addEventListener("click", () => {
                ladybird.sendMessage("exportCsv");
            });

            document.getElementById("delete-all").addEventListener("click", () => {
                if (!searchValue)
                    return;
                // Bulk delete needs an explicit yes on top of the click: the
                // search box is free text and one click should not empty a site.
                if (window.confirm(`Delete every credential for "${searchValue}"?`))
                    ladybird.sendMessage("deleteAllForOrigin", searchValue);
            });

            document.addEventListener("WebUILoaded", () => {
                ladybird.sendMessage("loadCredentials");
            });

            document.addEventListener("WebUIMessage", event => {
                if (event.detail.name === "renderCredentials") {
                    rows = event.detail.data.rows ?? [];
                    render();
                } else if (event.detail.name === "downloadCsv") {
                    const blob = new Blob([event.detail.data.csv], { type: "text/csv" });
                    const link = document.createElement("a");
                    link.href = URL.createObjectURL(blob);
                    link.download = "credentials.csv";
                    link.click();
                }
            });
        </script>
    </body>
</html>
'''

NEW_FILES["UI/Qt/CredentialSettingsPage.h"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <UI/Qt/WebUIPage.h>

namespace Ladybird {

// about:credentials — the re-auth-gated management view over the bridge vault. Rows carry
// { origin, username } only; secrets are never rendered here.
class CredentialSettingsPage final : public WebUIPage {
public:
    AK_ALLOC_WITH_KMALLOC;

    explicit CredentialSettingsPage(u64 web_ui_id)
        : WebUIPage(web_ui_id)
    {
    }

    virtual void received_message(String const& name, JsonValue const& data) override;

private:
    void load_credentials();
};

}
'''

NEW_FILES["UI/Qt/CredentialSettingsPage.cpp"] = r'''/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonArray.h>
#include <AK/JsonObject.h>
#include <LibWebView/BrowsingSession.h>
#include <UI/Qt/CredentialSettingsPage.h>
#include <UI/Qt/CredentialsPrompt.h>

namespace Ladybird {

namespace {

// JsonValue refuses ByteString (deleted ctor); Strings cross as StringView.
JsonValue json_string(Utf16String const& text)
{
    ByteString bs = text.to_byte_string();
    return JsonValue { StringView { bs.characters(), bs.length() } };
}

}

void CredentialSettingsPage::received_message(String const& name, JsonValue const& data)
{
    if (name == "loadCredentials"sv) {
        load_credentials();
        return;
    }
    auto* delegate = credentials_bridge_delegate();
    if (!delegate)
        return;
    if (name == "deleteCredential"sv)
        delegate->credentials_delete(data.get_integer<u64>().value_or(0));
    else if (name == "deleteAllForOrigin"sv) {
        if (!consume_user_activation())
            return; // the button is the user's; a scripted sendMessage is not
        auto origin = Utf16String::from_utf8(data.as_string());
        // Exact match against a stored origin only: the search box is free text,
        // and a partial match must never delete a site the user did not name.
        bool exact_match = false;
        for (auto const& row : delegate->credentials_rows()) {
            if (row.origin == origin) {
                exact_match = true;
                break;
            }
        }
        if (exact_match)
            delegate->credentials_delete_all(origin);
    } else if (name == "exportCsv"sv) {
        if (!consume_user_activation())
            return; // bulk plaintext leaves the vault only on a real click
        JsonObject csv_payload;
        csv_payload.set("csv"_string, json_string(delegate->credentials_export_csv()));
        send_message("downloadCsv"_string, JsonValue { move(csv_payload) });
    }
    load_credentials();
}

void CredentialSettingsPage::load_credentials()
{
    JsonArray rows;
    if (auto* delegate = credentials_bridge_delegate()) {
        for (auto const& row : delegate->credentials_rows()) {
            JsonObject entry;
            entry.set("origin"_string, json_string(row.origin));
            entry.set("username"_string, json_string(row.username));
            entry.set("id"_string, JsonValue { row.id });
            MUST(rows.append(move(entry)));
        }
    }
    JsonObject payload;
    payload.set("rows"_string, JsonValue { move(rows) });
    send_message("renderCredentials"_string, move(payload));
}

}
'''

edit("UI/Qt/CMakeLists.txt",
     "    HistoryPage.cpp",
     "    CredentialSettingsPage.cpp\n    HistoryPage.cpp", "0008")

edit("UI/cmake/ResourceFiles.cmake",
     "    crashes.html\n",
     "    crashes.html\n    credentials.html\n", "0008")

edit("UI/Qt/Application.cpp",
     "#include <UI/Qt/VersionPage.h>",
     "#include <UI/Qt/CredentialSettingsPage.h>\n#include <UI/Qt/VersionPage.h>", "0008")

edit("UI/Qt/Application.cpp",
     """    m_web_ui_pages->register_page("version"_string, "Version"_string, [](u64 web_ui_id, WebView::IsPrivate) -> NonnullOwnPtr<WebUIPage> {
        return make<VersionPage>(web_ui_id);
    });""",
     """    m_web_ui_pages->register_page("version"_string, "Version"_string, [](u64 web_ui_id, WebView::IsPrivate) -> NonnullOwnPtr<WebUIPage> {
        return make<VersionPage>(web_ui_id);
    });
    m_web_ui_pages->register_page("credentials"_string, "Credentials"_string, [](u64 web_ui_id, WebView::IsPrivate) -> NonnullOwnPtr<WebUIPage> {
        return make<CredentialSettingsPage>(web_ui_id);
    });""", "0008")

# delegate (0008 part): management rows + delete + csv.
edit("UI/Qt/CredentialsPrompt.h",
     """    virtual void js_prevent_silent_access(Utf16String const& origin, bool prevent)
    {
        (void)origin;
        (void)prevent;
    }
};""",
     """    virtual void js_prevent_silent_access(Utf16String const& origin, bool prevent)
    {
        (void)origin;
        (void)prevent;
    }

    // about:credentials (M9a): management surface. Rows never carry secrets; the
    // re-auth gate is the vault's own CapabilityToken, enforced by the service.
    struct CredentialRow {
        Utf16String origin;
        Utf16String username;
        u64 id { 0 };
    };
    virtual Vector<CredentialRow> credentials_rows() { return {}; }
    virtual bool credentials_delete(u64) { return false; }
    virtual bool credentials_delete_all(Utf16String const&) { return false; }
    virtual Utf16String credentials_export_csv() { return {}; }
};""", "0008")

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
        text = text.replace(old, new, 1)  # later edits may anchor on earlier ones' output
print("anchors OK:", sum(len(v) for v in EDITS.values()), "edits across", len(EDITS), "files")

# ---------------- snapshot baseline, apply ----------------
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

# ---------------- extract per-owner hunks (chained snapshots) ----------------
# Each file's diff is taken per owner: baseline -> after-owner-A-edits -> ... so
# an owner's hunk contains exactly its own lines even when two owners' edits sit
# in one contiguous region. Owners are applied in sorted order — matching the
# order edits were declared in — and an owner's later edits may anchor on an
# earlier owner's output.
import tempfile


def hunks_between(prev_text, next_text, path):
    """Real `diff -u -U3` between two snapshots; return the hunk list (from @@ on)."""
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
    start = 0
    for i, ln in enumerate(lines):
        if ln.startswith("@@"):
            start = i
            break
    else:
        return []
    out = []
    cur = None
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


patch_files = {"0007": [], "0008": []}
for path in sorted(list(EDITS) + list(NEW_FILES)):
    final_text = open(os.path.join(TREE, path)).read()
    baseline_path = os.path.join(BASELINE, path)
    base_text = open(baseline_path).read() if os.path.exists(baseline_path) else ""
    if path in NEW_FILES:
        owner = "0008" if path.startswith(("Base/res/", "UI/Qt/CredentialSettingsPage")) else "0007"
        owners_in_order = [owner]
        states = [base_text, final_text]
    else:
        owners_in_order = sorted({own for _, _, own in EDITS[path]})
        states = [base_text]
        text = base_text
        for owner in owners_in_order:
            for old, new, own in EDITS[path]:
                if own == owner:
                    assert text.count(old) == 1, f"owner-chain anchor miss in {path} for {owner}: {old[:80]!r}"
                    text = text.replace(old, new, 1)
            states.append(text)
        assert states[-1] == final_text, f"owner-chain result != applied file for {path}"
    for i, owner in enumerate(owners_in_order):
        hunks = hunks_between(states[i], states[i + 1], path)
        if not hunks:
            continue
        if path in NEW_FILES:
            header = ["diff --git a/%s b/%s\n" % (path, path),
                      "new file mode 100644\n",
                      "--- /dev/null\n",
                      "+++ b/%s\n" % path]
        else:
            header = ["diff --git a/%s b/%s\n" % (path, path),
                      "--- a/%s\n" % path,
                      "+++ b/%s\n" % path]
        patch_files[owner].append("".join(header) + "".join("".join(h) for h in hunks))

def write_patch(name, title, body):
    header = (f"From ladybird-keychain-bridge patch-set — apply with `git apply` "
              f"on the pinned Ladybird tree (09fa4834) as a stack, in numeric order.\n{title}\n\n")
    with open(os.path.join(PATCHES, name), "w") as f:
        f.write(header + "".join(body))
    print("wrote", name, "files:", sum(b.count("diff --git") for b in body))

write_patch("0007-credentials-container.patch",
            "0007: navigator.credentials store()/get()/preventSilentAccess() against the vault (M8).",
            patch_files["0007"])
write_patch("0008-credential-settings-webui.patch",
            "0008: about:credentials management page (M9a).",
            patch_files["0008"])

# ---------------- restore ----------------
sh("git", "reset")
sh("git", "checkout", "--", ".")
sh("git", "clean", "-fdq", "-e", ".codegraph")
assert sh("git", "status", "--porcelain").strip() == "", "tree not clean after restore"
print("tree restored clean")
