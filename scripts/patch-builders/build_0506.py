#!/usr/bin/env python3
"""Build patches 0005-autofill-popup + 0006-textediting-insert against the
pinned Ladybird tree. Two-phase: stack 0001..0004, verify ALL anchors, apply,
extract hunks into the two patch files by marker, restore the tree clean."""
import os
import subprocess
import sys

import os as _os
BRIDGE_DEFAULT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
TREE = _os.environ.get("LKB_LADYBIRD_DIR", _os.path.join(_os.path.dirname(BRIDGE_DEFAULT), "ladybird-pinned"))
BRIDGE = BRIDGE_DEFAULT
PATCHES = os.path.join(BRIDGE, "patches/ladybird")


def sh(*args):
    r = subprocess.run(args, cwd=TREE, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"command failed: {args}\n{r.stdout}\n{r.stderr}")
    return r.stdout


sh("git", "checkout", "--", ".")
sh("git", "clean", "-fdq", "-e", ".codegraph")
if sh("git", "status", "--porcelain").strip():
    sys.exit("pinned tree is not clean")
for p in ("0001-form-detection.patch", "0002-split-page-heuristic.patch",
          "0003-credentials-ipc.patch", "0004-save-prompt.patch"):
    sh("git", "apply", os.path.join(PATCHES, p))

BASELINE = "/tmp/lkb-0506-baseline"
subprocess.run(["rm", "-rf", BASELINE], check=True)
os.makedirs(BASELINE)

# path -> [(old, new, owner)]
EDITS = {}


def edit(path, old, new, owner):
    EDITS.setdefault(path, []).append((old, new, owner))


# ============================ 0006: insert-text command ============================
edit("Libraries/LibWebCommon/Page/TextEditingCommand.h",
     "        DeleteToEndOfParagraph,\n    };",
     "        DeleteToEndOfParagraph,\n        InsertText,\n    };", "0006")
edit("Libraries/LibWebCommon/Page/TextEditingCommand.h",
     "    Type type { Type::MoveBackward };\n    bool extend_selection { false };",
     "    Type type { Type::MoveBackward };\n    bool extend_selection { false };\n    Utf16String text {};\n    // Credential inserts carry the token the UI process received with the\n    // popup request; Page::handle_text_editing_command_from_ui validates it.\n    Optional<u64> fill_token {};", "0006")
edit("Libraries/LibWebCommon/Page/TextEditingCommand.h",
     "#include <AK/Types.h>",
     "#include <AK/Optional.h>\n#include <AK/Types.h>\n#include <AK/Utf16String.h>", "0006")

edit("Libraries/LibWebCommon/Page/TextEditingCommand.ipc",
     "    DeleteToEndOfParagraph,\n}",
     "    DeleteToEndOfParagraph,\n    InsertText,\n}", "0006")
edit("Libraries/LibWebCommon/Page/TextEditingCommand.ipc",
     "    Web::TextEditingCommand::Type type;\n    bool extend_selection;\n}",
     "    Web::TextEditingCommand::Type type;\n    bool extend_selection;\n    Utf16String text;\n    Optional<u64> fill_token;\n}", "0006")

edit("Libraries/LibWeb/Page/EventHandler.cpp",
     """        target->handle_delete(input_type);
        break;
    }
    default:
        return EventResult::Dropped;""",
     """        target->handle_delete(input_type);
        break;
    }
    case Type::InsertText: {
        // ladybird-keychain-bridge (M7b): credential injection asked for by the
        // user clicking a suggestion. Sites must see it like typing: cancelable
        // beforeinput, then the target's insert hook fires the synchronous
        // input event; change rides the normal commit path (blur/commit).
        if (command.text.is_empty())
            break;
        GC::Root<DOM::Document> rooted_document { document };
        GC::Root<JS::Cell> rooted_target { target->as_cell() };
        GC::Root<DOM::Node> scope { target->mouse_selection_scope() };
        FIRE(input_event(UIEvents::EventNames::beforeinput, UIEvents::InputTypes::insertText, m_navigable, command.text));
        if (m_navigable->active_document() != document || !document->is_fully_active()
            || document->active_input_events_target() != target || !scope || !scope->is_connected()
            || target->mouse_selection_scope().ptr() != scope.ptr())
            return EventResult::Handled;
        target->handle_insert(UIEvents::InputTypes::insertText, command.text);
        break;
    }
    default:
        return EventResult::Dropped;""", "0006")

edit("Libraries/LibWeb/Page/Page.h",
     "    EventResult handle_keydown(UIEvents::KeyCode, unsigned modifiers, u32 code_point, bool repeat, bool should_insert_text, bool async_scroll_performed_default_action = false, ReadonlySpan<TextEditingCommand> editing_commands = {}, bool native_editing_binding_resolved = false, Optional<u64> user_input_scroll_count_with_nothing_to_scroll = {});",
     "    EventResult handle_keydown(UIEvents::KeyCode, unsigned modifiers, u32 code_point, bool repeat, bool should_insert_text, bool async_scroll_performed_default_action = false, ReadonlySpan<TextEditingCommand> editing_commands = {}, bool native_editing_binding_resolved = false, Optional<u64> user_input_scroll_count_with_nothing_to_scroll = {});\n\n    bool handle_text_editing_command_from_ui(TextEditingCommand const&);", "0006")

edit("Libraries/LibWeb/Page/Page.cpp",
     "    return navigable->event_handler().handle_keydown(key, modifiers, code_point, repeat, should_insert_text, async_scroll_performed_default_action, editing_commands, native_editing_binding_resolved);\n}",
     """    return navigable->event_handler().handle_keydown(key, modifiers, code_point, repeat, should_insert_text, async_scroll_performed_default_action, editing_commands, native_editing_binding_resolved);
}

bool Page::handle_text_editing_command_from_ui(TextEditingCommand const& command)
{
    // ladybird-keychain-bridge (M7b): the UI injects a user-chosen credential
    // into the focused field only after a real click on a suggestion. Reuses
    // the native command path so the site observes beforeinput/input like typing.
    if (command.type == TextEditingCommand::Type::InsertText) {
        // Credential inserts are tokenized: the token was minted for one popup
        // request against one element, is single-use, and the element must
        // still be connected and focused when the secret arrives.
        if (!command.fill_token.has_value())
            return false;
        auto pending = m_pending_credential_fills.take(*command.fill_token);
        if (!pending.has_value())
            return false;
        auto element = pending->element.strong_ref();
        if (!element || !element->is_connected())
            return false;
        if (element->document().focused_area().ptr() != element.ptr())
            return false;
    }
    auto navigable = hosted_focused_navigable();
    if (!navigable)
        return false;
    auto result = navigable->event_handler().handle_text_editing_command(command);
    return result == EventResult::Handled || result == EventResult::Accepted;
}""", "0006")

edit("Services/WebContent/WebContentServer.ipc",
     "    key_event(Web::PageId page_id, Web::KeyEvent event) =|",
     "    key_event(Web::PageId page_id, Web::KeyEvent event) =|\n    insert_text(Web::PageId page_id, Web::TextEditingCommand command) =|", "0006")

edit("Services/WebContent/ConnectionFromClient.h",
     "    virtual void key_event(Web::PageId page_id, Web::KeyEvent) override;",
     """    virtual void key_event(Web::PageId page_id, Web::KeyEvent) override;
    virtual void insert_text(Web::PageId page_id, Web::TextEditingCommand command) override;
    virtual void credential_selected(Web::PageId page_id, u64 suggestion_id) override;""", "0006")

edit("Services/WebContent/ConnectionFromClient.cpp",
     "#include <WebContent/Worker/WorkerThread.h>",
     "#include <WebContent/Worker/WorkerThread.h>\n#include <LibWebCommon/Page/TextEditingCommand.h>", "0006")

edit("Services/WebContent/ConnectionFromClient.cpp",
     """void ConnectionFromClient::key_event(Web::PageId page_id, Web::KeyEvent event)
{
    enqueue_input_event({ page_id, move(event), {}, {} });
}""",
     """void ConnectionFromClient::key_event(Web::PageId page_id, Web::KeyEvent event)
{
    enqueue_input_event({ page_id, move(event), {}, {} });
}

void ConnectionFromClient::insert_text(Web::PageId page_id, Web::TextEditingCommand command)
{
    // ladybird-keychain-bridge (M7b): UI-delivered credential injection; the UI
    // only ever sends this after a real click on a credential suggestion.
    auto client = page(page_id);
    if (!client.has_value())
        return;
    (void)client->page().handle_text_editing_command_from_ui(move(command));
}

void ConnectionFromClient::credential_selected(Web::PageId page_id, u64 suggestion_id)
{
    // The UI committed to a suggestion; the fill itself rides insert_text.
    // Nothing else to do in WebContent — an unknown page is dropped by design.
    (void)page_id;
    (void)suggestion_id;
}""", "0006")

# ============================ 0005: autofill popup ============================
edit("Libraries/LibWeb/HTML/HTMLInputElement.cpp",
     """void HTMLInputElement::did_receive_focus()
{""",
     """static Optional<Utf16String> credential_field_kind(HTMLInputElement const& input)
{
    if (input.type_state() == HTMLInputElement::TypeAttributeState::Password)
        return "password"_utf16;
    if (first_is_one_of(input.type_state(), HTMLInputElement::TypeAttributeState::Text,
                        HTMLInputElement::TypeAttributeState::Email)) {
        if (input.parse_autocomplete_attribute().field_name == "username"_utf16)
            return "username"_utf16;
        if (first_is_one_of(input.name(), "username"_utf16, "user"_utf16, "email"_utf16))
            return "username"_utf16;
    }
    return {};
}

void HTMLInputElement::did_receive_focus()
{
    // ladybird-keychain-bridge (M7a): a focused, empty credential field with a
    // fresh user gesture asks the UI for a field-anchored autofill popup — the
    // same transient-activation rule that gates a <select> picker. No gesture,
    // no request; a field the user is already typing into is never interrupted.
    if (is_connected() && value().is_empty()) {
        if (auto kind = credential_field_kind(*this); kind.has_value()) {
            auto* relevant_window = window_from_global_object(relevant_global_object(*this));
            if (relevant_window && relevant_window->has_transient_activation()) {
                auto rect = get_bounding_client_rect();
                auto navigable = document().navigable();
                if (navigable && navigable->local_root()) {
                    auto position = navigable->to_page_position(Web::CSSPixelPoint { rect.x(), rect.bottom() });
                    document().page().did_request_credential_suggestions(GC::Weak<HTMLElement> { *this },
                        navigable->local_root()->id(), URL::Origin(document().origin()), position,
                        rect.width(), kind.release_value());
                }
            }
        }
    }""", "0005")

edit("Libraries/LibWeb/Page/Page.h",
     "    void did_request_select_dropdown(GC::Weak<HTML::HTMLSelectElement> target, HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items);",
     "    void did_request_select_dropdown(GC::Weak<HTML::HTMLSelectElement> target, HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items);\n\n    void did_request_credential_suggestions(GC::Weak<HTML::HTMLElement> target, HTML::CrossProcessId local_root_id, URL::Origin origin, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind);", "0005")

edit("Libraries/LibWeb/Page/Page.h",
     "    virtual void page_did_request_select_dropdown([[maybe_unused]] HTML::CrossProcessId local_root_id, [[maybe_unused]] Web::CSSPixelPoint content_position, [[maybe_unused]] Web::CSSPixels minimum_width, [[maybe_unused]] Vector<Web::HTML::SelectItem> items) { }",
     """    virtual void page_did_request_select_dropdown([[maybe_unused]] HTML::CrossProcessId local_root_id, [[maybe_unused]] Web::CSSPixelPoint content_position, [[maybe_unused]] Web::CSSPixels minimum_width, [[maybe_unused]] Vector<Web::HTML::SelectItem> items) { }

    virtual void page_did_request_credential_suggestions([[maybe_unused]] URL::Origin origin, [[maybe_unused]] HTML::CrossProcessId local_root_id, [[maybe_unused]] Web::CSSPixelPoint content_position, [[maybe_unused]] Web::CSSPixels minimum_width, [[maybe_unused]] Utf16String field_kind, [[maybe_unused]] u64 fill_token) { }""", "0005")

edit("Libraries/LibWeb/Page/Page.h",
     "    GC::Weak<HTML::HTMLElement> m_pending_non_blocking_dialog_target;",
     """    GC::Weak<HTML::HTMLElement> m_pending_non_blocking_dialog_target;

    // ladybird-keychain-bridge (M7a/M7b): one pending autofill offer per popup
    // request. The element is held weakly on purpose: if it is collected, the
    // token can never authorize an insert again.
    struct PendingCredentialFill {
        GC::Weak<HTML::HTMLElement> element;
        Utf16String kind;
    };
    HashMap<u64, PendingCredentialFill> m_pending_credential_fills;
    u64 m_next_credential_fill_token { 1 };""", "0005")

edit("Libraries/LibWeb/Page/Page.cpp",
     """    if (m_pending_non_blocking_dialog == PendingNonBlockingDialog::None) {
        m_pending_non_blocking_dialog = PendingNonBlockingDialog::Select;
        m_pending_non_blocking_dialog_target = move(target);
        m_client->page_did_request_select_dropdown(local_root_id, content_position, minimum_width, move(items));
    }
}""",
     """    if (m_pending_non_blocking_dialog == PendingNonBlockingDialog::None) {
        m_pending_non_blocking_dialog = PendingNonBlockingDialog::Select;
        m_pending_non_blocking_dialog_target = move(target);
        m_client->page_did_request_select_dropdown(local_root_id, content_position, minimum_width, move(items));
    }
}

void Page::did_request_credential_suggestions(GC::Weak<HTML::HTMLElement> target, HTML::CrossProcessId local_root_id, URL::Origin origin, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind)
{
    // The UI must prove knowledge of this token when the secret arrives
    // (handle_text_editing_command_from_ui); stale entries are bounded.
    if (m_pending_credential_fills.size() > 16)
        m_pending_credential_fills.clear();
    u64 const fill_token = m_next_credential_fill_token++;
    m_pending_credential_fills.set(fill_token, PendingCredentialFill { .element = move(target), .kind = field_kind });
    m_client->page_did_request_credential_suggestions(move(origin), local_root_id, content_position, minimum_width,
                                                       move(field_kind), fill_token);
}""", "0005")

edit("Services/WebContent/PageClient.h",
     "    virtual void page_did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items) override;",
     """    virtual void page_did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items) override;
    virtual void page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token) override;""", "0005")

edit("Services/WebContent/PageClient.cpp",
     """void PageClient::page_did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items)
{
    client().async_did_request_select_dropdown(m_id, local_root_id, page().css_to_device_point(content_position).to_type<int>(), minimum_width * device_pixels_per_css_pixel(), items);
}""",
     """void PageClient::page_did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Vector<Web::HTML::SelectItem> items)
{
    client().async_did_request_select_dropdown(m_id, local_root_id, page().css_to_device_point(content_position).to_type<int>(), minimum_width * device_pixels_per_css_pixel(), items);
}

void PageClient::page_did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Web::CSSPixelPoint content_position, Web::CSSPixels minimum_width, Utf16String field_kind, u64 fill_token)
{
    client().async_did_request_credential_suggestions(m_id, move(origin), local_root_id, page().css_to_device_point(content_position).to_type<int>(), minimum_width * device_pixels_per_css_pixel(), move(field_kind), fill_token);
}""", "0005")

edit("Services/WebContent/WebContentClient.ipc",
     "    did_request_credential_suggestions(Web::PageId page_id, URL::Origin origin, Web::HTML::CrossProcessId frame_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind) =|",
     "    did_request_credential_suggestions(Web::PageId page_id, URL::Origin origin, Web::HTML::CrossProcessId frame_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|", "0005")

edit("Libraries/LibWebView/WebContentPage.h",
     "    virtual void did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items) override;",
     """    virtual void did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items) override;
    virtual void did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;""", "0005")

edit("Libraries/LibWebView/WebContentPage.cpp",
     """void WebContentPage::did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items)
{
    if (auto target = view_position(local_root_id, content_position); target.has_value())
        target->view.did_request_select_dropdown({}, *this, target->position, minimum_width, move(items));
}""",
     """void WebContentPage::did_request_select_dropdown(Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items)
{
    if (auto target = view_position(local_root_id, content_position); target.has_value())
        target->view.did_request_select_dropdown({}, *this, target->position, minimum_width, move(items));
}

void WebContentPage::did_request_credential_suggestions(URL::Origin origin, Web::HTML::CrossProcessId local_root_id, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    if (auto target = view_position(local_root_id, content_position); target.has_value())
        target->view.did_request_credential_suggestions({}, *this, move(origin), target->position, minimum_width, move(field_kind), fill_token);
}""", "0005")

edit("Libraries/LibWebView/ViewImplementation.h",
     "    Function<void(Web::CredentialsSaveRequestPayload const&)> on_request_save_credentials;",
     """    Function<void(Web::CredentialsSaveRequestPayload const&)> on_request_save_credentials;
    Function<void(URL::Origin const&, Gfx::IntPoint, i32, Utf16String const&, u64)> on_request_credential_suggestions;""", "0005")

edit("Libraries/LibWebView/ViewImplementation.h",
     "    void did_request_select_dropdown(Badge<WebContentPage>, WebContentPage& requesting_page, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items);",
     """    void did_request_select_dropdown(Badge<WebContentPage>, WebContentPage& requesting_page, Gfx::IntPoint content_position, i32 minimum_width, Vector<Web::HTML::SelectItem> items);
    void did_request_credential_suggestions(Badge<WebContentPage>, WebContentPage& requesting_page, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token);
    void select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token);""", "0005")

edit("Libraries/LibWebView/ViewImplementation.h",
     "    RefPtr<WebContentPage> m_select_dropdown_page;",
     """    RefPtr<WebContentPage> m_select_dropdown_page;
    RefPtr<WebContentPage> m_credential_popup_page;
    Gfx::IntPoint m_last_credential_popup_position;
    Utf16String m_last_credential_popup_kind;""", "0005")

edit("Libraries/LibWebView/ViewImplementation.cpp",
     """    m_select_dropdown_page = requesting_page;
    if (on_request_select_dropdown)
        on_request_select_dropdown(to_widget_position(content_position), minimum_width / device_pixel_ratio(), move(items));
}""",
     """    m_select_dropdown_page = requesting_page;
    if (on_request_select_dropdown)
        on_request_select_dropdown(to_widget_position(content_position), minimum_width / device_pixel_ratio(), move(items));
}

void ViewImplementation::did_request_credential_suggestions(Badge<WebContentPage>, WebContentPage& requesting_page, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    // Repeated focus of the same field of the same page (dialog close, focus
    // restore) is not a fresh offer; the popup is anchored per page+spot+kind,
    // mirroring how m_select_dropdown_page scopes the <select> picker.
    if (&requesting_page == m_credential_popup_page
        && content_position == m_last_credential_popup_position && field_kind == m_last_credential_popup_kind)
        return;
    m_credential_popup_page = requesting_page;
    m_last_credential_popup_position = content_position;
    m_last_credential_popup_kind = field_kind;
    if (on_request_credential_suggestions)
        on_request_credential_suggestions(origin, to_widget_position(content_position), minimum_width / device_pixel_ratio(), field_kind, fill_token);
}

void ViewImplementation::select_credential(u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    page().async_credential_selected(suggestion_id);

    Web::TextEditingCommand command;
    command.type = Web::TextEditingCommand::Type::InsertText;
    command.text = move(secret);
    command.fill_token = fill_token;
    page().async_insert_text(command);
}""", "0005")

edit("Services/Hub/View.cpp",
     """        on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_save_credentials(view_id(), payload);
        };""",
     """        on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_save_credentials(view_id(), payload);
        };

        on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {
            if (auto* ui = ConnectionFromUI::the())
                ui->async_view_request_credential_suggestions(view_id(), origin, content_position, minimum_width, field_kind, fill_token);
        };""", "0005")

edit("Services/Hub/HubClient.ipc",
     "    view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload) =|",
     """    view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload) =|
    view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) =|""", "0005")

edit("Services/Hub/HubServer.ipc",
     "    view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome) =|",
     """    view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome) =|
    view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) =|""", "0005")

edit("Services/Hub/ConnectionFromUI.h",
     "    virtual void view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome) override;",
     """    virtual void view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome) override;
    virtual void view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token) override;""", "0005")

edit("Services/Hub/ConnectionFromUI.cpp",
     """void ConnectionFromUI::view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome)
{
    if (auto* view = find_view(view_id)) {
        view->did_get_permission_answer(answer_id, outcome);
        view->push_state_to_ui();
    }
}""",
     """void ConnectionFromUI::view_answer_permission_request(u64 view_id, u64 answer_id, Web::Permissions::PromptOutcome outcome)
{
    if (auto* view = find_view(view_id)) {
        view->did_get_permission_answer(answer_id, outcome);
        view->push_state_to_ui();
    }
}

void ConnectionFromUI::view_select_credential(u64 view_id, u64 suggestion_id, Utf16String secret, u64 fill_token)
{
    if (auto* view = find_view(view_id))
        view->select_credential(suggestion_id, move(secret), fill_token);
}""", "0005")

edit("UI/Qt/NativeTextEditingLineEdit.cpp",
     "    switch (command.type) {\n    case Type::MoveBackward:",
     """    switch (command.type) {
    case Type::InsertText:
        if (!isReadOnly())
            insert(qstring_from_utf16_string(command.text));
        break;
    case Type::MoveBackward:""", "0006")
edit("UI/Qt/NativeTextEditingLineEdit.cpp",
     "include <UI/Qt/NativeTextEditingLineEdit.h>\n\n#ifdef AK_OS_MACOS",
     "include <UI/Qt/NativeTextEditingLineEdit.h>\n#include <UI/Qt/StringUtils.h>\n\n#ifdef AK_OS_MACOS", "0006")

# Upstream file: 0006 grew TextEditingCommand with text/fill_token, so these
# aggregate inits must name every field under -Werror,-Wmissing-field-initializers.
edit("UI/Qt/NativeTextEditingBindings.mm",
     "            return Web::TextEditingCommand { command.type, false };",
     "            return Web::TextEditingCommand { command.type, false, {}, {} };", "0006")

edit("UI/Qt/NativeTextEditingBindings.mm",
     "            return Web::TextEditingCommand { command.type, true };",
     "            return Web::TextEditingCommand { command.type, true, {}, {} };", "0006")

edit("UI/Qt/RemoteView.h",
     "    decltype(Hub::View::on_request_save_credentials) on_request_save_credentials;",
     """    decltype(Hub::View::on_request_save_credentials) on_request_save_credentials;
    decltype(Hub::View::on_request_credential_suggestions) on_request_credential_suggestions;""", "0005")

edit("UI/Qt/HubConnection.h",
     "    virtual void view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload) override;",
     """    virtual void view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload) override;
    virtual void view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token) override;""", "0005")

edit("UI/Qt/HubConnection.cpp",
     """void HubConnection::view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_save_credentials)
        return;
    view->on_request_save_credentials(payload);
}""",
     """void HubConnection::view_request_save_credentials(u64 view_id, Web::CredentialsSaveRequestPayload payload)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_save_credentials)
        return;
    view->on_request_save_credentials(payload);
}

void HubConnection::view_request_credential_suggestions(u64 view_id, URL::Origin origin, Gfx::IntPoint content_position, i32 minimum_width, Utf16String field_kind, u64 fill_token)
{
    auto* view = RemoteView::find(view_id);
    if (!view || !view->on_request_credential_suggestions)
        return;
    view->on_request_credential_suggestions(origin, content_position, minimum_width, field_kind, fill_token);
}""", "0005")

edit("UI/Qt/CredentialsPrompt.h",
     "#include <LibWeb/HTML/CredentialsSaveRequestPayload.h>",
     """#include <LibWebView/CredentialSuggestion.h>
#include <LibWeb/HTML/CredentialsSaveRequestPayload.h>""", "0005")

edit("UI/Qt/CredentialsPrompt.h",
     """    // Gate the offer before any dialog opens (never-for-this-site lists, empty
    // payloads). Default: always offer.
    virtual bool should_offer(Web::CredentialsSaveRequestPayload const&) { return true; }
};""",
     """    // Gate the offer before any dialog opens (never-for-this-site lists, empty
    // payloads). Default: always offer.
    virtual bool should_offer(Web::CredentialsSaveRequestPayload const&) { return true; }

    // Autofill popup (M7a): suggestions are { id, username, label } only — the
    // secret is handed out for one selection, only when the user picks it.
    // Defaults let a bridge that only saves register nothing for autofill.
    virtual Vector<WebView::CredentialSuggestion> suggestions_for(Utf16String const&, Utf16String const&) { return {}; }
    virtual Utf16String secret_for(u64) { return {}; }
};""", "0005")

edit("UI/Qt/Tab.cpp",
     """    view().on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
        if (Utf16String::from_utf8(view().url().origin().serialize()) != payload.frame_origin)
            return; // committed URL and payload origin must agree before any prompt
        show_save_credentials_prompt(view(), payload);
    };""",
     """    view().on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
        if (Utf16String::from_utf8(view().url().origin().serialize()) != payload.frame_origin)
            return; // committed URL and payload origin must agree before any prompt
        show_save_credentials_prompt(view(), payload);
    };

    view().on_request_credential_suggestions = [this](URL::Origin const& origin, Gfx::IntPoint position, i32 minimum_width, Utf16String const& field_kind, u64 fill_token) {
        // The popup may only ever aim at the page this tab actually shows.
        if (Utf16String::from_utf8(view().url().origin().serialize()) != Utf16String::from_utf8(origin.serialize()))
            return;
        auto* delegate = Ladybird::credentials_bridge_delegate();
        if (!delegate)
            return;
        auto suggestions = delegate->suggestions_for(Utf16String::from_utf8(origin.serialize()), field_kind);
        if (suggestions.is_empty())
            return;
        if (!m_credentials_dropdown)
            m_credentials_dropdown = new SelectDropdown(&view());
        Vector<Web::HTML::SelectItem> items;
        for (size_t index = 0; index < suggestions.size(); ++index) {
            auto const& suggestion = suggestions[index];
            Web::HTML::SelectItemOption option;
            option.id = static_cast<u32>(index); // per-popup index: vault ids are u64
            option.label = suggestion.label;
            option.value = suggestion.username;
            items.append(Web::HTML::SelectItem { AK::move(option) });
        }
        m_credentials_suggestions = AK::move(suggestions);
        m_credentials_fill_token = fill_token;
        m_credentials_dropdown->on_closed = [this](Optional<u32> const& selected_id) {
            if (!selected_id.has_value())
                return;
            auto* delegate = Ladybird::credentials_bridge_delegate();
            if (!delegate)
                return;
            if (*selected_id >= m_credentials_suggestions.size())
                return;
            auto const& suggestion = m_credentials_suggestions[static_cast<size_t>(*selected_id)];
            HubConnection::the().async_view_select_credential(view().view_id(), suggestion.suggestion_id,
                delegate->secret_for(suggestion.suggestion_id), m_credentials_fill_token);
        };
        m_credentials_dropdown->open(view().mapToGlobal(QPoint { position.x(), position.y() }), minimum_width, items);
    };""", "0005")

edit("UI/Qt/Tab.cpp",
     "#include <UI/Qt/CredentialsPrompt.h>",
     """#include <UI/Qt/CredentialsPrompt.h>
#include <UI/Qt/HubConnection.h>
#include <UI/Qt/SelectDropdown.h>""", "0005")

edit("UI/Qt/Tab.h",
     "    PermissionPromptQueue m_permission_prompts;",
     """    PermissionPromptQueue m_permission_prompts;
    SelectDropdown* m_credentials_dropdown { nullptr };
    Vector<WebView::CredentialSuggestion> m_credentials_suggestions;
    u64 m_credentials_fill_token { 0 };""", "0005")

edit("UI/Qt/Tab.h",
     "#include <AK/kmalloc.h>",
     """#include <AK/kmalloc.h>
#include <LibWebView/CredentialSuggestion.h>""", "0005")

edit("UI/Qt/Tab.h",
     "namespace Ladybird {",
     "namespace Ladybird {\n\nclass SelectDropdown;", "0005")

edit("UI/Qt/Tab.cpp",
     "#include <LibURL/URL.h>",
     """#include <LibURL/URL.h>
#include <LibWebCommon/HTML/SelectItem.h>""", "0005")

# ---------------- verify ALL anchors before touching anything ----------------
for path, pairs in EDITS.items():
    full = os.path.join(TREE, path)
    if not os.path.exists(full):
        sys.exit(f"missing file {path}")
    text = open(full).read()
    for old, _new, owner in pairs:
        n = text.count(old)
        if n != 1:
            sys.exit(f"anchor count {n} (want 1) in {path} owner {owner}: {old[:80]!r}")
print("anchors OK:", sum(len(v) for v in EDITS.values()), "edits across", len(EDITS), "files")

# ---------------- snapshot baseline, then apply ----------------
for path in EDITS:
    src = os.path.join(TREE, path)
    dst = os.path.join(BASELINE, path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    subprocess.run(["cp", src, dst], check=True)

for path, pairs in EDITS.items():
    full = os.path.join(TREE, path)
    text = open(full).read()
    for old, new, _ in pairs:
        text = text.replace(old, new, 1)
    open(full, "w").write(text)

# ---------------- extract hunks ----------------
def distinctive_lines(pairs, owner):
    out = []
    for old, new, own in pairs:
        if own != owner:
            continue
        old_set = {l.strip() for l in old.splitlines()}
        for line in new.splitlines():
            line = line.strip()
            if len(line) >= 24 and line not in old_set and not line.startswith(("//", "*")):
                out.append(line)
    return out


def classify_file(path, pairs, hunks):
    owners = {own for _, _, own in pairs}
    if len(owners) == 1:
        return [owners.pop()] * len(hunks)
    d5 = distinctive_lines(pairs, "0005")
    d6 = distinctive_lines(pairs, "0006")
    result = []
    for h in hunks:
        ht = "".join(h)
        s5 = sum(1 for l in d5 if l in ht)
        s6 = sum(1 for l in d6 if l in ht)
        if s5 == s6:
            sys.exit(f"hunk classification tie in {path}: s5={s5} s6={s6}\n{ht[:200]}")
        result.append("0005" if s5 > s6 else "0006")
    # completeness: every distinctive line of each owner must appear in that owner's hunks
    for owner, ds in (("0005", d5), ("0006", d6)):
        joined = "".join("".join(h) for h, o in zip(hunks, result) if o == owner)
        for l in ds:
            if l not in joined:
                sys.exit(f"missing added line for {owner} in {path}: {l!r}")
    return result

patch_files = {"0005": [], "0006": []}
for path in sorted(EDITS):
    r = subprocess.run(["diff", "-u", "-U3", os.path.join(BASELINE, path),
                        os.path.join(TREE, path)], capture_output=True, text=True)
    diff = r.stdout
    if not diff.strip():
        continue
    lines = diff.splitlines(keepends=True)
    hunks = []
    cur = None
    for ln in lines:
        if ln.startswith("@@"):
            if cur is not None:
                hunks.append(cur)
            cur = [ln]
        elif cur is None:
            continue  # drop diff -u's baseline ---/+++ path lines
        else:
            cur.append(ln)
    if cur is not None:
        hunks.append(cur)
    header = ["diff --git a/%s b/%s\n" % (path, path),
              "--- a/%s\n" % path,
              "+++ b/%s\n" % path]
    owners = classify_file(path, EDITS[path], hunks)
    for owner in ("0005", "0006"):
        mine = [h for h, o in zip(hunks, owners) if o == owner]
        if mine:
            patch_files[owner].append("".join(header) + "".join("".join(h) for h in mine))

def write_patch(name, title, body):
    header = (f"From ladybird-keychain-bridge patch-set — apply with `git apply` "
              f"on the pinned Ladybird tree (09fa4834) after 0001-0004.\n{title}\n\n")
    with open(os.path.join(PATCHES, name), "w") as f:
        f.write(header + "".join(body))
    print("wrote", name, "files:", sum(b.count("diff --git") for b in body))

write_patch("0005-autofill-popup.patch",
            "0005: field-anchored credential autofill popup (M7a).",
            patch_files["0005"])
write_patch("0006-textediting-insert.patch",
            "0006: TextEditingCommand::InsertText — user-activated credential injection (M7b).",
            patch_files["0006"])

# ---------------- restore ----------------
sh("git", "checkout", "--", ".")
sh("git", "clean", "-fdq", "-e", ".codegraph")
assert sh("git", "status", "--porcelain").strip() == "", "tree not clean after restore"
print("tree restored clean")
