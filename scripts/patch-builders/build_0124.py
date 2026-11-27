#!/usr/bin/env python3
"""Rebuild patches 0001-0004 with the final-review fixes layered on top of the
committed patch content.

ONE-SHOT BY DESIGN: the fix edits anchor on the ORIGINAL (pre-review) patch
content, so run this only to regenerate 0001-0004 from that state (git-check
out the pre-review patch files first, e.g. from the merge-base). Re-running it
on the already-fixed patches fails loudly at the first anchor — that is the
anchor discipline working, not a bug. build_0506/0708/0009 are idempotent
against the current committed stack.

For each patch i: restore the pinned tree, stack the *regenerated* 1..i-1, apply
the committed patch i, apply the fix edits (anchored on the post-patch state),
then emit the per-file diff from (before patch i) to (fixed state). Anchors
that do not match exactly once abort loudly — anchor drift is a finding, never
a silent pass.
"""
import os
import subprocess
import sys
import tempfile

import os as _os
BRIDGE_DEFAULT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
TREE = _os.environ.get("LKB_LADYBIRD_DIR", _os.path.join(_os.path.dirname(BRIDGE_DEFAULT), "ladybird-pinned"))
BRIDGE = BRIDGE_DEFAULT
PATCHES = os.path.join(BRIDGE, "patches/ladybird")

PATCH_NAMES = {
    "0001": "0001-form-detection.patch",
    "0002": "0002-split-page-heuristic.patch",
    "0003": "0003-credentials-ipc.patch",
    "0004": "0004-save-prompt.patch",
}
TITLES = {
    "0001": "0001: login-form detection + credential-save payload (M4).",
    "0002": "0002: split-page login heuristic on password blur (M4b).",
    "0003": "0003: credentials IPC structs and messages (WebContent boundary).",
    "0004": "0004: save-credentials prompt plumbing, UI to WebContent (M4).",
}


def sh(*args):
    r = subprocess.run(args, cwd=TREE, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"command failed: {args}\n{r.stdout}\n{r.stderr}")
    return r.stdout


def restore():
    sh("git", "checkout", "--", ".")
    sh("git", "clean", "-fdq", "-e", ".codegraph")
    if sh("git", "status", "--porcelain").strip():
        sys.exit("tree not clean after restore")


if sh("git", "status", "--porcelain").strip():
    sys.exit("pinned tree is not clean")

# path -> [(old, new, patch)] — fix edits anchored on the post-apply state.
EDITS = {}


def edit(path, old, new, owner):
    EDITS.setdefault(path, []).append((old, new, owner))


# ======================= 0001: form detection fixes =======================

F = "Libraries/LibWeb/HTML/HTMLFormElement.cpp"

# Drop the duplicated include the first pass added.
edit(F,
     "#include <LibWeb/HTML/SubmitEvent.h>\n#include <LibWeb/Page/Page.h>\n#include <LibWeb/HighResolutionTime/TimeOrigin.h>",
     "#include <LibWeb/HTML/SubmitEvent.h>\n#include <LibWeb/HighResolutionTime/TimeOrigin.h>",
     "0001")

# URL::Parser for the submit-action origin.
edit(F,
     "#include <LibTextCodec/Decoder.h>\n#include <LibWeb/Bindings/CSS.h>",
     "#include <LibTextCodec/Decoder.h>\n#include <LibURL/Parser.h>\n#include <LibURL/URL.h>\n#include <LibWeb/Bindings/CSS.h>",
     "0001")

# Empty passwords are not a save offer.
edit(F,
     "    if (!secret.has_value())\n        return {};",
     "    if (!secret.has_value() || secret->is_empty())\n        return {};",
     "0001")

# Submit action origin from the form's action attribute resolved against the
# document base URL; top_level_origin is a field, not a method.
edit(F,
     """    auto& document = form.document();
    payload.frame_origin = document.origin().serialize();
    payload.submit_action_origin = payload.frame_origin;
    if (auto top_level = document.relevant_settings_object().top_level_origin(); top_level.has_value())""",
     """    auto& document = form.document();
    payload.frame_origin = document.origin().serialize();
    // https://w3c.github.io/webappsec-credential-management/#submit-action-origin:
    // the form's action attribute resolved against the document base URL; an
    // absent action resolves to the document URL.
    URL::URL action_url = document.url();
    if (auto action_attribute = get_attribute_ns({}, AttributeNames::action); action_attribute.has_value()) {
        if (auto parsed = URL::Parser::basic_parse(*action_attribute, document.base_url()); parsed.has_value())
            action_url = parsed.release_value();
    }
    payload.submit_action_origin = action_url.origin().serialize();
    if (auto top_level = document.relevant_settings_object().top_level_origin; top_level.has_value())""",
     "0001")

# The save offer must not precede the submit event: move the notify after the
# dispatch block (canceled or validation-blocked submissions never prompt).
edit(F,
     """    // ladybird-keychain-bridge (M4): once per submitted form that carries a
    // password field, notify the UI so it can offer to save.
    if (auto payload = credentials_save_request_payload(*this); payload.has_value())
        document().page().client().page_did_request_save_credentials(*payload);

    // 5. If the submitted from submit() method flag is not set, then:""",
     "    // 5. If the submitted from submit() method flag is not set, then:",
     "0001")

edit(F,
     """        if (cannot_navigate())
            return {};
    }

    // 6. Let encoding be the result of picking an encoding for the form.""",
     """        if (cannot_navigate())
            return {};
    }

    // ladybird-keychain-bridge (M4): once per submitted form that carries a
    // non-empty password field, notify the UI so it can offer to save — after
    // the submit event fired and could have canceled the submission.
    if (auto payload = credentials_save_request_payload(*this); payload.has_value())
        document().page().client().page_did_request_save_credentials(*payload);

    // 6. Let encoding be the result of picking an encoding for the form.""",
     "0001")

T = "Tests/LibWeb/TestLoginFormDetection.cpp"
edit(T,
     """    auto payload = Web::HTML::HTMLFormElement::credentials_save_request_payload(
        static_cast<Web::HTML::HTMLFormElement&>(*form));
    EXPECT(!payload.has_value());
}""",
     """    auto payload = Web::HTML::HTMLFormElement::credentials_save_request_payload(
        static_cast<Web::HTML::HTMLFormElement&>(*form));
    EXPECT(!payload.has_value());
}

TEST_CASE(empty_password_form_yields_no_payload)
{
    auto document = create_document();
    auto form = add_form(document);
    add_input(form, "text"_utf16, "username"_utf16, "alice"_utf16);
    add_input(form, "password"_utf16, "password"_utf16, ""_utf16);

    auto payload = Web::HTML::HTMLFormElement::credentials_save_request_payload(
        static_cast<Web::HTML::HTMLFormElement&>(*form));
    EXPECT(!payload.has_value());
}

TEST_CASE(action_attribute_sets_submit_action_origin)
{
    auto document = create_document();
    auto form = add_form(document);
    MUST(form->set_attribute(Web::HTML::AttributeNames::action, "https://evil.example/login"_utf16));
    add_input(form, "text"_utf16, "username"_utf16, "alice"_utf16);
    add_input(form, "password"_utf16, "password"_utf16, "hunter2"_utf16);

    auto payload = Web::HTML::HTMLFormElement::credentials_save_request_payload(
        static_cast<Web::HTML::HTMLFormElement&>(*form));
    EXPECT(payload.has_value());
    if (payload.has_value()) {
        // The save is bound to where the password actually goes, not merely to
        // where the page came from: a cross-origin action must be visible here.
        EXPECT_EQ(payload->submit_action_origin, "https://evil.example"_string);
        EXPECT_NE(payload->submit_action_origin, payload->frame_origin);
    }
}""",
     "0001")

# ======================= 0002: split-page fixes =======================

edit("Libraries/LibWeb/HTML/HTMLInputElement.cpp",
     "        if (auto top = doc.relevant_settings_object().top_level_origin(); top.has_value())",
     "        if (auto top = doc.relevant_settings_object().top_level_origin; top.has_value())",
     "0002")

edit("Libraries/LibWeb/HTML/HTMLInputElement.cpp",
     """    if (m_type == TypeAttributeState::Password && !value().is_empty() && !has_same_page_username_field(*this)) {
        CredentialsSaveRequestPayload payload;""",
     """    if (m_type == TypeAttributeState::Password && !value().is_empty()
        && !m_credentials_blur_prompted && !has_same_page_username_field(*this)) {
        m_credentials_blur_prompted = true; // coalesce: one split-page offer per field instance
        CredentialsSaveRequestPayload payload;""",
     "0002")

edit("Libraries/LibWeb/HTML/HTMLInputElement.h",
     "    bool m_user_validity { false };",
     "    bool m_user_validity { false };\n    bool m_credentials_blur_prompted { false }; // ladybird-keychain-bridge (M4b)",
     "0002")

# ======================= 0003: ipc layering fixes =======================

IPC_C = "Services/WebContent/WebContentClient.ipc"
edit(IPC_C,
     "#include <LibWeb/StorageAPI/StorageKey.h>\n#include <LibWebView/CredentialSuggestion.h>\n",
     "#include <LibWeb/StorageAPI/StorageKey.h>\n",
     "0003")

edit(IPC_C,
     """[ExistingCpp]
struct WebView::CredentialSuggestion {
    u64 suggestion_id;
    Utf16String username;
    Utf16String label;
}

""",
     "",
     "0003")

IPC_S = "Services/WebContent/WebContentServer.ipc"
edit(IPC_S,
     "#include <LibWebCommon/Gamepad/GamepadStateBuffer.h>\n#include <LibWebView/CredentialSuggestion.h>\n",
     "#include <LibWebCommon/Gamepad/GamepadStateBuffer.h>\n",
     "0003")

# ======================= 0004: prompt fixes =======================

edit("UI/Qt/CredentialsPrompt.h",
     """class CredentialsBridgeDelegate {
public:
    virtual ~CredentialsBridgeDelegate() = default;
    virtual void did_decide(Web::CredentialsSaveRequestPayload const&, CredentialsPromptOutcome) = 0;
};""",
     """class CredentialsBridgeDelegate {
public:
    virtual ~CredentialsBridgeDelegate() = default;
    virtual void did_decide(Web::CredentialsSaveRequestPayload const&, CredentialsPromptOutcome) = 0;

    // Gate the offer before any dialog opens (never-for-this-site lists, empty
    // payloads). Default: always offer.
    virtual bool should_offer(Web::CredentialsSaveRequestPayload const&) { return true; }
};""",
     "0004")

edit("UI/Qt/CredentialsPrompt.cpp",
     """void show_save_credentials_prompt(QWidget& parent, Web::CredentialsSaveRequestPayload const& payload)
{
    auto* dialog = new QMessageBox(&parent);""",
     """void show_save_credentials_prompt(QWidget& parent, Web::CredentialsSaveRequestPayload const& payload)
{
    auto* bridge = credentials_bridge_delegate();
    if (!bridge || !bridge->should_offer(payload))
        return; // no vault linked, or the delegate declines: never show a dead-end prompt

    auto* dialog = new QMessageBox(&parent);""",
     "0004")

edit("UI/Qt/CredentialsPrompt.cpp",
     """    auto* save = dialog->addButton(QStringLiteral("Save"), QMessageBox::AcceptRole);
    dialog->addButton(QStringLiteral("Not now"), QMessageBox::RejectRole);""",
     """    auto* save = dialog->addButton(QStringLiteral("Save"), QMessageBox::AcceptRole);
    auto* not_now = dialog->addButton(QStringLiteral("Not now"), QMessageBox::RejectRole);""",
     "0004")

edit("UI/Qt/CredentialsPrompt.cpp",
     """        CredentialsPromptOutcome outcome = CredentialsPromptOutcome::Dismissed;
        if (clicked == save)
            outcome = CredentialsPromptOutcome::Saved;
        else if (clicked == never)
            outcome = CredentialsPromptOutcome::NeverForSite;""",
     """        CredentialsPromptOutcome outcome = CredentialsPromptOutcome::Dismissed;
        if (clicked == save)
            outcome = CredentialsPromptOutcome::Saved;
        else if (clicked == not_now)
            outcome = CredentialsPromptOutcome::NotNow;
        else if (clicked == never)
            outcome = CredentialsPromptOutcome::NeverForSite;""",
     "0004")

# The prompt must be aimed at the page the tab actually shows: a compromised
# WebContent process cannot target another tab through a spoofed payload.
edit("UI/Qt/Tab.cpp",
     """    view().on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
        show_save_credentials_prompt(view(), payload);
    };""",
     """    view().on_request_save_credentials = [this](Web::CredentialsSaveRequestPayload const& payload) {
        if (Utf16String::from_utf8(view().url().origin().serialize()) != payload.frame_origin)
            return; // committed URL and payload origin must agree before any prompt
        show_save_credentials_prompt(view(), payload);
    };""",
     "0004")

# Anchors are verified per patch inside the loop, against the state the fix
# edits actually apply to (after patches 1..i plus the existing patch i).


def files_touched(patch_name):
    out = []
    for line in open(os.path.join(PATCHES, patch_name)):
        if line.startswith("diff --git a/"):
            out.append(line.split(" b/")[1].strip())
    return out


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
    start = None
    for i, ln in enumerate(lines):
        if ln.startswith("@@"):
            start = i
            break
    if start is None:
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


for num, patch_name in PATCH_NAMES.items():
    restore()
    for prev_num in PATCH_NAMES:
        if prev_num >= num:
            break
        sh("git", "apply", os.path.join(PATCHES, PATCH_NAMES[prev_num]))

    touched = files_touched(patch_name) + [p for p, pairs in EDITS.items()
                                           if any(o == num for _, _, o in pairs)]
    touched = sorted(set(touched))

    base = {}
    for path in touched:
        full = os.path.join(TREE, path)
        base[path] = open(full).read() if os.path.exists(full) else None

    sh("git", "apply", os.path.join(PATCHES, patch_name))

    for path, pairs in EDITS.items():
        mine = [(old, new) for old, new, owner in pairs if owner == num]
        if not mine:
            continue
        full = os.path.join(TREE, path)
        text = open(full).read()
        for old, new in mine:
            if text.count(old) != 1:
                sys.exit(f"post-apply anchor miss in {path} for {num}: {old[:80]!r}")
            text = text.replace(old, new, 1)
        open(full, "w").write(text)

    body = []
    for path in touched:
        final = open(os.path.join(TREE, path)).read()
        a_text = base[path]
        hunks = hunks_between(a_text if a_text is not None else "", final)
        if not hunks:
            continue
        header = ["diff --git a/%s b/%s\n" % (path, path)]
        if a_text is None:
            header += ["new file mode 100644\n", "--- /dev/null\n", "+++ b/%s\n" % path]
        else:
            header += ["--- a/%s\n" % path, "+++ b/%s\n" % path]
        body.append("".join(header) + "".join("".join(h) for h in hunks))

    with open(os.path.join(PATCHES, patch_name), "w") as f:
        f.write(TITLES[num] + "\n\n" + "".join(body))
    print("wrote", patch_name, "files:", sum(b.count("diff --git") for b in body))

restore()
print("ALL 0001-0004 rebuilt")
