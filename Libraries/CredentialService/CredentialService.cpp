#include "CredentialService.h"

#include "CsvBridge.h"

#include <openssl/rand.h>

namespace lkb {

namespace {

// Never-break rule, enforced on EVERY read path (review fix): plain http is
// served only as the literal-localhost explicit-port opt-in. Storage stays
// policy-free so this single gate cannot be raced by a future entry point.
bool origin_served(Origin const& origin) {
    return origin.scheme != "http" || origin.is_local_opt_in();
}

} // namespace

void CredentialService::audit(std::string event, Origin const& origin, std::size_t length) {
    m_audit.push_back({std::move(event), origin.serialize(), length});
}

ErrorOr<SaveDecision> CredentialService::offer_save(SaveRequest const& request) {
    SaveDecision decision;
    if (!request.submit_action_origin.equal(request.frame_origin)) {
        decision.kind = SaveDecision::Kind::Reject;
        decision.reason = SaveDecision::Reason::CrossOriginSubmit;
        audit("save-reject", request.frame_origin, request.secret.size());
        return ErrorOr<SaveDecision>::ok(decision);
    }
    if (request.frame_origin.scheme == "http" && !request.frame_origin.is_local_opt_in()) {
        decision.kind = SaveDecision::Kind::Reject;
        decision.reason = SaveDecision::Reason::HttpProhibited;
        audit("save-reject", request.frame_origin, request.secret.size());
        return ErrorOr<SaveDecision>::ok(decision);
    }
    auto never = m_vault.is_never(request.frame_origin);
    if (never.is_error())
        return ErrorOr<SaveDecision>::error(never.error());
    if (never.value()) {
        decision.kind = SaveDecision::Kind::NeverList;
        decision.reason = SaveDecision::Reason::NeverListed; // silent: no prompt by contract
        return ErrorOr<SaveDecision>::ok(decision);
    }
    // Re-submitting what the vault already holds (e.g. a pre-filled autofilled
    // credential) must not nag: with an identical secret for this origin — and
    // username, when the form carried one — there is nothing new to capture.
    // An empty secret means "unknown at offer time": the prompt stays as-is.
    if (!request.secret.empty()) {
        std::optional<std::string_view> hint;
        if (!request.username.empty())
            hint = request.username;
        auto found = m_vault.find(request.frame_origin, hint);
        if (found.is_error())
            return ErrorOr<SaveDecision>::error(found.error());
        for (auto const& match : found.value()) {
            if (match.record.secret != request.secret)
                continue;
            if (!request.username.empty() && match.record.username != request.username)
                continue;
            decision.kind = SaveDecision::Kind::Unchanged;
            audit("save-unchanged", request.frame_origin, request.secret.size());
            return ErrorOr<SaveDecision>::ok(decision);
        }
    }
    decision.kind = SaveDecision::Kind::Save;
    return ErrorOr<SaveDecision>::ok(decision);
}

ErrorOr<void> CredentialService::save_from_form(SaveRequest const& request,
                                                SaveDecision const& decision) {
    // Enforced again here: callers cannot bypass offer_save's policy.
    if (decision.kind == SaveDecision::Kind::NeverList)
        return ErrorOr<void>::ok();
    auto never = m_vault.is_never(request.frame_origin);
    if (never.is_error())
        return ErrorOr<void>::error(never.error());
    if (never.value())
        return ErrorOr<void>::ok(); // never-list is authoritative regardless of passed decision
    if (!request.submit_action_origin.equal(request.frame_origin))
        return ErrorOr<void>::ok();
    if (request.frame_origin.scheme == "http" && !request.frame_origin.is_local_opt_in())
        return ErrorOr<void>::ok();

    CredentialRecord record;
    record.origin = request.frame_origin;
    record.username = request.username;
    record.secret = request.secret;
    auto now = m_clock.now();
    record.created = now;
    record.last_used = now;
    record.updated = now;
    record.form_meta = request.form_meta;

    auto put = m_vault.put(record);
    if (put.is_error())
        return put;
    audit("save", request.frame_origin, request.secret.size());
    return ErrorOr<void>::ok();
}

ErrorOr<std::vector<Match>>
CredentialService::lookup_for_origin(Origin const& origin, std::optional<std::string_view> hint,
                                     std::uint64_t page_token) {
    auto it = m_page_tokens.find(page_token);
    if (it == m_page_tokens.end())
        return ErrorOr<std::vector<Match>>::error({ErrorCode::Unauthorized, "unknown page token"});
    if (!it->second.first.equal(origin))
        return ErrorOr<std::vector<Match>>::error(
            {ErrorCode::Unauthorized, "page token origin mismatch"});
    if (m_clock.now() - it->second.second > CapabilityToken::ttl_seconds)
        return ErrorOr<std::vector<Match>>::error({ErrorCode::Unauthorized, "page token expired"});

    // Review fix: autofill lookups honor the scheme policy too, whatever path
    // the record took into the vault.
    if (!origin_served(origin))
        return ErrorOr<std::vector<Match>>::error(
            {ErrorCode::Unauthorized, "plain-http origin not served"});

    return m_vault.find(origin, hint);
}

ErrorOr<std::uint64_t> CredentialService::issue_page_token(Origin const& origin) {
    unsigned char raw[8];
    if (RAND_bytes(raw, static_cast<int>(sizeof(raw))) != 1)
        return ErrorOr<std::uint64_t>::error({ErrorCode::IO, "rng failure"});
    std::uint64_t token = 0;
    for (auto b : raw)
        token = token << 8 | b;
    if (token == 0)
        token = 1;
    m_page_tokens[token] = {origin, m_clock.now()};
    return ErrorOr<std::uint64_t>::ok(token);
}

void CredentialService::revoke_page_token(std::uint64_t token) {
    m_page_tokens.erase(token);
}

ErrorOr<void> CredentialService::delete_credential(std::int64_t id, CapabilityToken& token) {
    if (!token.consume())
        return ErrorOr<void>::error({ErrorCode::Unauthorized, "capability required or used"});
    // Review fix: the audit event names the record's origin (it was an empty
    // string); origin lookup happens before the removal.
    auto origin = m_vault.origin_of_id(id);
    if (origin.is_error())
        return ErrorOr<void>::error(origin.error());
    auto rm = m_vault.remove_credential(id);
    if (rm.is_error())
        return rm;
    audit("delete", origin.value(), 0);
    return ErrorOr<void>::ok();
}

ErrorOr<void> CredentialService::delete_bulk(Origin const& origin, CapabilityToken& token) {
    if (!token.consume())
        return ErrorOr<void>::error({ErrorCode::Unauthorized, "capability required or used"});
    auto rm = m_vault.remove_origin(origin);
    if (rm.is_error())
        return rm;
    audit("delete-bulk", origin, 0);
    return ErrorOr<void>::ok();
}

ErrorOr<std::vector<CredentialRecord>> CredentialService::list(CapabilityToken& token) {
    if (!token.consume())
        return ErrorOr<std::vector<CredentialRecord>>::error(
            {ErrorCode::Unauthorized, "capability required or used"});
    size_t undecodable = 0;
    auto all = m_vault.all(undecodable);
    if (all.is_error())
        return all;
    if (undecodable > 0)
        m_audit.push_back({"undecodable-count", "", undecodable});
    return all;
}

// CSV admin surfaces (AGENTS.md): fail closed without a live, unconsumed token.
ErrorOr<std::size_t> CredentialService::import_csv(ByteBuffer const& csv, CapabilityToken& token) {
    if (!token.consume())
        return ErrorOr<std::size_t>::error(
            {ErrorCode::Unauthorized, "capability required or used"});
    size_t skipped = 0;
    auto imported = lkb::import_csv(csv, m_vault, &skipped);
    if (imported.is_error())
        return imported;
    if (skipped > 0)
        m_audit.push_back({"import-skipped", "", skipped});
    return imported;
}

ErrorOr<ByteBuffer> CredentialService::export_csv(CapabilityToken& token) {
    if (!token.consume())
        return ErrorOr<ByteBuffer>::error({ErrorCode::Unauthorized, "capability required or used"});
    return lkb::export_csv(m_vault);
}

ErrorOr<void> CredentialService::on_prompt_result(SaveRequest const& request,
                                                  SaveDecision const& decision, UserDecision user) {
    switch (user) {
    case UserDecision::NotNow:
        m_audit.push_back({"prompt-not-now", request.frame_origin.serialize(), 0});
        return ErrorOr<void>::ok();
    case UserDecision::NeverForSite: {
        auto marked = mark_never(request.frame_origin);
        if (marked.is_error())
            return marked;
        m_audit.push_back({"prompt-never", request.frame_origin.serialize(), 0});
        return ErrorOr<void>::ok();
    }
    case UserDecision::Save:
        if (decision.kind != SaveDecision::Kind::Save)
            return ErrorOr<void>::error(
                Error{ErrorCode::InvalidOrigin, "policy rejected this save"});
        return save_from_form(request, decision);
    }
    return ErrorOr<void>::error(Error{ErrorCode::Invalid, "unknown user decision"});
}

ErrorOr<void> CredentialService::mark_never(Origin const& origin) {
    auto mark = m_vault.mark_never(origin);
    if (mark.is_error())
        return mark;
    audit("never", origin, 0);
    return ErrorOr<void>::ok();
}

ErrorOr<std::optional<Match>> CredentialService::js_get(Origin const& origin, bool allow_silent) {
    // Review fix: same scheme gate as every other read path.
    if (!origin_served(origin))
        return ErrorOr<std::optional<Match>>::error(
            {ErrorCode::Unauthorized, "plain-http origin not served"});

    auto it = m_prevent_silent.find(origin.serialize());
    if (!allow_silent && it != m_prevent_silent.end() && it->second)
        return ErrorOr<std::optional<Match>>::error(
            {ErrorCode::Unauthorized, "silent access prevented for this origin"});

    auto found = m_vault.find(origin, std::nullopt);
    if (found.is_error())
        return ErrorOr<std::optional<Match>>::error(found.error());
    if (found.value().empty())
        return ErrorOr<std::optional<Match>>::ok(
            std::nullopt); // exact-origin miss: silence, not error
    return ErrorOr<std::optional<Match>>::ok(found.value().front()); // most recently used first
}

ErrorOr<void> CredentialService::set_prevent_silent_access(Origin const& origin, bool prevent) {
    m_prevent_silent[origin.serialize()] = prevent;
    return ErrorOr<void>::ok();
}

} // namespace lkb
