#include "CredentialService.h"

#include <openssl/rand.h>

namespace lkb {

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

ErrorOr<void> CredentialService::delete_credential(std::int64_t id, CapabilityToken const& token) {
    if (!token.valid())
        return ErrorOr<void>::error({ErrorCode::Unauthorized, "capability required"});
    auto rm = m_vault.remove_credential(id);
    if (rm.is_error())
        return rm;
    m_audit.push_back({"delete", "", 0});
    return ErrorOr<void>::ok();
}

ErrorOr<void> CredentialService::delete_bulk(Origin const& origin, CapabilityToken const& token) {
    if (!token.valid())
        return ErrorOr<void>::error({ErrorCode::Unauthorized, "capability required"});
    auto rm = m_vault.remove_origin(origin);
    if (rm.is_error())
        return rm;
    audit("delete-bulk", origin, 0);
    return ErrorOr<void>::ok();
}

ErrorOr<std::vector<CredentialRecord>> CredentialService::list(CapabilityToken const& token) {
    if (!token.valid())
        return ErrorOr<std::vector<CredentialRecord>>::error(
            {ErrorCode::Unauthorized, "capability required"});
    size_t undecodable = 0;
    auto all = m_vault.all(undecodable);
    if (all.is_error())
        return all;
    if (undecodable > 0)
        m_audit.push_back({"undecodable-count", "", undecodable});
    return all;
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

Capabilities CredentialService::capabilities() const {
    return Capabilities{};
}

} // namespace lkb
