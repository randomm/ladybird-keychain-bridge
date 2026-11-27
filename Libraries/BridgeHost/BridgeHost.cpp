#include "BridgeHost.h"

#include "SaveRequest.h"
#include "VaultStore.h"

#include <chrono>

namespace lkb {

std::int64_t SystemClock::now() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

namespace {

std::optional<Origin> parse_origin(std::string_view raw) {
    auto parsed = Origin::parse(raw);
    if (parsed.is_error())
        return std::nullopt;
    return std::move(parsed.value());
}

SaveRequest make_request(Origin const& frame, Origin const& top, Origin const& action,
                         std::string_view username, std::string_view secret) {
    SaveRequest request;
    request.frame_origin = frame;
    request.top_level_origin = top;
    request.submit_action_origin = action;
    request.username = std::string(username);
    request.secret = ByteBuffer(secret.begin(), secret.end());
    return request;
}

} // namespace

bool BridgeHost::should_offer(std::string_view frame_origin, std::string_view submit_action_origin,
                              std::string_view username, std::string_view secret) {
    auto frame = parse_origin(frame_origin);
    auto action = parse_origin(submit_action_origin);
    if (!frame.has_value() || !action.has_value())
        return false;
    SaveRequest request = make_request(*frame, *frame, *action, username, secret);
    auto decision = m_service.offer_save(request);
    return !decision.is_error() && decision.value().kind == SaveDecision::Kind::Save;
}

void BridgeHost::did_decide(std::string_view frame_origin, std::string_view top_level_origin,
                            std::string_view submit_action_origin, std::string_view username,
                            std::string_view secret, Outcome outcome) {
    auto frame = parse_origin(frame_origin);
    auto top = parse_origin(top_level_origin);
    auto action = parse_origin(submit_action_origin);
    if (!frame.has_value() || !top.has_value() || !action.has_value())
        return;
    SaveRequest request = make_request(*frame, *top, *action, username, secret);

    // The service's own verdict is re-derived, so a decision routed around the
    // offer path cannot smuggle a rejected save through (cross-origin submits and
    // http origins stay rejected; never-listed becomes the NeverForSite route).
    auto decision = m_service.offer_save(request);
    if (decision.is_error())
        return;

    CredentialService::UserDecision user =
        outcome == Outcome::Save           ? CredentialService::UserDecision::Save
        : outcome == Outcome::NeverForSite ? CredentialService::UserDecision::NeverForSite
                                           : CredentialService::UserDecision::NotNow;
    (void)m_service.on_prompt_result(request, decision.value(), user);
}

std::vector<BridgeHost::Suggestion> BridgeHost::suggestions_for(std::string_view origin) {
    std::vector<Suggestion> out;
    auto parsed = parse_origin(origin);
    if (!parsed.has_value())
        return out;
    auto page_token = m_service.issue_page_token(*parsed);
    if (page_token.is_error())
        return out;
    auto matches = m_service.lookup_for_origin(*parsed, std::nullopt, page_token.value());
    if (matches.is_error())
        return out;
    for (auto& match : matches.value()) {
        out.push_back(
            {static_cast<std::uint64_t>(match.id), match.record.username, match.record.username});
        // The secret stays here, in-process, until the user selects this id.
        m_pending_secrets[static_cast<std::uint64_t>(match.id)] =
            std::string(match.record.secret.begin(), match.record.secret.end());
    }
    return out;
}

std::optional<std::string> BridgeHost::take_secret(std::uint64_t id) {
    auto it = m_pending_secrets.find(id);
    if (it == m_pending_secrets.end())
        return std::nullopt;
    std::string secret = std::move(it->second);
    m_pending_secrets.erase(it); // single use: a second take never re-answers
    return secret;
}

std::optional<std::pair<std::string, std::string>>
BridgeHost::js_get(std::string_view origin, bool allow_silent, bool password_requested) {
    // A get() that did not ask for password credentials must not touch the vault.
    if (!password_requested)
        return std::nullopt;
    auto parsed = parse_origin(origin);
    if (!parsed.has_value())
        return std::nullopt;
    auto match = m_service.js_get(*parsed, allow_silent);
    if (match.is_error() || !match.value().has_value())
        return std::nullopt;
    auto& record = match.value()->record;
    return std::make_pair(record.username, std::string(record.secret.begin(), record.secret.end()));
}

void BridgeHost::js_store(std::string_view origin, std::string_view username,
                          std::string_view secret) {
    auto parsed = parse_origin(origin);
    if (!parsed.has_value())
        return;
    SaveRequest request = make_request(*parsed, *parsed, *parsed, username, secret);
    // navigator.credentials.store() is an explicit page request: the decision
    // is Save, but the service still refuses http origins by policy.
    SaveDecision decision;
    decision.kind = SaveDecision::Kind::Save;
    (void)m_service.save_from_form(request, decision);
}

void BridgeHost::js_prevent_silent(std::string_view origin, bool prevent) {
    auto parsed = parse_origin(origin);
    if (!parsed.has_value())
        return;
    (void)m_service.set_prevent_silent_access(*parsed, prevent);
}

std::optional<CapabilityToken> BridgeHost::mint_token() {
    auto token = CapabilityToken::mint(m_auth, m_clock);
    if (token.is_error())
        return std::nullopt;
    return std::move(token.value());
}

std::vector<BridgeHost::Row> BridgeHost::rows() {
    std::vector<Row> out;
    auto token = mint_token();
    if (!token.has_value())
        return out;
    auto records = m_service.list(*token);
    if (records.is_error())
        return out;
    for (auto const& record : records.value())
        out.push_back({record.origin.serialize(), record.username, record.id});
    return out;
}

bool BridgeHost::remove(std::int64_t id) {
    auto token = mint_token();
    if (!token.has_value())
        return false;
    return !m_service.delete_credential(id, *token).is_error();
}

bool BridgeHost::remove_all(std::string_view origin) {
    auto token = mint_token();
    if (!token.has_value())
        return false;
    auto parsed = parse_origin(origin);
    if (!parsed.has_value())
        return false;
    return !m_service.delete_bulk(*parsed, *token).is_error();
}

std::optional<std::string> BridgeHost::export_csv() {
    auto token = mint_token();
    if (!token.has_value())
        return std::nullopt;
    auto csv = m_service.export_csv(*token);
    if (csv.is_error())
        return std::nullopt;
    return std::string(csv.value().begin(), csv.value().end());
}

} // namespace lkb
