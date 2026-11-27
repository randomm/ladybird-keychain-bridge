#pragma once

#include "CapabilityToken.h"
#include "Clock.h"
#include "SaveRequest.h"
#include "VaultStore.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lkb {

struct AuditEvent {
    std::string event;
    std::string origin;
    std::size_t length{0}; // length only — never secret material
};

struct Capabilities {
    // Fail closed: nothing is claimed enabled until the integrator feeds the
    // SystemVaultSource probe matrix in via set_capabilities().
    bool save_enabled{false};
    bool autofill_enabled{false};
    bool keychain_available{false};
};

// The security core. Contains zero log/crash/print calls: the only observable
// side-channel is audit_log(), whose events carry {event, origin, length}.
class CredentialService {
  public:
    CredentialService(VaultStore& vault, Clock& clock) : m_vault(vault), m_clock(clock) {}

    ErrorOr<SaveDecision> offer_save(SaveRequest const&);
    ErrorOr<std::vector<Match>> lookup_for_origin(Origin const&,
                                                  std::optional<std::string_view> hint,
                                                  std::uint64_t page_token);
    ErrorOr<void> save_from_form(SaveRequest const&, SaveDecision const&);
    // Admin surfaces: a live, unconsumed CapabilityToken is required and each
    // token unlocks exactly one admin call (replay within the TTL fails closed).
    ErrorOr<void> delete_credential(std::int64_t id, CapabilityToken&);
    ErrorOr<void> delete_bulk(Origin const&, CapabilityToken&);
    ErrorOr<std::vector<CredentialRecord>> list(CapabilityToken&);

    // CSV bridge (admin surfaces, AGENTS.md): token-gated wrappers over the
    // free functions, which stay vault-only for tooling/tests.
    ErrorOr<std::size_t> import_csv(ByteBuffer const& csv, CapabilityToken&);
    ErrorOr<ByteBuffer> export_csv(CapabilityToken&);

    ErrorOr<void> mark_never(Origin const&);

    // Save-prompt outcome from the UI (Task 13 / M6): routes the user's choice
    // through the service exactly once.
    enum class UserDecision { Save, NotNow, NeverForSite };
    ErrorOr<void> on_prompt_result(SaveRequest const&, SaveDecision const&, UserDecision);

    ErrorOr<std::uint64_t> issue_page_token(Origin const&);
    void revoke_page_token(std::uint64_t token);

    // navigator.credentials.get()/preventSilentAccess() policy (M8): exact-origin
    // match only — a subdomain is a different origin and never matches; the
    // per-origin preventSilentAccess flag blocks answers to SILENT callers
    // (allow_silent=false) only; and no read path answers a plain-http origin
    // outside the localhost-explicit-port opt-in.
    ErrorOr<std::optional<Match>> js_get(Origin const&, bool allow_silent);
    ErrorOr<void> set_prevent_silent_access(Origin const&, bool);

    std::vector<AuditEvent> const& audit_log() const { return m_audit; }
    Capabilities capabilities() const { return m_capabilities; }
    // The integrator feeds the SystemVaultSource probe matrix here; until then
    // everything reads false and dependent UI must degrade explicitly.
    void set_capabilities(Capabilities caps) { m_capabilities = caps; }

  private:
    void audit(std::string event, Origin const& origin, std::size_t length);

    VaultStore& m_vault;
    Clock& m_clock;
    std::vector<AuditEvent> m_audit;
    std::map<std::uint64_t, std::pair<Origin, std::int64_t>> m_page_tokens;
    std::map<std::string, bool> m_prevent_silent; // keyed by origin.serialize()
    Capabilities m_capabilities;
};

} // namespace lkb
