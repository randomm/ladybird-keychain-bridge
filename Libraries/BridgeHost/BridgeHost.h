#pragma once

#include "CapabilityToken.h"
#include "Clock.h"
#include "CredentialService.h"
#include "RedisAuthCallback.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lkb {

// Production clock for the browser host (tests keep using FakeClock).
class SystemClock final : public Clock {
  public:
    virtual std::int64_t now() const override;
};

// The headless half of the browser integration. The Qt host (patch 0009) is a
// thin type-conveter over this class; every vault-facing decision the UI makes
// lives here, on portable types, and is covered by the offline test suite.
// Secrets follow the UI contract: suggestions and rows never carry them; a
// secret is released once, by id, only when the user selects a suggestion.
class BridgeHost {
  public:
    BridgeHost(CredentialService& service, RedisAuthCallback& auth, Clock& clock)
        : m_service(service), m_auth(auth), m_clock(clock) {}

    enum class Outcome { Save, NotNow, NeverForSite };

    struct Suggestion {
        std::uint64_t id{0};
        std::string username;
        std::string label;
    };
    struct Row {
        std::string origin;
        std::string username;
        std::int64_t id{0};
    };

    // Save prompt (M6): the dialog opens only when the service itself would
    // accept — never-listed origins, cross-origin submits and plain-http
    // origins all decline here, before any widget exists.
    // secret is the submitted password when known at prompt time (the browser
    // host always has it); an empty secret keeps the legacy "unknown" behavior.
    bool should_offer(std::string_view frame_origin, std::string_view submit_action_origin,
                      std::string_view username, std::string_view secret = {});
    void did_decide(std::string_view frame_origin, std::string_view top_level_origin,
                    std::string_view submit_action_origin, std::string_view username,
                    std::string_view secret, Outcome outcome);

    // Autofill popup (M7a/M7b): lookup registers the matched secrets in-process;
    // take_secret hands one out exactly once, by id.
    std::vector<Suggestion> suggestions_for(std::string_view origin);
    std::optional<std::string> take_secret(std::uint64_t id);

    // navigator.credentials (M8): password:false asks resolve empty without a
    // vault read; matching is exact-origin (the service enforces the rest).
    std::optional<std::pair<std::string, std::string>>
    js_get(std::string_view origin, bool allow_silent, bool password_requested);
    void js_store(std::string_view origin, std::string_view username, std::string_view secret);
    void js_prevent_silent(std::string_view origin, bool prevent);

    // about:credentials (M9a): each admin call authenticates its own one-shot
    // CapabilityToken through the host's auth callback; refused auth = no-op.
    std::vector<Row> rows();
    bool remove(std::int64_t id);
    bool remove_all(std::string_view origin);
    std::optional<std::string> export_csv();

  private:
    std::optional<CapabilityToken> mint_token();

    CredentialService& m_service;
    RedisAuthCallback& m_auth;
    Clock& m_clock;
    std::map<std::uint64_t, std::string> m_pending_secrets;
};

} // namespace lkb
