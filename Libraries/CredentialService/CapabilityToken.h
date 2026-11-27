#pragma once

#include "Clock.h"
#include "ErrorOr.h"
#include "RedisAuthCallback.h"

#include <cstdint>
#include <string>

namespace lkb {

// Single-use admin capability, 60 s TTL, clock injected for tests. Fail closed:
// invalid tokens never unlock admin methods.
class CapabilityToken {
  public:
    static constexpr std::int64_t ttl_seconds = 60;

    static ErrorOr<CapabilityToken> mint(RedisAuthCallback&, Clock&);

    bool valid() const;
    // Consume-on-use: the first valid call unlocks one admin operation; any
    // later call (same TTL window or not) fails closed.
    bool consume();
    void revoke() { m_revoked = true; }
    std::string const& value() const { return m_value; }

  private:
    CapabilityToken() = default;

    std::string m_value;
    std::int64_t m_issued_at{0};
    bool m_revoked{false};
    bool m_used{false};
    Clock* m_clock{nullptr};
};

} // namespace lkb
