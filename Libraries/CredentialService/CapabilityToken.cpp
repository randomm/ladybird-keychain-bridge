#include "CapabilityToken.h"

#include <openssl/rand.h>

namespace lkb {

ErrorOr<CapabilityToken> CapabilityToken::mint(RedisAuthCallback& auth, Clock& clock) {
    auto raw = auth.request_token();
    if (raw.is_error())
        return ErrorOr<CapabilityToken>::error(raw.error());

    // Independent CSPRNG nonce: the redis token value alone never identifies the
    // capability (defence in depth against token-value guessing).
    unsigned char nonce[16];
    if (RAND_bytes(nonce, static_cast<int>(sizeof(nonce))) != 1)
        return ErrorOr<CapabilityToken>::error({ErrorCode::Unauthorized, "rng failure"});

    static char const* hexd = "0123456789abcdef";
    std::string hex;
    for (auto b : nonce) {
        hex += hexd[b >> 4];
        hex += hexd[b & 15];
    }

    CapabilityToken token;
    token.m_value = raw.value() + ":" + hex;
    token.m_issued_at = clock.now();
    token.m_clock = &clock;
    return ErrorOr<CapabilityToken>::ok(std::move(token));
}

bool CapabilityToken::valid() const {
    if (m_revoked || !m_clock)
        return false;
    auto age = m_clock->now() - m_issued_at;
    return age >= 0 && age <= ttl_seconds;
}

} // namespace lkb
