#pragma once

#include "RedisAuthCallback.h"

namespace lkb {

class FakeRedisAuth final : public RedisAuthCallback {
  public:
    ErrorOr<std::string> request_token() override {
        if (m_fail)
            return ErrorOr<std::string>::error({ErrorCode::Unauthorized, "redis auth refused"});
        ++m_calls;
        return ErrorOr<std::string>::ok(m_value);
    }
    void set_fail(bool v) { m_fail = v; }
    void set_value(std::string v) { m_value = std::move(v); }
    int calls() const { return m_calls; }

  private:
    bool m_fail{false};
    int m_calls{0};
    std::string m_value{"tok-dev-value"};
};

} // namespace lkb
