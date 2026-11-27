#pragma once

#include "ErrorOr.h"

#include <string>

namespace lkb {

// The host UI proves admin intent through the redis-backed auth endpoint; the
// service itself never stores credentials for it.
class RedisAuthCallback {
  public:
    virtual ~RedisAuthCallback() = default;
    virtual ErrorOr<std::string> request_token() = 0;
};

} // namespace lkb
