#pragma once

#include <cstdint>

namespace lkb {

class Clock {
  public:
    virtual ~Clock() = default;
    virtual std::int64_t now() const = 0;
};

} // namespace lkb
