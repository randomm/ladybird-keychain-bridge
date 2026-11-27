#pragma once

#include "Clock.h"

namespace lkb {

class FakeClock final : public Clock {
  public:
    explicit FakeClock(std::int64_t start = 1'000'000) : m_now(start) {}
    std::int64_t now() const override { return m_now; }
    void advance(std::int64_t seconds) { m_now += seconds; }

  private:
    std::int64_t m_now;
};

} // namespace lkb
