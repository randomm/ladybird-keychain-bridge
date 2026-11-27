#include "CapabilityToken.h"
#include "testing/FakeClock.h"
#include "testing/FakeRedisAuth.h"
#include "testing/TestAssert.h"

using namespace lkb;

int main() {
    FakeClock clock;
    FakeRedisAuth auth;

    auto minted = CapabilityToken::mint(auth, clock);
    EXPECT(!minted.is_error());
    EXPECT_EQ(auth.calls(), 1);
    if (!minted.is_error()) {
        EXPECT(minted.value().valid());
        clock.advance(59);
        EXPECT(minted.value().valid());
        clock.advance(2); // 61 s total
        EXPECT(!minted.value().valid());
    }

    // revoked tokens are dead immediately
    {
        FakeClock c2;
        FakeRedisAuth a2;
        auto t = CapabilityToken::mint(a2, c2);
        EXPECT(!t.is_error());
        t.value().revoke();
        EXPECT(!t.value().valid());
    }

    // mint surfaces callback failures (fail closed)
    {
        FakeClock c3;
        FakeRedisAuth a3;
        a3.set_fail(true);
        auto t = CapabilityToken::mint(a3, c3);
        EXPECT(t.is_error());
    }

    return ::lkb::failures();
}
