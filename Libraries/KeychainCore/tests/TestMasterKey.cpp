#include "MasterKey.h"
#include "testing/FakeKeychainBackend.h"
#include "testing/TestAssert.h"

using namespace lkb;

int main()
{
    // 1. create-on-first-use with injected RNG; second call reads the stored key.
    {
        FakeKeychainBackend fake;
        ByteBuffer fake_key(16, 0xAB);
        auto rng = [&](size_t n) { return ByteBuffer(n, 0xAB); };
        auto first = master_key_or_create(fake, rng);
        EXPECT(!first.is_error());
        if (!first.is_error()) {
            EXPECT_EQ(first.value().size(), static_cast<size_t>(16));
            EXPECT(first.value() == fake_key);
        }
        auto second = master_key_or_create(fake, rng);
        EXPECT(!second.is_error());
        EXPECT(second.value() == fake_key);
        EXPECT_EQ(fake.stored().has_value(), true);
    }

    // 2. locked keychain: typed InteractionNotAllowed, surfaced, no retry loop.
    {
        FakeKeychainBackend fake;
        fake.set_read_error(KeychainError::InteractionNotAllowed);
        auto rng = [](size_t n) { return ByteBuffer(n, 0x01); };
        auto r = master_key_or_create(fake, rng);
        EXPECT(r.is_error());
        if (r.is_error())
            EXPECT_EQ(static_cast<int>(r.error().code), static_cast<int>(ErrorCode::InteractionNotAllowed));
        EXPECT_EQ(fake.read_count(), 1); // no silent retry
    }

    // 3. corrupt stored blob (15 bytes) -> UnexpectedData, never a short key.
    {
        FakeKeychainBackend fake;
        fake.set_stored(ByteBuffer(15, 0x02));
        auto rng = [](size_t n) { return ByteBuffer(n, 0x03); };
        auto r = master_key_or_create(fake, rng);
        EXPECT(r.is_error());
        if (r.is_error())
            EXPECT_EQ(static_cast<int>(r.error().code), static_cast<int>(ErrorCode::UnexpectedData));
    }

    // 4. backend unavailable -> typed failure, creation not attempted.
    {
        FakeKeychainBackend fake;
        fake.set_available(false);
        auto rng = [](size_t n) { return ByteBuffer(n, 0x04); };
        auto r = master_key_or_create(fake, rng);
        EXPECT(r.is_error());
        EXPECT_EQ(fake.write_count(), 0);
    }

    return ::lkb::failures();
}
