// Compile+link proof for the Apple backend ONLY. Deliberately never calls
// is_available()/read_master_key(): unit tests must not touch the real keychain.
#include "SecItemKeychainBackend.h"
#include "testing/TestAssert.h"

int main()
{
    EXPECT(sizeof(lkb::SecItemKeychainBackend) > 0);
    // Reference the factory symbol without invoking any keychain path.
    EXPECT(lkb::SecItemKeychainBackend::create != nullptr);
    return ::lkb::failures();
}
