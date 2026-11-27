// The headless half of the UI integration: the Qt host converts Ladybird types
// and forwards here, so everything the browser does with the vault is testable
// offline (FakeKeychainBackend/FakeClock/FakeRedisAuth only, per the doctrine).
#include "BridgeHost.h"

#include "testing/FakeClock.h"
#include "testing/FakeRedisAuth.h"
#include "testing/TestAssert.h"

#include <string>
#include <unistd.h>

using namespace lkb;

int main() {
    FakeClock clock;
    FakeRedisAuth auth;

    static char path[] = "/tmp/lkb-host-XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0)
        ::close(fd);
    auto made = VaultStore::open(path, ByteBuffer(16, 7));
    ::unlink(path);
    EXPECT(!made.is_error());
    if (made.is_error())
        return ::lkb::failures();
    auto vault = std::move(made.value());
    CredentialService service{vault, clock};
    BridgeHost host{service, auth, clock};

    auto https = "https://login.example";

    // 1) save flow: offer, user saves, row appears; secrets never in rows.
    EXPECT(host.should_offer(https, https, "alice"));
    host.did_decide(https, https, https, "alice", "hunter2", BridgeHost::Outcome::Save);
    auto rows = host.rows();
    EXPECT_EQ(rows.size(), static_cast<size_t>(1));
    if (!rows.empty()) {
        EXPECT_EQ(rows[0].origin, std::string("https://login.example"));
        EXPECT_EQ(rows[0].username, std::string("alice"));
    }

    // 2) never-for-site suppresses the offer entirely.
    host.did_decide("https://never.example", https, https, "bob", "pw",
                    BridgeHost::Outcome::NeverForSite);
    EXPECT(!host.should_offer("https://never.example", https, "bob"));

    // 3) http (outside the localhost opt-in) is never offered.
    EXPECT(!host.should_offer("http://plain.example", https, "carol"));

    // 4) autofill: suggestions carry {id, username, label} only; the secret is
    //    released once, by id, after selection — never in the suggestion.
    auto suggestions = host.suggestions_for(https);
    EXPECT_EQ(suggestions.size(), static_cast<size_t>(1));
    if (!suggestions.empty()) {
        EXPECT_EQ(suggestions[0].username, std::string("alice"));
        auto secret = host.take_secret(suggestions[0].id);
        EXPECT(secret.has_value());
        if (secret.has_value())
            EXPECT_EQ(*secret, std::string("hunter2"));
        EXPECT(!host.take_secret(suggestions[0].id).has_value()); // single use
    }
    EXPECT(!host.take_secret(9999).has_value()); // unknown id

    // 5) js_get: exact origin only; no password ask resolves without a vault read.
    auto hit = host.js_get(https, true, true);
    EXPECT(hit.has_value());
    if (hit.has_value())
        EXPECT_EQ(hit->second, std::string("hunter2"));
    EXPECT(!host.js_get("https://other.example", true, true).has_value());
    EXPECT(!host.js_get(https, true, false).has_value()); // password:false → nothing

    // 6) js_store then js_get round-trips; preventSilentAccess blocks silent only.
    host.js_store("https://shop.example", "dave", "letmein");
    auto shop = host.js_get("https://shop.example", true, true);
    EXPECT(shop.has_value());
    host.js_prevent_silent("https://shop.example", true);
    EXPECT(!host.js_get("https://shop.example", false, true).has_value());
    EXPECT(host.js_get("https://shop.example", true, true).has_value());

    // 7) admin deletes mint their own single-use tokens; a refused auth is fail-closed.
    EXPECT_EQ(host.rows().size(), static_cast<size_t>(2));
    if (rows.size() == 1)
        EXPECT(host.remove(rows[0].id));
    EXPECT_EQ(host.rows().size(), static_cast<size_t>(1));
    auth.set_fail(true);
    EXPECT(!host.remove_all("https://shop.example")); // re-auth refused → nothing deleted
    EXPECT(host.rows().empty());                      // and the admin list is gated too
    auth.set_fail(false);
    EXPECT_EQ(host.rows().size(), static_cast<size_t>(1)); // the refused call deleted nothing
    EXPECT(host.remove_all("https://shop.example"));
    EXPECT_EQ(host.rows().size(), static_cast<size_t>(0));

    // 8) export forwards the service CSV (admin-gated; empty vault still exports header).
    auto csv = host.export_csv();
    EXPECT(csv.has_value());

    // 9) production clock: sane epoch seconds (token TTLs must not live in 1970),
    //    monotonic non-decreasing.
    SystemClock wall;
    auto t1 = wall.now();
    auto t2 = wall.now();
    EXPECT(t1 > 1700000000);
    EXPECT(t2 >= t1);

    return ::lkb::failures();
}
