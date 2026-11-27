#include "ErrorOr.h"
#include "Origin.h"
#include "testing/TestAssert.h"

int main()
{
    auto a = lkb::Origin::parse("HTTPS://Example.COM:443/");
    EXPECT(!a.is_error());
    if (!a.is_error()) {
        EXPECT_EQ(a.value().scheme, std::string("https"));
        EXPECT_EQ(a.value().host, std::string("example.com"));
        EXPECT_EQ(a.value().port, static_cast<std::uint16_t>(443));
    }

    auto b = lkb::Origin::parse("https://x");
    auto c = lkb::Origin::parse("https://x:443");
    EXPECT(!b.is_error() && !c.is_error());
    EXPECT(b.value().equal(c.value()));

    auto d = lkb::Origin::parse("https://u:p@x/y#z");
    EXPECT(d.is_error());
    if (d.is_error())
        EXPECT_EQ(static_cast<int>(d.error().code), static_cast<int>(lkb::ErrorCode::InvalidOrigin));

    auto l = lkb::Origin::parse("http://localhost:8080");
    EXPECT(!l.is_error());
    EXPECT(l.value().is_local_opt_in());

    auto e = lkb::Origin::parse("http://evil.com");
    EXPECT(!e.is_error());
    EXPECT(!e.value().is_local_opt_in());

    auto no_port = lkb::Origin::parse("http://localhost");
    EXPECT(!no_port.is_error());
    EXPECT(!no_port.value().is_local_opt_in()); // http opt-in requires explicit port

    auto loopback = lkb::Origin::parse("http://127.0.0.1:8080");
    EXPECT(!loopback.is_error());
    EXPECT(!loopback.value().is_local_opt_in()); // literal localhost only

    EXPECT(lkb::Origin::parse("not a url").is_error());
    EXPECT(lkb::Origin::parse("ftp://x").is_error());
    EXPECT(lkb::Origin::parse("https://").is_error());
    EXPECT(lkb::Origin::parse("https://x:99999").is_error());
    EXPECT(lkb::Origin::parse("https://x/y?q=1").is_error()); // query/fragment not origins

    auto p8080 = lkb::Origin::parse("http://localhost:8080");
    auto p8081 = lkb::Origin::parse("http://localhost:8081");
    EXPECT(!p8080.value().equal(p8081.value()));

    return ::lkb::failures();
}
