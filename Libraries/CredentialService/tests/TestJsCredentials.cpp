#include "CapabilityToken.h"
#include "CredentialService.h"
#include "VaultStore.h"
#include "testing/FakeClock.h"
#include "testing/TestAssert.h"

#include <cstdio>
#include <string>

using namespace lkb;

static char path[] = "/tmp/lkb-jscred-XXXXXX";

static Origin origin_of(std::string_view s) {
    auto o = Origin::parse(s);
    EXPECT(!o.is_error());
    return std::move(o.value());
}

static void save(CredentialService& service, std::string_view origin, std::string_view user,
                 std::string_view secret) {
    SaveRequest r;
    r.frame_origin = origin_of(origin);
    r.top_level_origin = r.frame_origin;
    r.submit_action_origin = r.frame_origin;
    r.username = std::string(user);
    r.secret = ByteBuffer(secret.begin(), secret.end());
    auto d = service.offer_save(r);
    EXPECT(!d.is_error());
    EXPECT_EQ(static_cast<int>(d.value().kind), static_cast<int>(SaveDecision::Kind::Save));
    auto s = service.save_from_form(r, d.value());
    EXPECT(!s.is_error());
}

// navigator.credentials policy at the service (M8): exact-origin match with no
// silent cross-subdomain fill, and the per-origin preventSilentAccess flag.
int main() {
    std::remove(path);
    auto opened = VaultStore::open(path, ByteBuffer(16, 0x55));
    EXPECT(!opened.is_error());
    if (opened.is_error())
        return ::lkb::failures();
    FakeClock clock;
    CredentialService service(opened.value(), clock);

    save(service, "https://app.example", "erin", "pw-js-1");

    // exact-origin get returns the credential
    auto got = service.js_get(origin_of("https://app.example"), true);
    EXPECT(!got.is_error());
    EXPECT(got.value().has_value());
    if (got.value().has_value())
        EXPECT_EQ(got.value()->record.username, std::string("erin"));

    // subdomain never matches silently
    auto sub = service.js_get(origin_of("https://login.app.example"), true);
    EXPECT(!sub.is_error());
    EXPECT(!sub.value().has_value());

    // preventSilentAccess blocks the SILENT caller (allow_silent=false): a page
    // that asked for silent access after the user invoked preventSilentAccess()
    // gets no answer. A mediated (non-silent) get keeps working.
    EXPECT(!service.set_prevent_silent_access(origin_of("https://app.example"), true).is_error());
    auto blocked = service.js_get(origin_of("https://app.example"), false);
    EXPECT(blocked.is_error());
    if (blocked.is_error())
        EXPECT_EQ(static_cast<int>(blocked.error().code),
                  static_cast<int>(ErrorCode::Unauthorized));

    auto mediated_ok = service.js_get(origin_of("https://app.example"), true);
    EXPECT(!mediated_ok.is_error());
    EXPECT(mediated_ok.value().has_value());

    // Review fix: js_get enforces https-or-localhost-explicit-port even for
    // rows placed in the vault by another path (import, migration, bug).
    {
        auto& vault = opened.value();
        CredentialRecord smuggled;
        smuggled.origin = origin_of("http://evil.example");
        smuggled.username = "mallory";
        std::string sec = "leaked-attempt";
        smuggled.secret = ByteBuffer(sec.begin(), sec.end());
        EXPECT(!vault.put(smuggled).is_error());
        auto denied = service.js_get(origin_of("http://evil.example"), true);
        EXPECT(denied.is_error());

        auto localhost_ok = service.js_get(origin_of("http://localhost:8443"), true);
        EXPECT(!localhost_ok.is_error());
    }

    return ::lkb::failures();
}
