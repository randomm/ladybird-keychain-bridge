#include "CapabilityToken.h"
#include "CredentialService.h"
#include "VaultStore.h"
#include "testing/FakeClock.h"
#include "testing/TestAssert.h"

#include <cstdio>
#include <string>

using namespace lkb;

static char path[] = "/tmp/lkb-autofill-XXXXXX";

static Origin origin_of(std::string_view s) {
    auto o = Origin::parse(s);
    EXPECT(!o.is_error());
    return std::move(o.value());
}

static SaveRequest request(std::string_view origin, std::string_view username,
                           std::string_view secret) {
    SaveRequest r;
    r.frame_origin = origin_of(origin);
    r.top_level_origin = r.frame_origin;
    r.submit_action_origin = r.frame_origin;
    r.username = std::string(username);
    r.secret = ByteBuffer(secret.begin(), secret.end());
    return r;
}

// Autofill lookup semantics behind the page-token gate (Task 14 / M7a):
// exact-origin matching, multi-account ordering, hint filtering, no-match
// silence. Suggestion payloads that reach the UI are { id, username, label }
// (patches/ladybird 0003 WebView::CredentialSuggestion) — secrets never
// travel with a suggestion; that contract lives at the UI boundary, not here.
int main() {
    std::remove(path);
    auto opened = VaultStore::open(path, ByteBuffer(16, 0x66));
    EXPECT(!opened.is_error());
    if (opened.is_error())
        return ::lkb::failures();
    FakeClock clock;
    CredentialService service(opened.value(), clock);

    auto save = [&](std::string_view origin, std::string_view user, std::string_view secret) {
        auto r = request(origin, user, secret);
        auto d = service.offer_save(r);
        EXPECT(!d.is_error());
        EXPECT_EQ(static_cast<int>(d.value().kind), static_cast<int>(SaveDecision::Kind::Save));
        auto s = service.save_from_form(r, d.value());
        EXPECT(!s.is_error());
    };

    save("https://accounts.example", "erin", "pw-erin-1");
    clock.advance(60);
    save("https://accounts.example", "alfred", "pw-alfred-2");
    clock.advance(60);
    save("https://accounts.example", "zoe", "pw-zoe-3");

    // multi-account: every credential registered at the exact origin is offered
    auto pt = service.issue_page_token(origin_of("https://accounts.example"));
    EXPECT(!pt.is_error());
    auto all =
        service.lookup_for_origin(origin_of("https://accounts.example"), std::nullopt, pt.value());
    EXPECT(!all.is_error());
    if (!all.is_error()) {
        EXPECT_EQ(all.value().size(), static_cast<std::size_t>(3));
        // most-recently-touched first: zoe, alfred, erin
        if (all.value().size() == 3) {
            EXPECT_EQ(all.value()[0].record.username, std::string("zoe"));
            EXPECT_EQ(all.value()[1].record.username, std::string("alfred"));
            EXPECT_EQ(all.value()[2].record.username, std::string("erin"));
        }
    }

    // username hint narrows to that account alone
    auto hinted = service.lookup_for_origin(origin_of("https://accounts.example"),
                                            std::string_view("alfred"), pt.value());
    EXPECT(!hinted.is_error());
    if (!hinted.is_error()) {
        EXPECT_EQ(hinted.value().size(), static_cast<std::size_t>(1));
        if (hinted.value().size() == 1)
            EXPECT_EQ(hinted.value()[0].record.username, std::string("alfred"));
    }

    // no match is silence, not an error
    auto empty_pt = service.issue_page_token(origin_of("https://quiet.example"));
    auto none = service.lookup_for_origin(origin_of("https://quiet.example"), std::nullopt,
                                          empty_pt.value());
    EXPECT(!none.is_error());
    if (!none.is_error())
        EXPECT_EQ(none.value().size(), static_cast<std::size_t>(0));

    // a subdomain of a populated origin is a different, empty origin (exact-origin rule)
    auto sub_pt = service.issue_page_token(origin_of("https://login.accounts.example"));
    auto sub = service.lookup_for_origin(origin_of("https://login.accounts.example"), std::nullopt,
                                         sub_pt.value());
    EXPECT(!sub.is_error());
    if (!sub.is_error())
        EXPECT_EQ(sub.value().size(), static_cast<std::size_t>(0));

    return ::lkb::failures();
}
