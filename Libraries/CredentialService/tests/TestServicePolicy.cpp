#include "CapabilityToken.h"
#include "CredentialService.h"
#include "VaultStore.h"
#include "testing/FakeClock.h"
#include "testing/FakeRedisAuth.h"
#include "testing/TestAssert.h"

#include <cstdio>
#include <string>
#include <unistd.h>

using namespace lkb;
using UserDecision = CredentialService::UserDecision;

static char path[] = "/tmp/lkb-policy-XXXXXX";

static Origin origin_of(std::string_view s) {
    auto o = Origin::parse(s);
    EXPECT(!o.is_error());
    return std::move(o.value());
}

static SaveRequest request(std::string_view frame, std::string_view submit,
                           std::string_view secret = "sup3r-s3cr3t-value") {
    SaveRequest r;
    r.frame_origin = origin_of(frame);
    r.top_level_origin = r.frame_origin;
    r.submit_action_origin = origin_of(submit);
    r.username = "erin";
    r.secret = ByteBuffer(secret.begin(), secret.end());
    return r;
}

int main() {
    std::remove(path);
    auto opened = VaultStore::open(path, ByteBuffer(16, 0x77));
    EXPECT(!opened.is_error());
    FakeClock clock;
    CredentialService service(opened.value(), clock);

    // cross-origin submit rejected
    {
        auto d = service.offer_save(request("https://a.example", "https://b.example"));
        EXPECT(!d.is_error());
        EXPECT_EQ(static_cast<int>(d.value().kind), static_cast<int>(SaveDecision::Kind::Reject));
        EXPECT_EQ(static_cast<int>(d.value().reason),
                  static_cast<int>(SaveDecision::Reason::CrossOriginSubmit));
    }

    // http rejected unless localhost-with-explicit-port
    {
        auto d = service.offer_save(request("http://evil.example", "http://evil.example"));
        EXPECT(!d.is_error());
        EXPECT_EQ(static_cast<int>(d.value().kind), static_cast<int>(SaveDecision::Kind::Reject));
        EXPECT_EQ(static_cast<int>(d.value().reason),
                  static_cast<int>(SaveDecision::Reason::HttpProhibited));

        auto ok = service.offer_save(request("http://localhost:8080", "http://localhost:8080"));
        EXPECT(!ok.is_error());
        EXPECT_EQ(static_cast<int>(ok.value().kind), static_cast<int>(SaveDecision::Kind::Save));
    }

    // https save allowed + persisted
    {
        auto d = service.offer_save(request("https://login.example", "https://login.example"));
        EXPECT(!d.is_error());
        EXPECT_EQ(static_cast<int>(d.value().kind), static_cast<int>(SaveDecision::Kind::Save));
        SaveDecision save{SaveDecision::Kind::Save, SaveDecision::Reason::None};
        EXPECT(
            !service.save_from_form(request("https://login.example", "https://login.example"), save)
                 .is_error());
    }

    // never-listed origin: silent reject (NeverList), no save
    {
        EXPECT(!service.mark_never(origin_of("https://spam.example")).is_error());
        auto d = service.offer_save(request("https://spam.example", "https://spam.example"));
        EXPECT(!d.is_error());
        EXPECT_EQ(static_cast<int>(d.value().kind),
                  static_cast<int>(SaveDecision::Kind::NeverList));
        SaveDecision forced{SaveDecision::Kind::Save, SaveDecision::Reason::None};
        EXPECT(
            !service.save_from_form(request("https://spam.example", "https://spam.example"), forced)
                 .is_error());
        auto& vault = opened.value();
        auto rows = vault.find(origin_of("https://spam.example"), std::nullopt);
        EXPECT(rows.value().empty()); // never-list is enforced in save_from_form too
    }

    // admin gating: list/delete_bulk require a live CapabilityToken
    FakeRedisAuth auth;
    auto token = CapabilityToken::mint(auth, clock);
    EXPECT(!token.is_error());
    {
        auto l = service.list(token.value());
        EXPECT(!l.is_error());
        EXPECT_EQ(l.value().size(), static_cast<size_t>(1));
    }
    {
        token.value().revoke();
        auto l = service.list(token.value());
        EXPECT(l.is_error());
        if (l.is_error())
            EXPECT_EQ(static_cast<int>(l.error().code), static_cast<int>(ErrorCode::Unauthorized));
        auto del = service.delete_bulk(origin_of("https://login.example"), token.value());
        EXPECT(del.is_error());
    }

    // page-token gating for autofill lookup
    {
        auto pt = service.issue_page_token(origin_of("https://login.example"));
        EXPECT(!pt.is_error());
        auto found =
            service.lookup_for_origin(origin_of("https://login.example"), std::nullopt, pt.value());
        EXPECT(!found.is_error());
        EXPECT_EQ(found.value().size(), static_cast<size_t>(1));

        service.revoke_page_token(pt.value());
        auto denied =
            service.lookup_for_origin(origin_of("https://login.example"), std::nullopt, pt.value());
        EXPECT(denied.is_error());
        if (denied.is_error())
            EXPECT_EQ(static_cast<int>(denied.error().code),
                      static_cast<int>(ErrorCode::Unauthorized));

        // foreign-origin page token cannot be replayed elsewhere
        auto pt2 = service.issue_page_token(origin_of("https://other.example"));
        auto crossed = service.lookup_for_origin(origin_of("https://login.example"), std::nullopt,
                                                 pt2.value());
        EXPECT(crossed.is_error());
    }

    // Save-prompt user decisions (Task 13 / M6) route exactly once.
    {
        auto& vault = opened.value();
        auto req = request("https://prompt.example", "https://prompt.example");
        auto dec = service.offer_save(req);
        EXPECT(!dec.is_error());
        EXPECT_EQ(static_cast<int>(dec.value().kind), static_cast<int>(SaveDecision::Kind::Save));

        // NotNow: neither stored nor never-listed.
        EXPECT(!service.on_prompt_result(req, dec.value(), UserDecision::NotNow).is_error());
        EXPECT(vault.find(origin_of("https://prompt.example"), std::nullopt).value().empty());
        EXPECT(!vault.is_never(origin_of("https://prompt.example")).value());

        // NeverForSite: never-listed, nothing stored.
        EXPECT(!service.on_prompt_result(req, dec.value(), UserDecision::NeverForSite).is_error());
        EXPECT(vault.is_never(origin_of("https://prompt.example")).value());
        EXPECT(vault.find(origin_of("https://prompt.example"), std::nullopt).value().empty());

        // Save: stored exactly once.
        auto req2 = request("https://prompt2.example", "https://prompt2.example");
        auto dec2 = service.offer_save(req2);
        EXPECT(!service.on_prompt_result(req2, dec2.value(), UserDecision::Save).is_error());
        EXPECT_EQ(vault.find(origin_of("https://prompt2.example"), std::nullopt).value().size(),
                  static_cast<size_t>(1));
        EXPECT(!service.on_prompt_result(req2, dec2.value(), UserDecision::Save).is_error());
        EXPECT_EQ(vault.find(origin_of("https://prompt2.example"), std::nullopt).value().size(),
                  static_cast<size_t>(1)); // upsert, not duplicate

        // A Save decision on a service-rejected policy never writes.
        auto bad = request("https://a2.example", "https://b2.example");
        auto rejected = service.offer_save(bad);
        EXPECT(!rejected.is_error());
        auto res = service.on_prompt_result(bad, rejected.value(), UserDecision::Save);
        EXPECT(res.is_error());
        EXPECT(vault.find(origin_of("https://a2.example"), std::nullopt).value().empty());
    }

    // Review Focus 1: secrets never appear in audit events.
    {
        bool leaked = false;
        for (auto& ev : service.audit_log()) {
            std::string joined = ev.event + "|" + ev.origin;
            if (joined.find("sup3r-s3cr3t-value") != std::string::npos)
                leaked = true;
        }
        EXPECT(!leaked);
        bool has_event = false;
        for (auto& ev : service.audit_log()) {
            if (ev.event == "save")
                has_event = true;
        }
        EXPECT(has_event);
    }

    // Review fix: capabilities fail closed until the integrator feeds them
    // from the SystemVaultSource probe matrix (no hardcoded all-true lie).
    {
        auto caps = service.capabilities();
        EXPECT(!caps.save_enabled);
        EXPECT(!caps.autofill_enabled);
        EXPECT(!caps.keychain_available);
        Capabilities on;
        on.save_enabled = on.autofill_enabled = on.keychain_available = true;
        service.set_capabilities(on);
        auto fed = service.capabilities();
        EXPECT(fed.save_enabled);
        EXPECT(fed.autofill_enabled);
        EXPECT(fed.keychain_available);
    }

    // Review fix: the admin capability is single-use — a captured token cannot
    // be replayed for a second admin call inside its TTL window.
    {
        auto t = CapabilityToken::mint(auth, clock);
        EXPECT(!t.is_error());
        auto first = service.list(t.value());
        EXPECT(!first.is_error());
        auto second = service.list(t.value());
        EXPECT(second.is_error());
        if (second.is_error())
            EXPECT_EQ(static_cast<int>(second.error().code),
                      static_cast<int>(ErrorCode::Unauthorized));
    }

    // Review fix: read paths enforce the same https-or-localhost-explicit-port
    // rule as the save path, so a row smuggled in through any future entry
    // point still never answers a plain-http caller.
    {
        auto& vault = opened.value();
        CredentialRecord smuggled;
        smuggled.origin = origin_of("http://evil.example");
        smuggled.username = "mallory";
        std::string sec = "leaked-attempt";
        smuggled.secret = ByteBuffer(sec.begin(), sec.end());
        EXPECT(!vault.put(smuggled).is_error()); // storage itself is policy-free

        auto pt = service.issue_page_token(origin_of("http://evil.example"));
        EXPECT(!pt.is_error());
        auto denied =
            service.lookup_for_origin(origin_of("http://evil.example"), std::nullopt, pt.value());
        EXPECT(denied.is_error());
        if (denied.is_error())
            EXPECT_EQ(static_cast<int>(denied.error().code),
                      static_cast<int>(ErrorCode::Unauthorized));

        auto js_denied = service.js_get(origin_of("http://evil.example"), true);
        EXPECT(js_denied.is_error());

        auto ok_local = service.js_get(origin_of("http://localhost:8443"), true);
        EXPECT(!ok_local.is_error()); // opt-in origin answers (empty, not error)
        if (!ok_local.is_error())
            EXPECT(!ok_local.value().has_value());
    }

    // Review fix: the delete audit event names the record's origin (delete_bulk
    // already did; delete_credential logged an empty string).
    {
        auto& vault = opened.value();
        auto rows = vault.find(origin_of("https://login.example"), std::nullopt);
        EXPECT(!rows.is_error());
        EXPECT(!rows.value().empty());
        if (!rows.value().empty()) {
            auto id = rows.value()[0].id;
            auto t = CapabilityToken::mint(auth, clock);
            EXPECT(!t.is_error());
            auto del = service.delete_credential(id, t.value());
            EXPECT(!del.is_error());
            bool found = false;
            for (auto& ev : service.audit_log()) {
                if (ev.event == "delete" && ev.origin == "https://login.example")
                    found = true;
            }
            EXPECT(found);
        }
    }

    // Review fix: CSV import/export are admin surfaces — gated by a live token
    // at the service boundary (fail closed).
    {
        auto expired = CapabilityToken::mint(auth, clock);
        EXPECT(!expired.is_error());
        expired.value().revoke();
        auto bad = service.import_csv(ByteBuffer(), expired.value());
        EXPECT(bad.is_error());
        auto bad_out = service.export_csv(expired.value());
        EXPECT(bad_out.is_error());
        if (bad_out.is_error())
            EXPECT_EQ(static_cast<int>(bad_out.error().code),
                      static_cast<int>(ErrorCode::Unauthorized));

        auto good = CapabilityToken::mint(auth, clock);
        auto exp = service.export_csv(good.value());
        EXPECT(!exp.is_error());
    }

    std::remove(path);
    return ::lkb::failures();
}
