// M10: the system-vault probe reports capabilities EXPLICITLY and its audit
// carries {operation, status} tokens only — never key or secret material.
#include "SystemVaultSource.h"
#include "testing/FakeKeychainBackend.h"

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>

static int s_failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                            \
            ++s_failures;                                                                          \
        }                                                                                          \
    } while (0)

namespace {

// A backend whose read always returns different bytes than what was written —
// the vault lies about persistence, and the probe must not believe it.
class LyingBackend final : public lkb::KeychainBackend {
  public:
    lkb::ErrorOr<lkb::ByteBuffer> read_master_key() override {
        return lkb::ErrorOr<lkb::ByteBuffer>::ok(lkb::ByteBuffer{0xde, 0xad, 0xbe, 0xef});
    }
    lkb::ErrorOr<void> write_master_key(lkb::ByteBuffer const&, lkb::Accessibility) override {
        return lkb::ErrorOr<void>::ok();
    }
    lkb::ErrorOr<void> delete_master_key() override { return lkb::ErrorOr<void>::ok(); }
    bool is_available() override { return true; }
};

// Delete that silently keeps the item — the probe must report delete as false.
class NoDeleteBackend final : public lkb::KeychainBackend {
  public:
    lkb::ErrorOr<lkb::ByteBuffer> read_master_key() override {
        if (!m_stored)
            return lkb::ErrorOr<lkb::ByteBuffer>::error({lkb::ErrorCode::NotFound, "absent"});
        return lkb::ErrorOr<lkb::ByteBuffer>::ok(*m_stored);
    }
    lkb::ErrorOr<void> write_master_key(lkb::ByteBuffer const& k, lkb::Accessibility) override {
        m_stored = k;
        return lkb::ErrorOr<void>::ok();
    }
    lkb::ErrorOr<void> delete_master_key() override { return lkb::ErrorOr<void>::ok(); }
    bool is_available() override { return true; }

  private:
    std::optional<lkb::ByteBuffer> m_stored;
};

// The complete audit vocabulary: an entry outside it is a defect by construction.
bool audit_is_only_tokens(std::vector<lkb::ProbeAuditEntry> const& entries) {
    static std::set<std::string> const operations{"probe", "save", "read", "update", "delete"};
    static std::set<std::string> const statuses{
        "ok", "unavailable", "mismatch", "still-present", "not-found", "error", "refused"};
    for (auto const& e : entries) {
        if (!operations.count(e.operation) || !statuses.count(e.status))
            return false;
    }
    return true;
}

} // namespace

int main() {
    // 1. Unavailable keychain degrades explicitly: every capability false, never optimistic.
    {
        lkb::FakeKeychainBackend fake;
        fake.set_available(false);
        lkb::SystemVaultSource source{fake, lkb::SystemVaultSource::DedicatedProbe::Yes};
        auto caps = source.probe();
        CHECK(!caps.keychain_available);
        CHECK(!caps.save_read_roundtrip);
        CHECK(!caps.update);
        CHECK(!caps.delete_item);
        CHECK(!source.audit().empty());
        CHECK(audit_is_only_tokens(source.audit()));
    }

    // 2. Healthy backend: every capability verified by a real roundtrip.
    {
        lkb::FakeKeychainBackend fake;
        lkb::SystemVaultSource source{fake, lkb::SystemVaultSource::DedicatedProbe::Yes};
        auto caps = source.probe();
        CHECK(caps.keychain_available);
        CHECK(caps.save_read_roundtrip);
        CHECK(caps.update);
        CHECK(caps.delete_item);
        CHECK(fake.write_count() == 2);    // save + update
        CHECK(fake.read_count() >= 3);     // after save, after update, after delete
        CHECK(!fake.stored().has_value()); // the probe leaves no key behind
        CHECK(audit_is_only_tokens(source.audit()));
    }

    // 3. A vault that lies about persistence fails the roundtrip check.
    {
        LyingBackend lying;
        lkb::SystemVaultSource source{lying, lkb::SystemVaultSource::DedicatedProbe::Yes};
        auto caps = source.probe();
        CHECK(caps.keychain_available);
        CHECK(!caps.save_read_roundtrip);
        CHECK(audit_is_only_tokens(source.audit()));
    }

    // 4. A delete that leaves the item behind is reported, not believed.
    {
        NoDeleteBackend sticky;
        lkb::SystemVaultSource source{sticky, lkb::SystemVaultSource::DedicatedProbe::Yes};
        auto caps = source.probe();
        CHECK(!caps.delete_item);
        CHECK(audit_is_only_tokens(source.audit()));
    }

    // 5. Audit never carries key or secret material: every entry is a fixed token pair,
    //    and the serialized audit contains no byte of the probe key.
    {
        lkb::FakeKeychainBackend fake;
        lkb::SystemVaultSource source{fake, lkb::SystemVaultSource::DedicatedProbe::Yes};
        auto key = lkb::SystemVaultSource::probe_key();
        CHECK(key.size() == 32);
        (void)source.probe();
        std::string serialized;
        for (auto const& e : source.audit())
            serialized += e.operation + "|" + e.status + ";";
        std::string key_as_text;
        for (auto byte : key)
            key_as_text += static_cast<char>(byte);
        CHECK(serialized.find(key_as_text) == std::string::npos);
    }

    // 6. Misuse guard: a probe pointed at a backend the caller did not declare
    //    dedicated refuses to write/delete through it — wiring probe() to the
    //    production master-key backend must never destroy the real key.
    {
        lkb::FakeKeychainBackend fake;
        lkb::SystemVaultSource source{fake}; // default: NOT dedicated
        auto caps = source.probe();
        CHECK(!caps.keychain_available);
        CHECK(!caps.save_read_roundtrip);
        CHECK(fake.write_count() == 0);
        CHECK(fake.delete_count() == 0);
        CHECK(source.audit().size() == 1);
        CHECK(source.audit()[0].operation == "probe");
        CHECK(source.audit()[0].status == "refused");
    }

    if (s_failures == 0) {
        std::printf("ALL SYSTEM-VAULT PROBE TESTS PASSED\n");
        return 0;
    }
    std::printf("%d SYSTEM-VAULT PROBE CHECK(S) FAILED\n", s_failures);
    return 1;
}
