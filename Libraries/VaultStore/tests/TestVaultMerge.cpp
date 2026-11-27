#include "VaultStore.h"
#include "testing/TestAssert.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lkb;

static char path[] = "/tmp/lkb-merge-XXXXXX";

static Origin origin_of(std::string_view s) {
    auto o = Origin::parse(s);
    EXPECT(!o.is_error());
    return std::move(o.value());
}

static CredentialRecord record(std::string_view url, std::string_view user, std::string_view secret,
                               std::int64_t updated) {
    CredentialRecord r;
    r.origin = origin_of(url);
    r.username = std::string(user);
    r.secret = ByteBuffer(secret.begin(), secret.end());
    r.created = 100;
    r.last_used = 101;
    r.updated = updated;
    return r;
}

int main() {
    std::remove(path);
    auto opened = VaultStore::open(path, ByteBuffer(16, 0x5C));
    EXPECT(!opened.is_error());
    auto& vault = opened.value();

    // upsert: same origin+username -> one row, new secret, updated bumped, created kept
    EXPECT(!vault.put(record("https://site.example", "carol", "old", 150)).is_error());
    EXPECT(!vault.put(record("HTTPS://SITE.EXAMPLE", "carol", "new", 250)).is_error());

    auto hits = vault.find(origin_of("https://site.example"), std::nullopt);
    EXPECT_EQ(hits.value().size(), static_cast<size_t>(1));
    if (hits.value().size() == 1) {
        std::string const want = "new";
        EXPECT(hits.value()[0].record.secret == ByteBuffer(want.begin(), want.end()));
        EXPECT_EQ(hits.value()[0].record.created, static_cast<std::int64_t>(100));
        EXPECT_EQ(hits.value()[0].record.updated, static_cast<std::int64_t>(250));
    }

    // different username on same origin -> two rows
    EXPECT(!vault.put(record("https://site.example", "dave", "d1", 160)).is_error());
    auto both = vault.find(origin_of("https://site.example"), std::nullopt);
    EXPECT_EQ(both.value().size(), static_cast<size_t>(2));

    // same username on a DIFFERENT port is not the same credential
    EXPECT(!vault.put(record("https://site.example:8443", "carol", "other", 170)).is_error());
    auto ported = vault.find(origin_of("https://site.example:8443"), std::nullopt);
    EXPECT_EQ(ported.value().size(), static_cast<size_t>(1));
    if (ported.value().size() == 1) {
        std::string const want2 = "other";
        EXPECT(ported.value()[0].record.secret == ByteBuffer(want2.begin(), want2.end()));
    }

    // never-save markers roundtrip, casefolded
    EXPECT(!vault.mark_never(origin_of("https://Never.Example/ignored/path")).is_error());
    auto marked = vault.is_never(origin_of("https://never.example"));
    EXPECT(!marked.is_error());
    EXPECT_EQ(marked.value(), true);
    auto not_marked = vault.is_never(origin_of("https://other.example"));
    EXPECT_EQ(not_marked.value(), false);

    std::remove(path);
    return ::lkb::failures();
}
