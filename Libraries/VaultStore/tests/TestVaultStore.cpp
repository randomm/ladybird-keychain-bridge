#include "VaultStore.h"
#include "testing/TestAssert.h"

#include <sqlite3.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lkb;

static ByteBuffer key() {
    return ByteBuffer(16, 0x2A);
}

static Origin origin_of(std::string_view s) {
    auto o = Origin::parse(s);
    EXPECT(!o.is_error());
    return std::move(o.value());
}

static CredentialRecord record(std::string_view url, std::string_view user,
                               std::string_view secret) {
    CredentialRecord r;
    r.origin = origin_of(url);
    r.username = std::string(user);
    r.secret = ByteBuffer(secret.begin(), secret.end());
    r.created = 100;
    r.last_used = 101;
    r.updated = 102;
    return r;
}

static char const* db_path() {
    static char path[] = "/tmp/lkb-vault-XXXXXX";
    static bool made = false;
    if (!made) {
        int fd = mkstemp(path);
        if (fd < 0) {
            std::printf("mkstemp failed\n");
            std::exit(2);
        }
        close(fd);
        made = true;
    }
    return path;
}

int main() {
    std::remove(db_path());

    // put -> find exact origin returns plaintext
    {
        auto opened = VaultStore::open(db_path(), key());
        EXPECT(!opened.is_error());
        auto& vault = opened.value();

        EXPECT(!vault.put(record("https://example.com", "alice", "pw1")).is_error());
        auto found = vault.find(origin_of("https://example.com"), std::nullopt);
        EXPECT(!found.is_error());
        EXPECT_EQ(found.value().size(), static_cast<size_t>(1));
        if (found.value().size() == 1) {
            EXPECT(found.value()[0].record.username == std::string("alice"));
            std::string const want = "pw1";
            EXPECT(found.value()[0].record.secret == ByteBuffer(want.begin(), want.end()));
            EXPECT_EQ(found.value()[0].record.updated, static_cast<std::int64_t>(102));
        }

        // different host -> empty
        auto none_host = vault.find(origin_of("https://other.com"), std::nullopt);
        EXPECT(none_host.value().empty());

        // exact-port matching: 8080 vs 8081 do not collide
        EXPECT(!vault.put(record("http://localhost:8080", "bob", "pw2")).is_error());
        auto wrong_port = vault.find(origin_of("http://localhost:8081"), std::nullopt);
        EXPECT(wrong_port.value().empty());
        auto right_port = vault.find(origin_of("http://localhost:8080"), std::nullopt);
        EXPECT_EQ(right_port.value().size(), static_cast<size_t>(1));

        // username hint narrows results
        auto hinted = vault.find(origin_of("https://example.com"), std::string_view("nothere"));
        EXPECT(hinted.value().empty());

        // all() clean
        size_t undecodable = 99;
        auto all = vault.all(undecodable);
        EXPECT(!all.is_error());
        EXPECT_EQ(all.value().size(), static_cast<size_t>(2));
        EXPECT_EQ(undecodable, static_cast<size_t>(0));

        // upsert: same origin+username replaces, keeps created
        auto replacement = record("HTTPS://EXAMPLE.COM", "alice", "pw1b");
        EXPECT(!vault.put(replacement).is_error());
        auto again = vault.find(origin_of("https://example.com"), std::string_view("alice"));
        EXPECT_EQ(again.value().size(), static_cast<size_t>(1));
        if (again.value().size() == 1) {
            std::string const want_b = "pw1b";
            EXPECT(again.value()[0].record.secret == ByteBuffer(want_b.begin(), want_b.end()));
            EXPECT_EQ(again.value()[0].record.created, static_cast<std::int64_t>(100));
        }
    }

    // Review Focus 3: one corrupted row -> undecodable==1, others intact.
    {
        sqlite3* raw = nullptr;
        if (sqlite3_open(db_path(), &raw) != SQLITE_OK) {
            std::printf("corrupt open failed\n");
            return 1;
        }
        sqlite3_exec(raw, "UPDATE credentials SET blob = X'00112233' WHERE id = 1;", nullptr,
                     nullptr, nullptr);
        sqlite3_close(raw);

        auto opened = VaultStore::open(db_path(), key());
        auto& vault = opened.value();
        size_t undecodable = 99;
        auto all = vault.all(undecodable);
        EXPECT(!all.is_error());
        EXPECT_EQ(undecodable, static_cast<size_t>(1)); // id=1 (example.com) was corrupted
        EXPECT_EQ(all.value().size(), static_cast<size_t>(1));
        if (all.value().size() == 1) {
            std::string const want2 = "pw2";
            EXPECT(all.value()[0].secret ==
                   ByteBuffer(want2.begin(), want2.end())); // survivor plaintext intact
            EXPECT(all.value()[0].origin.host == std::string("localhost"));
        }

        // remove_origin wipes all rows for that origin (even the corrupted one)
        EXPECT(!vault.remove_origin(origin_of("https://example.com")).is_error());
        size_t und2 = 99;
        auto rest = vault.all(und2);
        EXPECT_EQ(rest.value().size(), static_cast<size_t>(1)); // localhost row survives
        EXPECT_EQ(und2, static_cast<size_t>(0));

        // Review Focus 5: casefolded origin columns roundtrip (put via HTTPS://EXAMPLE.COM)
        EXPECT(!vault.put(record("HTTPS://EXAMPLE.COM", "alice", "pw3")).is_error());
        auto casefolded = vault.find(origin_of("https://example.com"), std::nullopt);
        EXPECT_EQ(casefolded.value().size(), static_cast<size_t>(1));
    }

    std::remove(db_path());
    return ::lkb::failures();
}
