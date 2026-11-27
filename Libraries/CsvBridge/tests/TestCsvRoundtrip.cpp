#include "CsvBridge.h"
#include "VaultStore.h"
#include "testing/TestAssert.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#ifndef FIXTURE_DIR
#define FIXTURE_DIR "."
#endif

using namespace lkb;

static char path[] = "/tmp/lkb-csv-XXXXXX";

static ByteBuffer read_file(std::string const& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    auto s = ss.str();
    return ByteBuffer(s.begin(), s.end());
}

static ByteBuffer key() {
    return ByteBuffer(16, 0x9E);
}

static void wipe_db() {
    std::remove(path);
    std::remove((std::string(path) + "-wal").c_str());
    std::remove((std::string(path) + "-shm").c_str());
}

int main() {
    wipe_db();
    auto csv = read_file(std::string(FIXTURE_DIR) + "/passwords_export_columns.csv");
    EXPECT(!csv.empty());

    auto opened = VaultStore::open(path, key());
    EXPECT(!opened.is_error());
    auto& vault = opened.value();

    auto imported = import_csv(csv, vault);
    EXPECT(!imported.is_error());
    EXPECT_EQ(imported.value(), static_cast<size_t>(2));

    size_t und = 0;
    auto recs = vault.all(und);
    EXPECT_EQ(und, static_cast<size_t>(0));
    EXPECT_EQ(recs.value().size(), static_cast<size_t>(2));

    // OTP Auth Token survived as a verbatim extra
    bool otp_survived = false;
    bool created_kept = false;
    for (auto& r : recs.value()) {
        auto it = r.extra_fields.find("OTP Auth Token");
        if (it != r.extra_fields.end() && it->second == "otpsharedsecret")
            otp_survived = true;
        if (r.created == 1700000000)
            created_kept = true;
    }
    EXPECT(otp_survived);
    EXPECT(created_kept);

    // export -> re-import -> re-export: byte-equal
    auto e1 = export_csv(vault);
    EXPECT(!e1.is_error());
    std::string s1(e1.value().begin(), e1.value().end());
    EXPECT(s1.find("OTP Auth Token") != std::string::npos);

    wipe_db();
    auto second = VaultStore::open(path, key());
    auto& vault2 = second.value();
    auto re = import_csv(e1.value(), vault2);
    EXPECT(!re.is_error());
    EXPECT_EQ(re.value(), static_cast<size_t>(2));
    auto e2 = export_csv(vault2);
    EXPECT(!e2.is_error());
    std::string s2(e2.value().begin(), e2.value().end());
    EXPECT(s1 == s2); // byte-equal column header and values

    // formula-injection prefixes escaped on export
    {
        CredentialRecord r;
        r.origin = Origin::parse("https://eq.example").value();
        r.username = "=cmd|'/C calc'!A0";
        std::string sec = "p";
        r.secret = ByteBuffer(sec.begin(), sec.end());
        EXPECT(!vault2.put(r).is_error());
        auto e3 = export_csv(vault2);
        std::string s3(e3.value().begin(), e3.value().end());
        EXPECT(s3.find("'=cmd") != std::string::npos);
        EXPECT(s3.find("\n\"=cmd") == std::string::npos);
    }

    // oversized field -> TooLarge
    {
        std::string huge = "Title,Username,Password,URL\nx,alice,";
        huge.append((1 << 20) + 1, 'a'); // one past the 1 MiB cap
        huge += "\n";
        ByteBuffer big(huge.begin(), huge.end());
        wipe_db();
        auto v = VaultStore::open(path, key());
        auto res = import_csv(big, v.value());
        EXPECT(res.is_error());
        if (res.is_error())
            EXPECT_EQ(static_cast<int>(res.error().code), static_cast<int>(ErrorCode::TooLarge));
    }

    // unbalanced quote -> MalformedCsv
    {
        std::string bad = "Title,Username,Password,URL\nx,alice,\"unbalanced\n";
        ByteBuffer b(bad.begin(), bad.end());
        wipe_db();
        auto v = VaultStore::open(path, key());
        auto res = import_csv(b, v.value());
        EXPECT(res.is_error());
        if (res.is_error())
            EXPECT_EQ(static_cast<int>(res.error().code),
                      static_cast<int>(ErrorCode::MalformedCsv));
    }

    // row cap: 10000 rows ok-ish shape, 10001 data rows -> TooLarge
    {
        std::string many = "Title,Username,Password,URL\n";
        for (int i = 0; i < 10001; ++i)
            many += "t,u" + std::to_string(i) + ",pw,https://cap.example/\n";
        ByteBuffer mb(many.begin(), many.end());
        wipe_db();
        auto v = VaultStore::open(path, key());
        auto res = import_csv(mb, v.value());
        EXPECT(res.is_error());
        if (res.is_error())
            EXPECT_EQ(static_cast<int>(res.error().code), static_cast<int>(ErrorCode::TooLarge));
    }

    wipe_db();
    return ::lkb::failures();
}
