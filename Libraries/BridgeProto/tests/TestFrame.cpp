#include "Frame.h"
#include "Hkdf.h"
#include "Json.h"
#include "testing/TestAssert.h"

#include <cstring>
#include <string>

using namespace lkb;

static ByteBuffer key_mac() {
    ByteBuffer k(32, 0xA5);
    return k;
}

int main() {
    // canonical JSON: keys sorted, deterministic
    {
        auto j = Json::parse(R"({"b":1,"a":{"d":[true,null,"x"]},"c":-3})");
        EXPECT(!j.is_error());
        if (!j.is_error())
            EXPECT_EQ(j.value().canonical(),
                      std::string(R"({"a":{"d":[true,null,"x"]},"b":1,"c":-3})"));
        // idempotent: parse(canonical) canonicalizes to same bytes
        auto again = Json::parse(j.value().canonical());
        EXPECT(!again.is_error());
        EXPECT_EQ(again.value().canonical(), j.value().canonical());
    }

    ProtectedChannel req_channel(key_mac(), Direction::Request);
    ProtectedChannel resp_channel(key_mac(), Direction::Response);

    // seal -> unseal roundtrip (lookup request)
    std::uint64_t next_seq = 0;
    {
        auto wire = req_channel.seal(R"({"cmd":"lookup","origin":"https://x.example"})", 0);
        EXPECT(!wire.is_error());
        if (!wire.is_error()) {
            auto out = req_channel.unseal(wire.value(), next_seq, max_request_bytes);
            EXPECT(!out.is_error());
            if (!out.is_error()) {
                EXPECT_EQ(out.value().payload.get_string("cmd"), std::string("lookup"));
                EXPECT_EQ(out.value().seq, static_cast<std::uint64_t>(0));
                EXPECT_EQ(next_seq, static_cast<std::uint64_t>(1));
            }
        }

        // replayed frame (same seq) rejected
        auto again = req_channel.unseal(wire.value(), next_seq, max_request_bytes);
        EXPECT(again.is_error());

        // seq jump 200 rejected
        auto jump = req_channel.seal(R"({"cmd":"ping"})", 201);
        EXPECT(!jump.is_error());
        auto jumped = req_channel.unseal(jump.value(), next_seq, max_request_bytes);
        EXPECT(jumped.is_error());
    }

    // truncated buffer -> IncompleteFrame
    {
        ByteBuffer tiny{0x07, 0x00};
        std::uint64_t ns = 0;
        auto out = resp_channel.unseal(tiny, ns, max_response_bytes);
        EXPECT(out.is_error());
        if (out.is_error())
            EXPECT_EQ(static_cast<int>(out.error().code),
                      static_cast<int>(ErrorCode::IncompleteFrame));
    }

    // over-cap request -> TooLarge
    {
        ByteBuffer buf(4, 0);
        std::uint32_t huge_len = static_cast<std::uint32_t>(max_request_bytes + 1);
        buf[0] = static_cast<std::uint8_t>(huge_len);
        buf[1] = static_cast<std::uint8_t>(huge_len >> 8);
        buf[2] = static_cast<std::uint8_t>(huge_len >> 16);
        buf[3] = static_cast<std::uint8_t>(huge_len >> 24);
        std::uint64_t ns = 0;
        auto out = req_channel.unseal(buf, ns, max_request_bytes);
        EXPECT(out.is_error());
        if (out.is_error())
            EXPECT_EQ(static_cast<int>(out.error().code), static_cast<int>(ErrorCode::TooLarge));
    }

    // Attacker-crafted wire: payload in NON-canonical order with the MAC bound
    // to that non-canonical spelling. Verification canonicalizes first, so the
    // MAC must fail.
    {
        std::string non_canonical = R"({"b":1,"a":2})";
        ByteBuffer mac_in;
        std::uint64_t seq = 1;
        for (int i = 7; i >= 0; --i)
            mac_in.push_back(static_cast<std::uint8_t>(seq >> (8 * i)));
        mac_in.push_back(0); // Direction::Request
        mac_in.insert(mac_in.end(), non_canonical.begin(), non_canonical.end());
        auto mac = hmac_sha256(key_mac(), mac_in);
        EXPECT(!mac.is_error());
        static char const* hexd = "0123456789abcdef";
        std::string mac_hex;
        for (auto b : mac.value()) {
            mac_hex += hexd[b >> 4];
            mac_hex += hexd[b & 15];
        }
        std::string body =
            "{\"mac\":\"" + mac_hex + "\",\"payload\":" + non_canonical + ",\"seq\":1}";
        ByteBuffer wire(4 + body.size());
        auto len = static_cast<std::uint32_t>(body.size());
        wire[0] = static_cast<std::uint8_t>(len);
        wire[1] = static_cast<std::uint8_t>(len >> 8);
        wire[2] = static_cast<std::uint8_t>(len >> 16);
        wire[3] = static_cast<std::uint8_t>(len >> 24);
        memcpy(wire.data() + 4, body.data(), body.size());
        std::uint64_t ns = 1;
        auto out = req_channel.unseal(wire, ns, max_request_bytes);
        EXPECT(out.is_error()); // canonicalization defeats order-spoofing
    }

    // wrong key -> mac failure
    {
        ProtectedChannel other(ByteBuffer(32, 0x5A), Direction::Request);
        auto wire = req_channel.seal(R"({"cmd":"x"})", 2);
        EXPECT(!wire.is_error());
        std::uint64_t ns = 2;
        auto out = other.unseal(wire.value(), ns, max_request_bytes);
        EXPECT(out.is_error());
        if (out.is_error())
            EXPECT_EQ(static_cast<int>(out.error().code),
                      static_cast<int>(ErrorCode::Authentication));
    }

    return ::lkb::failures();
}
