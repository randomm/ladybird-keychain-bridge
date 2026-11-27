#include "AesGcm.h"
#include "Hkdf.h"
#include "testing/TestAssert.h"

#include <string>

using namespace lkb;

static ByteBuffer hex(std::string_view h)
{
    ByteBuffer out;
    auto val = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(val(h[i]) * 16 + val(h[i + 1])));
    return out;
}

static std::string bytes_to_hex(ByteBuffer const& b)
{
    static char const* d = "0123456789abcdef";
    std::string s;
    for (auto c : b) {
        s += d[c >> 4];
        s += d[c & 15];
    }
    return s;
}

static ByteBuffer rep(size_t n, std::uint8_t v) { return ByteBuffer(n, v); }

static ByteBuffer str(std::string_view s) { return ByteBuffer(s.begin(), s.end()); }

int main()
{
    ByteBuffer key = rep(32, 0x11);
    ByteBuffer aad { 'o', 'r', 'i', 'g' };
    ByteBuffer plain { 'h', 'u', 'n', 't' };

    // round trip
    auto enc = AesGcm::encrypt(key, plain, aad);
    EXPECT(!enc.is_error());
    if (!enc.is_error()) {
        EXPECT_EQ(enc.value().nonce.size(), static_cast<size_t>(12));
        EXPECT_EQ(enc.value().ciphertext.size(), plain.size() + 16); // tag appended
        auto dec = AesGcm::decrypt(key, enc.value().nonce, enc.value().ciphertext, aad);
        EXPECT(!dec.is_error());
        EXPECT(dec.value() == plain);
    }

    // empty plaintext round-trips
    {
        auto e = AesGcm::encrypt(key, ByteBuffer {}, aad);
        EXPECT(!e.is_error());
        auto d = AesGcm::decrypt(key, e.value().nonce, e.value().ciphertext, aad);
        EXPECT(!d.is_error() && d.value().empty());
    }

    if (!enc.is_error()) {
        // tampered ciphertext -> Authentication error
        auto bad = enc.value();
        bad.ciphertext[0] ^= 0xFF;
        auto d1 = AesGcm::decrypt(key, bad.nonce, bad.ciphertext, aad);
        EXPECT(d1.is_error());
        if (d1.is_error())
            EXPECT_EQ(static_cast<int>(d1.error().code), static_cast<int>(ErrorCode::Authentication));

        // wrong key -> Authentication error
        auto d2 = AesGcm::decrypt(rep(32, 0x22), enc.value().nonce, enc.value().ciphertext, aad);
        EXPECT(d2.is_error());

        // wrong AAD -> Authentication error
        auto d3 = AesGcm::decrypt(key, enc.value().nonce, enc.value().ciphertext, ByteBuffer { 'o', 'X', 'i', 'g' });
        EXPECT(d3.is_error());

        // nonce uniqueness across encryptions
        auto enc2 = AesGcm::encrypt(key, plain, aad);
        EXPECT(enc2.value().nonce != enc.value().nonce);
    }

    // wrong key size rejected
    EXPECT(AesGcm::encrypt(rep(15, 0x11), plain, aad).is_error());

    // HKDF-SHA-256 known answer (vector generated with the same OpenSSL 3.x we link).
    {
        auto okm = hkdf_sha256(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42);
        EXPECT(!okm.is_error());
        if (!okm.is_error()) {
            EXPECT_EQ(bytes_to_hex(okm.value()), std::string(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
        }
    }

    // HMAC-SHA-256 known answer (RFC 4231 case 2).
    {
        auto mac = hmac_sha256(str("Jefe"), str("what do ya want for nothing?"));
        EXPECT(!mac.is_error());
        if (!mac.is_error()) {
            EXPECT_EQ(bytes_to_hex(mac.value()), std::string(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        }
    }

    return ::lkb::failures();
}
