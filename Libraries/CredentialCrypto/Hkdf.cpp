#include "Hkdf.h"

#include <openssl/hmac.h>

#include <algorithm>

namespace lkb {

namespace {

constexpr size_t sha256_len = 32;

}

ErrorOr<ByteBuffer> hmac_sha256(ByteBuffer const& key, ByteBuffer const& data) {
    ByteBuffer out(sha256_len);
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              out.data(), &len) ||
        len != sha256_len)
        return ErrorOr<ByteBuffer>::error({ErrorCode::Authentication, "hmac"});
    return ErrorOr<ByteBuffer>::ok(std::move(out));
}

static ErrorOr<ByteBuffer> hmac_bytes(ByteBuffer const& key, ByteBuffer const& data) {
    return hmac_sha256(key, data);
}

ErrorOr<ByteBuffer> hkdf_sha256(ByteBuffer const& ikm, ByteBuffer const& salt,
                                ByteBuffer const& info, size_t length) {
    if (length > 255 * sha256_len)
        return ErrorOr<ByteBuffer>::error({ErrorCode::Invalid, "hkdf length"});

    // extract
    ByteBuffer zero_salt(sha256_len, 0);
    auto prk = hmac_bytes(salt.empty() ? zero_salt : salt, ikm);
    if (prk.is_error())
        return prk;

    // expand
    ByteBuffer okm;
    ByteBuffer prev;
    unsigned char counter = 1;
    while (okm.size() < length) {
        ByteBuffer input = prev;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        auto t = hmac_bytes(prk.value(), input);
        if (t.is_error())
            return t;
        prev = t.value();
        size_t take = std::min(sha256_len, length - okm.size());
        okm.insert(okm.end(), prev.begin(), prev.begin() + static_cast<long>(take));
        ++counter;
    }
    return ErrorOr<ByteBuffer>::ok(std::move(okm));
}

} // namespace lkb
