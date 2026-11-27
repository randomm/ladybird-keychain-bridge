#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"

namespace lkb {

// HKDF-SHA-256 (RFC 5869) and HMAC-SHA-256 over OpenSSL EVP.
ErrorOr<ByteBuffer> hkdf_sha256(ByteBuffer const& ikm, ByteBuffer const& salt,
                                ByteBuffer const& info, size_t length);
ErrorOr<ByteBuffer> hmac_sha256(ByteBuffer const& key, ByteBuffer const& data);

} // namespace lkb
