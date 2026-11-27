#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"

namespace lkb {

struct EncryptedBlob {
    ByteBuffer nonce;      // 12 bytes, CSPRNG
    ByteBuffer ciphertext; // plaintext ciphertext || 16-byte tag
};

// AES-256-GCM via OpenSSL EVP. Only this file may call EVP_* for bulk crypto.
class AesGcm {
public:
    static ErrorOr<EncryptedBlob> encrypt(ByteBuffer const& key, ByteBuffer const& plaintext,
        ByteBuffer const& aad);
    static ErrorOr<ByteBuffer> decrypt(ByteBuffer const& key, ByteBuffer const& nonce,
        ByteBuffer const& ciphertext_with_tag, ByteBuffer const& aad);
};

}
