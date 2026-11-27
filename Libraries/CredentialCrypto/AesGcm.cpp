#include "AesGcm.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace lkb {

namespace {

Error crypto_error(std::string_view what) {
    return Error{ErrorCode::Authentication, std::string(what)};
}

} // namespace

ErrorOr<EncryptedBlob> AesGcm::encrypt(ByteBuffer const& key, ByteBuffer const& plaintext,
                                       ByteBuffer const& aad) {
    if (key.size() != 16 && key.size() != 32)
        return ErrorOr<EncryptedBlob>::error(crypto_error("aes key size"));

    EncryptedBlob blob;
    blob.nonce.resize(12);
    if (RAND_bytes(blob.nonce.data(), 12) != 1)
        return ErrorOr<EncryptedBlob>::error(crypto_error("rng failure"));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ErrorOr<EncryptedBlob>::error(crypto_error("ctx"));

    auto* cipher = key.size() == 32 ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    ByteBuffer out(plaintext.size() + 1);
    int aad_out = 0; // GCM AAD update reports aad length here; never mix with ct outl.
    int outl = 0;
    bool ok = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), blob.nonce.data()) == 1 &&
              (aad.empty() || EVP_EncryptUpdate(ctx, nullptr, &aad_out, aad.data(),
                                                static_cast<int>(aad.size())) == 1) &&
              (plaintext.empty() || EVP_EncryptUpdate(ctx, out.data(), &outl, plaintext.data(),
                                                      static_cast<int>(plaintext.size())) == 1);
    if (ok) {
        int finall = 0;
        ok = EVP_EncryptFinal_ex(ctx, out.data() + outl, &finall) == 1;
        out.resize(static_cast<size_t>(outl + finall));
    }
    if (ok) {
        ByteBuffer tag(16);
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1;
        out.insert(out.end(), tag.begin(), tag.end());
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return ErrorOr<EncryptedBlob>::error(crypto_error("encrypt"));
    blob.ciphertext = std::move(out);
    return ErrorOr<EncryptedBlob>::ok(std::move(blob));
}

ErrorOr<ByteBuffer> AesGcm::decrypt(ByteBuffer const& key, ByteBuffer const& nonce,
                                    ByteBuffer const& ciphertext_with_tag, ByteBuffer const& aad) {
    if ((key.size() != 16 && key.size() != 32) || nonce.size() != 12 ||
        ciphertext_with_tag.size() < 16)
        return ErrorOr<ByteBuffer>::error(crypto_error("input sizes"));

    auto* cipher = key.size() == 32 ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    size_t ct_len = ciphertext_with_tag.size() - 16;
    ByteBuffer out(ct_len + 1);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return ErrorOr<ByteBuffer>::error(crypto_error("ctx"));

    int aad_out = 0; // GCM AAD update reports aad length here; never mix with ct outl.
    int outl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              (aad.empty() || EVP_DecryptUpdate(ctx, nullptr, &aad_out, aad.data(),
                                                static_cast<int>(aad.size())) == 1) &&
              (ct_len == 0 || EVP_DecryptUpdate(ctx, out.data(), &outl, ciphertext_with_tag.data(),
                                                static_cast<int>(ct_len)) == 1);
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                 const_cast<std::uint8_t*>(ciphertext_with_tag.data() + ct_len)) ==
             1;
        int finall = 0;
        if (ok)
            ok = EVP_DecryptFinal_ex(ctx, out.data() + outl, &finall) == 1;
        out.resize(static_cast<size_t>(outl + finall));
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return ErrorOr<ByteBuffer>::error(crypto_error("authentication failed"));
    return ErrorOr<ByteBuffer>::ok(std::move(out));
}

} // namespace lkb
