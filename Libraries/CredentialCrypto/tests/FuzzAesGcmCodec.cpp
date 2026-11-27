// Standalone fuzz target (plan Task 6; owner/CI-fuzz runs with
// -fsanitize=fuzzer; excluded from the default build). Arbitrary key/nonce/
// ciphertext combinations must surface as typed errors only — never a crash,
// and never plaintext through a failed authentication.
#include "AesGcm.h"

#include <cstdint>

// Prototype ahead of the definition: clang -Wmissing-prototypes (on in the
// embedding browser build's global flag set) needs a visible declaration.
extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size);

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    if (size < 16 + 12 + 1 + 1)
        return 0;
    std::uint8_t const* p = data;
    lkb::ByteBuffer key(p, p + 16);
    p += 16;
    lkb::ByteBuffer nonce(p, p + 12);
    p += 12;
    std::size_t aad_len = *p++;
    if (size < static_cast<std::size_t>(p - data) + aad_len)
        return 0;
    lkb::ByteBuffer aad(p, p + aad_len);
    p += aad_len;
    lkb::ByteBuffer rest(p, data + size);

    // Attacker-supplied material through the open path: typed failure only.
    (void)lkb::AesGcm::decrypt(key, nonce, rest, aad);

    // Round-trip discipline: seal with the CSPRNG nonce inside encrypt, then
    // open a mutated ciphertext — acceptance is a crash-worthy finding.
    auto sealed = lkb::AesGcm::encrypt(key, rest, aad);
    if (!sealed.is_error()) {
        auto tampered = sealed.value().ciphertext;
        if (!tampered.empty()) {
            tampered[0] ^= 0xFF;
            auto opened = lkb::AesGcm::decrypt(key, sealed.value().nonce, tampered, aad);
            if (!opened.is_error() && !rest.empty())
                __builtin_trap(); // forged ciphertext accepted
        }
    }
    return 0;
}
