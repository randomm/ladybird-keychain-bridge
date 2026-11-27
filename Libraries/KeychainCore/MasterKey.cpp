#include "MasterKey.h"

#if defined(__APPLE__)
#    include <stdlib.h> // arc4random_buf
#else
#    include <sys/random.h>
#endif

namespace lkb {

constexpr size_t master_key_size = 16;

ByteBuffer default_master_key_rng(size_t n)
{
    ByteBuffer out(n);
#if defined(__APPLE__)
    arc4random_buf(out.data(), n);
#else
    ssize_t got = getrandom(out.data(), n, 0);
    while (got < 0 || static_cast<size_t>(got) < n)
        got = getrandom(out.data() + (got < 0 ? 0 : got), n - (got < 0 ? 0 : static_cast<size_t>(got)), 0);
#endif
    return out;
}

ErrorOr<ByteBuffer> master_key_or_create(KeychainBackend& backend, MasterKeyRng const& rng)
{
    if (!backend.is_available())
        return ErrorOr<ByteBuffer>::error({ ErrorCode::InteractionNotAllowed, "keychain unavailable" });

    auto read = backend.read_master_key();
    if (!read.is_error()) {
        if (read.value().size() != master_key_size)
            return ErrorOr<ByteBuffer>::error({ ErrorCode::UnexpectedData, "master key wrong size" });
        return read;
    }
    if (read.error().code != ErrorCode::NotFound)
        return ErrorOr<ByteBuffer>::error(read.error());

    auto key = rng(master_key_size);
    if (key.size() != master_key_size)
        return ErrorOr<ByteBuffer>::error({ ErrorCode::UnexpectedData, "rng returned wrong size" });

    auto write = backend.write_master_key(key, Accessibility::WhenUnlocked);
    if (write.is_error())
        return ErrorOr<ByteBuffer>::error(write.error());

    return ErrorOr<ByteBuffer>::ok(std::move(key));
}

}
