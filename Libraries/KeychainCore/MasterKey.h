#pragma once

#include "KeychainBackend.h"

#include <functional>

namespace lkb {

using MasterKeyRng = std::function<ByteBuffer(size_t)>;

// Returns the stored master key, creating it (via rng) on first use.
// 16-byte requirement is enforced here, never in callers.
ErrorOr<ByteBuffer> master_key_or_create(KeychainBackend&, MasterKeyRng const&);

// OS CSPRNG implementation used by production callers.
ByteBuffer default_master_key_rng(size_t n);

} // namespace lkb
