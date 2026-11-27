#include "SystemVaultSource.h"

#include <cstdlib>
#include <random>
#if defined(__APPLE__)
#include <stdlib.h> // arc4random_buf
#endif

namespace lkb {

void SystemVaultSource::audit(std::string operation, std::string status) {
    m_audit.push_back({move(operation), move(status)});
}

ByteBuffer SystemVaultSource::probe_key() {
    ByteBuffer key(32, 0);
#if defined(__APPLE__)
    arc4random_buf(key.data(), key.size());
#else
    std::random_device device;
    for (auto& byte : key)
        byte = static_cast<std::uint8_t>(device() & 0xff);
#endif
    return key;
}

VaultCapabilities SystemVaultSource::probe() {
    VaultCapabilities caps;

    if (!m_backend.is_available()) {
        audit("probe", "unavailable");
        return caps; // explicit degradation: nothing is assumed to work
    }
    caps.keychain_available = true;

    auto const key = probe_key();
    auto const other_key = probe_key();

    auto save = m_backend.write_master_key(key, Accessibility::WhenUnlocked);
    if (save.is_error()) {
        audit("save", "error");
        return caps;
    }
    audit("save", "ok");

    auto read = m_backend.read_master_key();
    if (read.is_error()) {
        audit("read", "not-found");
        return caps;
    }
    if (read.value() != key) {
        audit("read", "mismatch");
        return caps;
    }
    audit("read", "ok");
    caps.save_read_roundtrip = true;

    auto update = m_backend.write_master_key(other_key, Accessibility::WhenUnlocked);
    if (update.is_error()) {
        audit("update", "error");
    } else {
        audit("update", "ok");
        auto reread = m_backend.read_master_key();
        if (reread.is_error()) {
            audit("read", "not-found");
        } else if (reread.value() != other_key) {
            audit("read", "mismatch");
        } else {
            audit("read", "ok");
            caps.update = true;
        }
    }

    auto remove = m_backend.delete_master_key();
    if (remove.is_error()) {
        audit("delete", "error");
    } else {
        audit("delete", "ok");
        auto gone = m_backend.read_master_key();
        bool absent = gone.is_error() && gone.error().code == ErrorCode::NotFound;
        audit("read", absent ? "not-found" : "still-present");
        caps.delete_item = absent;
    }

    (void)m_backend.delete_master_key(); // leave no probe key behind, whatever happened above
    return caps;
}

} // namespace lkb
