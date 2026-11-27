#pragma once

#include "KeychainBackend.h"

#include <optional>
#include <string>

namespace lkb {

// APPLE-only SecItem adapter. The ONLY class in the repo allowed to call
// Security.framework. Keychain item: kSecClassGenericPassword with the given
// service/account; kSecAttrAccessibleWhenUnlocked is set for correctness but is
// ignored on the file-based login keychain (TN3137) — no at-rest claim.
class SecItemKeychainBackend final : public KeychainBackend {
public:
    // keychain_path: dedicated file-based keychain (owner-run matrices); nullopt = login keychain.
    static ErrorOr<SecItemKeychainBackend> create(std::string service, std::string account,
        std::optional<std::string> keychain_path = std::nullopt);

    ~SecItemKeychainBackend() override;
    SecItemKeychainBackend(SecItemKeychainBackend&&) noexcept;
    SecItemKeychainBackend& operator=(SecItemKeychainBackend&&) noexcept;

    ErrorOr<ByteBuffer> read_master_key() override;
    ErrorOr<void> write_master_key(ByteBuffer const&, Accessibility) override;
    bool is_available() override;

private:
    SecItemKeychainBackend() = default;

    std::string m_service;
    std::string m_account;
    void* m_keychain { nullptr }; // retained SecKeychainRef, or null => login keychain
};

}
