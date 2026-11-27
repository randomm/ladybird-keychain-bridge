#pragma once

#include "CredentialRecord.h"

#include <sqlite3.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace lkb {

// The encrypted vault: origin columns plaintext for matching; (username, secret,
// extra_fields, form_meta) encrypted per record with AES-GCM,
// AAD = canonical origin string, key = HKDF-SHA-256(master_key, salt, info=origin).
// SQLite is reached only from VaultStore.cpp via prepared statements + bound
// parameters (no SQL string formatting).
class VaultStore {
  public:
    static ErrorOr<VaultStore> open(std::string db_path, ByteBuffer master_key);
    ~VaultStore();
    VaultStore(VaultStore&&) noexcept;
    VaultStore& operator=(VaultStore&&) noexcept;
    VaultStore(VaultStore const&) = delete;

    ErrorOr<std::vector<Match>> find(Origin const& origin,
                                     std::optional<std::string_view> username_hint);
    ErrorOr<void> put(CredentialRecord const& record);
    ErrorOr<void> remove_credential(std::int64_t id);
    ErrorOr<std::vector<CredentialRecord>> all(size_t& out_undecodable);
    ErrorOr<void> remove_origin(Origin const& origin);
    ErrorOr<void> mark_never(Origin const& origin);
    ErrorOr<bool> is_never(Origin const& origin);
    ErrorOr<void> unmark_never(Origin const& origin);

  private:
    VaultStore() = default;

    ErrorOr<ByteBuffer> encrypt_record(CredentialRecord const& record) const;
    ErrorOr<CredentialRecord> decrypt_record(Origin origin, ByteBuffer const& blob,
                                             std::int64_t created, std::int64_t last_used,
                                             std::int64_t updated) const;

    sqlite3* m_db{nullptr};
    ByteBuffer m_master_key;
};

} // namespace lkb
