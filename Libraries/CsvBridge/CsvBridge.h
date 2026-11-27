#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"
#include "VaultStore.h"

#include <cstddef>

namespace lkb {

// Apple Passwords-app export compatible CSV bridge. Community-known column set:
// Title,Username,Password,URL,Notes,Created,Last Modified,Last Used,Verified,OTP Auth Token
// Username/Password/URL map onto the record; every other column is preserved
// verbatim in extra_fields and re-emitted on export.
constexpr size_t csv_max_field_bytes = 1u << 20;
constexpr size_t csv_max_rows = 10'000;

// Rows whose URL is unparsable or violates the scheme policy (plain http
// outside the localhost-explicit-port opt-in) are skipped and counted in
// skipped_out — they never reach the vault. The admin surfaces
// (CapabilityToken-gated) are CredentialService::import_csv/export_csv.
ErrorOr<size_t> import_csv(ByteBuffer const& csv, VaultStore& vault, size_t* skipped_out = nullptr);
ErrorOr<ByteBuffer> export_csv(VaultStore& vault);

} // namespace lkb
