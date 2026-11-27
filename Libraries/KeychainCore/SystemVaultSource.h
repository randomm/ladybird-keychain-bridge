#pragma once

#include "KeychainBackend.h"

#include <string>
#include <vector>

namespace lkb {

// One probe step as recorded for the capability matrix. The entry carries the
// operation name and a status token ONLY — never key, password or error text.
struct ProbeAuditEntry {
    std::string operation; // probe | save | read | update | delete
    std::string status;    // ok | unavailable | mismatch | still-present | not-found | error
};

struct VaultCapabilities {
    bool keychain_available{false};
    bool save_read_roundtrip{false};
    bool update{false};
    bool delete_item{false};
};

// M10: verifies the OS credential store end to end (save → read → update → read →
// delete → absent) and degrades EXPLICITLY: a capability is true only when its own
// roundtrip verified, and an unavailable keychain reports every capability false.
// The probe runs against a dedicated service/account with disposable key bytes;
// user items are never addressed.
class SystemVaultSource {
  public:
    // The probe WRITES AND DELETES through the backend. Wiring it to the same
    // backend that holds the real master key would overwrite and delete it, so
    // probe() only runs when the caller explicitly declares the backend a
    // dedicated probe store (its own service/account/keychain file).
    enum class DedicatedProbe { No, Yes };

    explicit SystemVaultSource(KeychainBackend& backend,
                               DedicatedProbe dedicated = DedicatedProbe::No)
        : m_backend(backend), m_dedicated(dedicated == DedicatedProbe::Yes) {}

    VaultCapabilities probe();

    std::vector<ProbeAuditEntry> const& audit() const { return m_audit; }

    // Fresh 32 bytes from the platform CSPRNG; never derived from user data.
    static ByteBuffer probe_key();

  private:
    void audit(std::string operation, std::string status);

    KeychainBackend& m_backend;
    bool m_dedicated{false};
    std::vector<ProbeAuditEntry> m_audit;
};

} // namespace lkb
