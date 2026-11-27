// Owner-run capability probe (M10). Runs the SystemVaultSource roundtrip against a
// DEDICATED file-based keychain — it refuses the login keychain and refuses to run
// without LKB_OWNER_RUN=1. Never touches user items.
#include "SecItemKeychainBackend.h"
#include "SystemVaultSource.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

int main(int argc, char** argv) {
    if (!std::getenv("LKB_OWNER_RUN")) {
        std::printf("PROBE REFUSED: owner-run only (set LKB_OWNER_RUN=1 and use "
                    "scripts/probe_system_vault.sh)\n");
        return 2;
    }

    std::string keychain_path;
    std::string service = "Ladybird Credentials Probe";
    std::string account = "lkb-probe";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--keychain"))
            keychain_path = argv[i + 1];
        else if (!std::strcmp(argv[i], "--service"))
            service = argv[i + 1];
        else if (!std::strcmp(argv[i], "--account"))
            account = argv[i + 1];
    }
    if (keychain_path.empty()) {
        std::printf("PROBE FAILED: --keychain <dedicated path> required\n");
        return 2;
    }
    if (keychain_path.find("login.keychain") != std::string::npos) {
        std::printf("PROBE FAILED: the probe never addresses the login keychain\n");
        return 2;
    }

    auto created = lkb::SecItemKeychainBackend::create(service, account, keychain_path);
    if (created.is_error()) {
        std::printf("PROBE FAILED: create: %s\n", created.error().message.c_str());
        return 1;
    }
    auto backend = std::move(created.value());

    lkb::SystemVaultSource source{backend};
    auto caps = source.probe();

    std::printf("capabilities:\n");
    std::printf("  keychain_available:  %s\n", caps.keychain_available ? "yes" : "NO");
    std::printf("  save_read_roundtrip: %s\n", caps.save_read_roundtrip ? "yes" : "NO");
    std::printf("  update:              %s\n", caps.update ? "yes" : "NO");
    std::printf("  delete:              %s\n", caps.delete_item ? "yes" : "NO");
    std::printf("audit:\n");
    for (auto const& entry : source.audit())
        std::printf("  %s=%s\n", entry.operation.c_str(), entry.status.c_str());

    bool all_ok =
        caps.keychain_available && caps.save_read_roundtrip && caps.update && caps.delete_item;
    std::printf("%s\n", all_ok ? "PROBE PASSED" : "PROBE DEGRADED");
    return all_ok ? 0 : 1;
}
