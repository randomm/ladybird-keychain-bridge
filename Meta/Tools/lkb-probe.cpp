// Owner-run capability probe (M10). Runs the SystemVaultSource roundtrip against a
// DEDICATED file-based keychain — it refuses the login keychain and refuses to run
// without LKB_OWNER_RUN=1. Never touches user items.
#include "SecItemKeychainBackend.h"
#include "SystemVaultSource.h"
#include "SystemVaultSourceProbe.h"

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
    std::string json_path;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--keychain"))
            keychain_path = argv[i + 1];
        else if (!std::strcmp(argv[i], "--service"))
            service = argv[i + 1];
        else if (!std::strcmp(argv[i], "--account"))
            account = argv[i + 1];
        else if (!std::strcmp(argv[i], "--json"))
            json_path = argv[i + 1];
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

    // The probe owns a dedicated service/account in a dedicated keychain file —
    // probe() refuses to run against anything else.
    lkb::SystemVaultSource source{backend, lkb::SystemVaultSource::DedicatedProbe::Yes};
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

    // System-mediated surfaces (plan Task 16): presence/availability states —
    // the signed matrix owns "available" (spec §7). Not part of the keychain
    // pass/fail: ad-hoc builds legitimately report unvalidated_* everywhere.
    auto as = lkb::probe_authorization_apis();
    std::printf("authorization services (presence; signed matrix validates):\n");
    std::printf("  password_provider: %s\n", lkb::to_string(as.password_provider));
    std::printf("  passkey_manager:   %s\n", lkb::to_string(as.passkey_manager));
    std::printf("  cxp_manager:       %s\n", lkb::to_string(as.cxp_manager));
    std::printf("  delivered_codes:   %s\n", lkb::to_string(as.delivered_codes));

    if (!json_path.empty()) {
        // Capability matrix only — audit entries are {operation, status} tokens, never secrets.
        FILE* out = std::fopen(json_path.c_str(), "w");
        if (!out) {
            std::printf("PROBE WARNING: cannot write %s\n", json_path.c_str());
        } else {
            std::fprintf(out, "{\n  \"capabilities\": {\n");
            std::fprintf(out, "    \"keychain_available\": %s,\n",
                         caps.keychain_available ? "true" : "false");
            std::fprintf(out, "    \"save_read_roundtrip\": %s,\n",
                         caps.save_read_roundtrip ? "true" : "false");
            std::fprintf(out, "    \"update\": %s,\n", caps.update ? "true" : "false");
            std::fprintf(out, "    \"delete\": %s\n", caps.delete_item ? "true" : "false");
            std::fprintf(out, "  },\n  \"authorization_services\": {\n");
            std::fprintf(out, "    \"password_provider\": \"%s\",\n",
                         lkb::to_string(as.password_provider));
            std::fprintf(out, "    \"passkey_manager\": \"%s\",\n",
                         lkb::to_string(as.passkey_manager));
            std::fprintf(out, "    \"cxp_manager\": \"%s\",\n", lkb::to_string(as.cxp_manager));
            std::fprintf(out, "    \"delivered_codes\": \"%s\"\n",
                         lkb::to_string(as.delivered_codes));
            std::fprintf(out, "  },\n  \"audit\": [");
            for (size_t i = 0; i < source.audit().size(); ++i) {
                auto const& e = source.audit()[i];
                std::fprintf(out, "%s\n    {\"operation\": \"%s\", \"status\": \"%s\"}",
                             i ? "," : "", e.operation.c_str(), e.status.c_str());
            }
            std::fprintf(out, "\n  ],\n  \"passed\": %s\n}\n", all_ok ? "true" : "false");
            std::fclose(out);
        }
    }

    std::printf("%s\n", all_ok ? "PROBE PASSED" : "PROBE DEGRADED");
    return all_ok ? 0 : 1;
}
