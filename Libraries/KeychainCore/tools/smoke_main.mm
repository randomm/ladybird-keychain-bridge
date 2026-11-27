// Owner-run smoke CLI against a dedicated file-based keychain (never the login keychain).
#import <Security/Security.h>

#include "MasterKey.h"
#include "SecItemKeychainBackend.h"

#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv)
{
    std::string keychain_path;
    std::string service = "Ladybird Safe Storage Smoke";
    std::string account = "Ladybird Smoke";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--keychain"))
            keychain_path = argv[i + 1];
        else if (!std::strcmp(argv[i], "--service"))
            service = argv[i + 1];
        else if (!std::strcmp(argv[i], "--account"))
            account = argv[i + 1];
    }
    if (keychain_path.empty()) {
        std::printf("SMOKE FAILED: --keychain <path> required\n");
        return 2;
    }

    auto created = lkb::SecItemKeychainBackend::create(service, account, keychain_path);
    if (created.is_error()) {
        std::printf("SMOKE FAILED: create: %s\n", created.error().message.c_str());
        return 1;
    }
    auto backend = std::move(created.value());

    if (!backend.is_available()) {
        std::printf("SMOKE FAILED: keychain unavailable (locked?)\n");
        return 1;
    }

    auto rng = [](size_t n) { return lkb::default_master_key_rng(n); };
    auto first = master_key_or_create(backend, rng);
    if (first.is_error()) {
        std::printf("SMOKE FAILED: create: %s\n", first.error().message.c_str());
        return 1;
    }
    auto reread = backend.read_master_key();
    if (reread.is_error() || reread.value() != first.value()) {
        std::printf("SMOKE FAILED: read-back mismatch\n");
        return 1;
    }
    auto rotated = rng(16);
    auto write = backend.write_master_key(rotated, lkb::Accessibility::WhenUnlocked);
    if (write.is_error()) {
        std::printf("SMOKE FAILED: update: %s\n", write.error().message.c_str());
        return 1;
    }
    auto reread2 = backend.read_master_key();
    if (reread2.is_error() || reread2.value() != rotated) {
        std::printf("SMOKE FAILED: update read-back mismatch\n");
        return 1;
    }
    std::printf("SMOKE OK\n");
    return 0;
}
