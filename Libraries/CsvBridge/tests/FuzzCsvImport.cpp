// Standalone fuzz target (owner/CI-fuzz runs with -fsanitize=fuzzer; excluded
// from the default build). Importing arbitrary bytes must never crash or
// allocate beyond the documented caps.
#include "CsvBridge.h"
#include "VaultStore.h"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size);

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    static int counter = 0;
    char path[] = "/tmp/lkb-fuzz-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return 0;
    close(fd);
    auto vault = lkb::VaultStore::open(path, lkb::ByteBuffer(16, 0xF));
    if (!vault.is_error())
        (void)lkb::import_csv(lkb::ByteBuffer(data, data + size), vault.value());
    std::remove(path);
    ++counter;
    return 0;
}
