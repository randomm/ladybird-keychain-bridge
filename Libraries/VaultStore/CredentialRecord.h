#pragma once

#include "ByteBuffer.h"
#include "Origin.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace lkb {

struct CredentialRecord {
    // Row id in the vault; populated only on read paths that carry it (all()),
    // so admin surfaces can name records for deletion. Not part of the stored
    // payload — put() assigns its own id.
    std::int64_t id{0};
    Origin origin;
    std::string username;
    ByteBuffer secret;
    std::int64_t created{0};
    std::int64_t last_used{0};
    std::int64_t updated{0};
    std::map<std::string, std::string> extra_fields;
    std::optional<std::string> form_meta;
};

struct Match {
    std::int64_t id{0};
    CredentialRecord record;
};

} // namespace lkb
