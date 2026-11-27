#pragma once

#include "ByteBuffer.h"
#include "Origin.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace lkb {

struct CredentialRecord {
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
