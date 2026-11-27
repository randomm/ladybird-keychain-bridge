#pragma once

#include "ByteBuffer.h"
#include "Origin.h"

#include <optional>
#include <string>

namespace lkb {

// Field names mirror the T11 bridge payload verbatim: top_level_origin,
// frame_origin, submit_action_origin, username, secret, field_scope, frame_id.
struct SaveRequest {
    Origin frame_origin;
    Origin top_level_origin;
    Origin submit_action_origin;
    std::string username;
    ByteBuffer secret;
    std::optional<std::string> form_meta;
};

struct SaveDecision {
    enum class Kind { Save, Reject, NeverList, Unchanged };
    enum class Reason { None, CrossOriginSubmit, HttpProhibited, NeverListed };

    Kind kind{Kind::Reject};
    Reason reason{Reason::None};
};

} // namespace lkb
