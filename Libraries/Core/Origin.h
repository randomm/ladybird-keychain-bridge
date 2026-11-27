#pragma once

#include "ErrorOr.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace lkb {

// Exact-origin identity: scheme (http|https) + casefolded ASCII host + port with
// default stripping. userinfo, query and fragment are rejected — they are not origins.
class Origin {
public:
    static ErrorOr<Origin> parse(std::string_view url);

    bool equal(Origin const& other) const
    {
        return scheme == other.scheme && host == other.host && port == other.port;
    }

    // http origins are usable ONLY for literal localhost with an explicit port
    // (owner-visible opt-in rule; https always allowed).
    bool is_local_opt_in() const
    {
        return scheme == "http" && host == "localhost" && has_explicit_port;
    }

    std::string serialize() const;

    std::string scheme;
    std::string host;
    std::uint16_t port { 0 };
    bool has_explicit_port { false };
};

}
