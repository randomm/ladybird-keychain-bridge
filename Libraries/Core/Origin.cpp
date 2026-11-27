#include "Origin.h"

#include <cctype>

namespace lkb {

static Error invalid(std::string what)
{
    return Error { ErrorCode::InvalidOrigin, std::move(what) };
}

ErrorOr<Origin> Origin::parse(std::string_view url)
{
    for (char c : url) {
        if (c == '@' || c == '#' || c == '?')
            return ErrorOr<Origin>::error(invalid("userinfo/query/fragment not allowed"));
    }

    auto sep = url.find("://");
    if (sep == std::string_view::npos)
        return ErrorOr<Origin>::error(invalid("missing scheme separator"));

    std::string scheme;
    scheme.reserve(sep);
    for (char c : url.substr(0, sep))
        scheme += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (scheme != "http" && scheme != "https")
        return ErrorOr<Origin>::error(invalid("unsupported scheme"));

    auto rest = url.substr(sep + 3);
    auto authority = rest.substr(0, rest.find('/'));
    if (authority.empty())
        return ErrorOr<Origin>::error(invalid("empty host"));

    std::string host { authority };
    std::uint16_t port = (scheme == "https") ? 443 : 80;
    bool explicit_port = false;

    if (auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = std::string(authority.substr(0, colon));
        auto port_str = authority.substr(colon + 1);
        if (port_str.empty() || port_str.size() > 5)
            return ErrorOr<Origin>::error(invalid("bad port"));
        unsigned value = 0;
        for (char c : port_str) {
            if (c < '0' || c > '9')
                return ErrorOr<Origin>::error(invalid("non-digit port"));
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value < 1 || value > 65535)
            return ErrorOr<Origin>::error(invalid("port out of range"));
        port = static_cast<std::uint16_t>(value);
        explicit_port = true;
    }

    for (char& c : host)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (host.empty())
        return ErrorOr<Origin>::error(invalid("empty host"));
    for (char c : host) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        if (!ok)
            return ErrorOr<Origin>::error(invalid("invalid host character"));
    }

    Origin origin;
    origin.scheme = std::move(scheme);
    origin.host = std::move(host);
    origin.port = port;
    origin.has_explicit_port = explicit_port;
    return ErrorOr<Origin>::ok(std::move(origin));
}

std::string Origin::serialize() const
{
    std::string out = scheme + "://" + host;
    bool default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    if (has_explicit_port && !default_port)
        out += ":" + std::to_string(port);
    return out;
}

}
