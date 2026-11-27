#include "Json.h"

#include <cstdio>

namespace lkb {

namespace {

Error json_err(std::string_view what) {
    return Error{ErrorCode::MalformedCsv, std::string(what)};
}

void skip_ws(std::string_view t, size_t& pos) {
    while (pos < t.size() && (t[pos] == ' ' || t[pos] == '\t' || t[pos] == '\n' || t[pos] == '\r'))
        ++pos;
}

ErrorOr<bool> consume(std::string_view t, size_t& pos, std::string_view lit) {
    skip_ws(t, pos);
    if (t.substr(pos, lit.size()) != lit)
        return ErrorOr<bool>::error(json_err("expected literal"));
    pos += lit.size();
    return ErrorOr<bool>::ok(true);
}

ErrorOr<std::string> parse_string_raw(std::string_view t, size_t& pos) {
    if (pos >= t.size() || t[pos] != '"')
        return ErrorOr<std::string>::error(json_err("expected string"));
    ++pos;
    std::string out;
    while (pos < t.size()) {
        char c = t[pos];
        if (c == '"') {
            ++pos;
            return ErrorOr<std::string>::ok(std::move(out));
        }
        if (c == '\\') {
            ++pos;
            if (pos >= t.size())
                break;
            char e = t[pos++];
            switch (e) {
            case '"':
                out += '"';
                break;
            case '\\':
                out += '\\';
                break;
            case '/':
                out += '/';
                break;
            case 'b':
                out += '\b';
                break;
            case 'f':
                out += '\f';
                break;
            case 'n':
                out += '\n';
                break;
            case 'r':
                out += '\r';
                break;
            case 't':
                out += '\t';
                break;
            case 'u': {
                if (pos + 4 > t.size())
                    return ErrorOr<std::string>::error(json_err("bad \\u"));
                unsigned cp = 0;
                for (int i = 0; i < 4; ++i) {
                    char h = t[pos++];
                    unsigned v = (h <= '9') ? h - '0' : ((h | 32) - 'a' + 10);
                    cp = cp * 16 + v;
                }
                if (cp < 0x80) {
                    out += static_cast<char>(cp);
                } else if (cp < 0x800) {
                    out += static_cast<char>(0xC0 | (cp >> 6));
                    out += static_cast<char>(0x80 | (cp & 0x3F));
                } else {
                    out += static_cast<char>(0xE0 | (cp >> 12));
                    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                    out += static_cast<char>(0x80 | (cp & 0x3F));
                }
                break;
            }
            default:
                return ErrorOr<std::string>::error(json_err("bad escape"));
            }
            continue;
        }
        if (static_cast<unsigned char>(c) < 0x20)
            return ErrorOr<std::string>::error(json_err("control char in string"));
        out += c;
        ++pos;
    }
    return ErrorOr<std::string>::error(json_err("unterminated string"));
}

void escape_into(std::string& out, std::string const& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

} // namespace

ErrorOr<Json> Json::parse(std::string_view text) {
    size_t pos = 0;
    auto v = parse_value(text, pos);
    if (v.is_error())
        return v;
    skip_ws(text, pos);
    if (pos != text.size())
        return ErrorOr<Json>::error(json_err("trailing content"));
    return v;
}

ErrorOr<Json> Json::parse_value(std::string_view text, size_t& pos) {
    skip_ws(text, pos);
    if (pos >= text.size())
        return ErrorOr<Json>::error(json_err("eof"));
    char c = text[pos];
    if (c == '{') {
        ++pos;
        Json obj = make_object();
        skip_ws(text, pos);
        if (pos < text.size() && text[pos] == '}') {
            ++pos;
            return ErrorOr<Json>::ok(std::move(obj));
        }
        while (true) {
            auto key = parse_string_raw(text, pos);
            if (key.is_error())
                return ErrorOr<Json>::error(key.error());
            skip_ws(text, pos);
            if (pos >= text.size() || text[pos] != ':')
                return ErrorOr<Json>::error(json_err("expected colon"));
            ++pos;
            auto value = parse_value(text, pos);
            if (value.is_error())
                return value;
            obj.set(std::move(key.value()), std::move(value.value()));
            skip_ws(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < text.size() && text[pos] == '}') {
                ++pos;
                return ErrorOr<Json>::ok(std::move(obj));
            }
            return ErrorOr<Json>::error(json_err("expected , or }"));
        }
    }
    if (c == '[') {
        ++pos;
        Json arr;
        arr.m_type = Type::Array;
        skip_ws(text, pos);
        if (pos < text.size() && text[pos] == ']') {
            ++pos;
            return ErrorOr<Json>::ok(std::move(arr));
        }
        while (true) {
            auto value = parse_value(text, pos);
            if (value.is_error())
                return value;
            arr.m_arr.push_back(std::move(value.value()));
            skip_ws(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < text.size() && text[pos] == ']') {
                ++pos;
                return ErrorOr<Json>::ok(std::move(arr));
            }
            return ErrorOr<Json>::error(json_err("expected , or ]"));
        }
    }
    if (c == '"') {
        auto s = parse_string_raw(text, pos);
        if (s.is_error())
            return ErrorOr<Json>::error(s.error());
        return ErrorOr<Json>::ok(make_string(std::move(s.value())));
    }
    auto tr = consume(text, pos, "true");
    if (!tr.is_error()) {
        Json j = make_bool(true);
        return ErrorOr<Json>::ok(j);
    }
    auto fa = consume(text, pos, "false");
    if (!fa.is_error()) {
        Json j = make_bool(false);
        return ErrorOr<Json>::ok(j);
    }
    auto nu = consume(text, pos, "null");
    if (!nu.is_error())
        return ErrorOr<Json>::ok(make_null());

    // number: integers only (subset)
    size_t start = pos;
    if (pos < text.size() && text[pos] == '-')
        ++pos;
    if (pos >= text.size() || text[pos] < '0' || text[pos] > '9')
        return ErrorOr<Json>::error(json_err("bad value"));
    std::int64_t sign = 1;
    if (text[start] == '-')
        sign = -1;
    std::int64_t v = 0;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
        v = v * 10 + (text[pos] - '0');
        ++pos;
    }
    if (pos < text.size() && (text[pos] == '.' || text[pos] == 'e' || text[pos] == 'E'))
        return ErrorOr<Json>::error(json_err("doubles unsupported"));
    return ErrorOr<Json>::ok(make_int(sign * v));
}

std::int64_t Json::get_int(std::string const& key, std::int64_t fallback) const {
    auto it = m_obj.find(key);
    if (it == m_obj.end() || it->second.m_type != Type::Int)
        return fallback;
    return it->second.m_int;
}

std::string Json::get_string(std::string const& key) const {
    auto it = m_obj.find(key);
    if (it == m_obj.end() || it->second.m_type != Type::String)
        return {};
    return it->second.m_str;
}

std::string Json::canonical() const {
    switch (m_type) {
    case Type::Null:
        return "null";
    case Type::Bool:
        return m_bool ? "true" : "false";
    case Type::Int:
        return std::to_string(m_int);
    case Type::String: {
        std::string out;
        escape_into(out, m_str);
        return out;
    }
    case Type::Array: {
        std::string out = "[";
        for (size_t i = 0; i < m_arr.size(); ++i) {
            if (i)
                out += ',';
            out += m_arr[i].canonical();
        }
        out += ']';
        return out;
    }
    case Type::Object: {
        std::string out = "{";
        bool first = true;
        for (auto& [k, v] : m_obj) { // std::map: sorted by code units (ASCII)
            if (!first)
                out += ',';
            first = false;
            escape_into(out, k);
            out += ':';
            out += v.canonical();
        }
        out += '}';
        return out;
    }
    }
    return "null";
}

} // namespace lkb
