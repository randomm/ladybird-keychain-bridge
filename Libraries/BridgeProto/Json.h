#pragma once

#include "ErrorOr.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lkb {

// Minimal JSON value model for bridge frames: null/bool/int/string/array/object.
// canonical() implements the RFC 8785 subset we use: object keys sorted by
// code unit, integers in shortest decimal form, JSON.stringify escaping.
class Json {
  public:
    enum class Type { Null, Bool, Int, String, Array, Object };

    static Json make_bool(bool v) {
        Json j;
        j.m_type = Type::Bool;
        j.m_bool = v;
        return j;
    }
    static Json make_int(std::int64_t v) {
        Json j;
        j.m_type = Type::Int;
        j.m_int = v;
        return j;
    }
    static Json make_string(std::string v) {
        Json j;
        j.m_type = Type::String;
        j.m_str = std::move(v);
        return j;
    }
    static Json make_object() {
        Json j;
        j.m_type = Type::Object;
        return j;
    }

    static ErrorOr<Json> parse(std::string_view text);

    Type type() const { return m_type; }
    std::int64_t get_int(std::string const& key, std::int64_t fallback = 0) const;
    std::string get_string(std::string const& key) const;
    void set(std::string key, Json value) { m_obj[std::move(key)] = std::move(value); }
    Json const* get(std::string const& key) const {
        auto it = m_obj.find(key);
        return it == m_obj.end() ? nullptr : &it->second;
    }

    std::string canonical() const;

  public:
    Json() = default;
    static Json make_null() { return Json{}; }

  private:
    Type m_type{Type::Null};
    bool m_bool{false};
    std::int64_t m_int{0};
    std::string m_str;
    std::vector<Json> m_arr;
    std::map<std::string, Json> m_obj; // key order canonical: sorted by std::string (code units)

    static ErrorOr<Json> parse_value(std::string_view text, size_t& pos, int depth = 0);
};

} // namespace lkb
