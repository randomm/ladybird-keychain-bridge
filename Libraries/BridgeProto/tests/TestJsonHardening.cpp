// Untrusted-input hardening for the frame codec's JSON parser (Review Focus 4):
// deep nesting, oversized numbers and malformed escapes must fail as typed
// errors — never as stack growth, UB or silent garbage.
#include "Json.h"
#include "testing/TestAssert.h"

#include <string>

using namespace lkb;

int main() {
    // Depth cap: unbounded recursion on nested containers is a stack DoS on
    // the 1 MiB frame surface.
    {
        std::string deep_ok = std::string(30, '[') + std::string(30, ']');
        EXPECT(!Json::parse(deep_ok).is_error());

        std::string deep_bad = std::string(65, '[') + std::string(65, ']');
        auto bad = Json::parse(deep_bad);
        EXPECT(bad.is_error());

        std::string obj_deep = std::string(65, '{');
        for (int i = 0; i < 65; ++i)
            obj_deep += "\"k\":";
        obj_deep += "1";
        obj_deep += std::string(65, '}');
        EXPECT(Json::parse(obj_deep).is_error());
    }

    // Number overflow: 20-digit runs are UB on int64 accumulation.
    {
        EXPECT(Json::parse("99999999999999999999").is_error());
        EXPECT(Json::parse("{\"seq\":99999999999999999999}").is_error());
        EXPECT(Json::parse("-9223372036854775809").is_error());
        auto ok = Json::parse("{\"seq\":1234567890123456789}");
        EXPECT(!ok.is_error());
        if (!ok.is_error())
            EXPECT_EQ(ok.value().get_int("seq", -1),
                      static_cast<std::int64_t>(1234567890123456789LL));
    }

    // Escapes: \u must be hex-only and reject lone surrogates.
    {
        EXPECT(Json::parse("\"\\u00zz\"").is_error());
        EXPECT(Json::parse("\"\\ud800\"").is_error());
        EXPECT(Json::parse("\"\\uDFFF\"").is_error());
        auto ok = Json::parse("\"a\\u0041b\"");
        EXPECT(!ok.is_error());
        if (!ok.is_error())
            EXPECT_EQ(ok.value().canonical(), std::string("\"aAb\""));
    }

    // Framing errors keep the Authentication taxonomy the header promises:
    // JSON failures surface as errors, never as a crash.
    {
        EXPECT(Json::parse("{\"a\": }").is_error());
        EXPECT(Json::parse("{\"a\":1,}").is_error());
        EXPECT(Json::parse("{\"a\":1} trailing").is_error());
    }

    return ::lkb::failures();
}
