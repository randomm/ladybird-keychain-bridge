#include "Frame.h"

#include "Hkdf.h"

#include <cstring>

namespace lkb {

namespace {

Error frame_err(std::string_view what, ErrorCode code) {
    return Error{code, std::string(what)};
}

ByteBuffer mac_input(std::uint64_t seq, Direction dir, std::string const& canonical_payload) {
    ByteBuffer out;
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>(seq >> (8 * i)));
    out.push_back(static_cast<std::uint8_t>(dir));
    out.insert(out.end(), canonical_payload.begin(), canonical_payload.end());
    return out;
}

std::string to_hex(ByteBuffer const& b) {
    static char const* d = "0123456789abcdef";
    std::string s;
    for (auto c : b) {
        s += d[c >> 4];
        s += d[c & 15];
    }
    return s;
}

ErrorOr<ByteBuffer> from_hex(std::string const& s) {
    if (s.size() % 2 != 0)
        return ErrorOr<ByteBuffer>::error(frame_err("bad hex", ErrorCode::Authentication));
    auto val = [](char c) -> int {
        if (c <= '9')
            return c - '0';
        return (c | 32) - 'a' + 10;
    };
    ByteBuffer out;
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = val(s[i]);
        int lo = val(s[i + 1]);
        if ((hi | lo) & ~0xF)
            return ErrorOr<ByteBuffer>::error(frame_err("bad hex", ErrorCode::Authentication));
        out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
    }
    return ErrorOr<ByteBuffer>::ok(std::move(out));
}

bool const_time_equal(ByteBuffer const& a, ByteBuffer const& b) {
    if (a.size() != b.size())
        return false;
    unsigned diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace

ErrorOr<ByteBuffer> ProtectedChannel::seal(std::string const& payload_json,
                                           std::uint64_t seq) const {
    auto payload = Json::parse(payload_json);
    if (payload.is_error())
        return ErrorOr<ByteBuffer>::error(payload.error());
    auto canonical_payload = payload.value().canonical();

    auto mac = hmac_sha256(m_key_mac, mac_input(seq, m_direction, canonical_payload));
    if (mac.is_error())
        return ErrorOr<ByteBuffer>::error(mac.error());

    std::string body = "{\"mac\":\"" + to_hex(mac.value()) + "\",\"payload\":" + canonical_payload +
                       ",\"seq\":" + std::to_string(seq) + "}";
    ByteBuffer wire(4 + body.size());
    auto len = static_cast<std::uint32_t>(body.size());
    wire[0] = static_cast<std::uint8_t>(len);
    wire[1] = static_cast<std::uint8_t>(len >> 8);
    wire[2] = static_cast<std::uint8_t>(len >> 16);
    wire[3] = static_cast<std::uint8_t>(len >> 24);
    memcpy(wire.data() + 4, body.data(), body.size());
    return ErrorOr<ByteBuffer>::ok(std::move(wire));
}

ErrorOr<UnsealedFrame> ProtectedChannel::unseal(ByteBuffer const& wire, std::uint64_t& io_next_seq,
                                                size_t cap) const {
    if (wire.size() < 4)
        return ErrorOr<UnsealedFrame>::error(frame_err("short header", ErrorCode::IncompleteFrame));
    std::uint32_t len =
        static_cast<std::uint32_t>(wire[0]) | static_cast<std::uint32_t>(wire[1]) << 8 |
        static_cast<std::uint32_t>(wire[2]) << 16 | static_cast<std::uint32_t>(wire[3]) << 24;
    if (static_cast<size_t>(len) > cap)
        return ErrorOr<UnsealedFrame>::error(frame_err("frame over cap", ErrorCode::TooLarge));
    if (wire.size() < 4 + static_cast<size_t>(len))
        return ErrorOr<UnsealedFrame>::error(frame_err("short body", ErrorCode::IncompleteFrame));

    std::string_view body(reinterpret_cast<char const*>(wire.data() + 4), len);
    auto envelope = Json::parse(body);
    if (envelope.is_error())
        return ErrorOr<UnsealedFrame>::error(envelope.error());

    Json const& env = envelope.value();
    if (env.get("seq") == nullptr)
        return ErrorOr<UnsealedFrame>::error(frame_err("missing seq", ErrorCode::Authentication));
    auto seq = static_cast<std::uint64_t>(env.get_int("seq"));

    // Sequence window first: cheapest replay defense, before any HMAC work.
    if (seq < io_next_seq)
        return ErrorOr<UnsealedFrame>::error(frame_err("replayed seq", ErrorCode::Authentication));
    constexpr std::uint64_t window = 64;
    if (seq > io_next_seq + window)
        return ErrorOr<UnsealedFrame>::error(frame_err("seq jump", ErrorCode::Authentication));

    auto mac_field = env.get_string("mac");
    auto want = from_hex(mac_field);
    if (want.is_error())
        return ErrorOr<UnsealedFrame>::error(want.error());

    // Canonicalize from the PARSED payload: the wire spelling cannot spoof the
    // MAC, which covers only the canonical form.
    auto const* payload_json = env.get("payload");
    if (!payload_json)
        return ErrorOr<UnsealedFrame>::error(
            frame_err("missing payload", ErrorCode::Authentication));
    std::string canonical_payload = payload_json->canonical();

    auto mac = hmac_sha256(m_key_mac, mac_input(seq, m_direction, canonical_payload));
    if (mac.is_error())
        return ErrorOr<UnsealedFrame>::error(mac.error());
    if (!const_time_equal(mac.value(), want.value()))
        return ErrorOr<UnsealedFrame>::error(frame_err("mac mismatch", ErrorCode::Authentication));

    auto payload = Json::parse(canonical_payload);
    if (payload.is_error())
        return ErrorOr<UnsealedFrame>::error(payload.error());

    io_next_seq = seq + 1;
    UnsealedFrame out;
    out.seq = seq;
    out.payload = std::move(payload.value());
    return ErrorOr<UnsealedFrame>::ok(std::move(out));
}

} // namespace lkb
