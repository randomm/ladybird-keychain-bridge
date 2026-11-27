#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"
#include "Json.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace lkb {

constexpr size_t max_request_bytes = 1u << 20;
constexpr size_t max_response_bytes = 16u << 20;

enum class Direction : std::uint8_t {
    Request = 0,
    Response = 1,
};

struct UnsealedFrame {
    std::uint64_t seq{0};
    Json payload{Json::make_null()};
};

// Wire: 4-byte LE payload length || {"seq":N,"mac":"hex","payload":{...}}
// mac = HMAC-SHA-256(key_mac, seq_be64 || direction_byte || canonical(payload)).
// Per-session verifier holds next_seq; frames with seq < next_seq (replay) or
// seq > next_seq+64 (jump) are rejected. Failures are Authentication, except
// framing errors (IncompleteFrame/TooLarge) which precede any parsing.
class ProtectedChannel {
  public:
    ProtectedChannel(ByteBuffer key_mac, Direction direction)
        : m_key_mac(std::move(key_mac)), m_direction(direction) {}

    ErrorOr<ByteBuffer> seal(std::string const& payload_json, std::uint64_t seq) const;
    ErrorOr<UnsealedFrame> unseal(ByteBuffer const& wire, std::uint64_t& io_next_seq,
                                  size_t cap) const;

  private:
    ByteBuffer m_key_mac;
    Direction m_direction;
};

} // namespace lkb
