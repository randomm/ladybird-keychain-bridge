#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"
#include "Json.h"

#include <cstdint>
#include <string>

namespace lkb {

struct HandshakeKeyPair {
    void* pkey{nullptr}; // owned EVP_PKEY*; opaque to keep OpenSSL out of headers
    HandshakeKeyPair() = default;
    ~HandshakeKeyPair();
    HandshakeKeyPair(HandshakeKeyPair&& o) noexcept;
    HandshakeKeyPair& operator=(HandshakeKeyPair&& o) noexcept;
    HandshakeKeyPair(HandshakeKeyPair const&) = delete;
};

struct HelloMsg {
    std::uint32_t proto_version{1};
    std::string caller_bundle_id;
    std::string eph_pub_hex; // uncompressed P-256 point
    std::string nonce_hex;   // 16 random bytes
    std::string canonical() const;
    Json to_json() const;
};

struct HelloAck {
    std::string server_pub_hex;
    Json capabilities;
    std::string transcript_hex;
    std::string canonical_without_transcript() const;
};

// hello -> hello_ack handshake; session key_mac = HKDF-SHA-256(
//   ikm = ECDH-P256(client_eph, server_eph),
//   salt = canonical(hello) || canonical(ack-with-empty-transcript),
//   info = "lkb-session", 32 bytes).
// The transcript hash binds hello to the peer identity string; a client that
// expects a different identity fails with ErrorCode::Handshake.
class Handshake {
  public:
    struct ClientStart {
        HelloMsg hello;
        HandshakeKeyPair keypair;
    };
    struct ServerSide {
        HelloAck ack;
        ByteBuffer key_mac;
        HandshakeKeyPair ephemerals;
    };

    static ErrorOr<HandshakeKeyPair> generate_keypair();
    static ErrorOr<HandshakeKeyPair> keypair_from_private_hex(std::string const& priv_hex);

    static ErrorOr<ClientStart> start_client(std::string caller_bundle_id,
                                             std::string priv_hex = {}, std::string nonce_hex = {});
    static ErrorOr<ServerSide> accept_hello(HelloMsg const& hello, std::string peer_identity,
                                            std::string priv_hex = {});
    static ErrorOr<ByteBuffer> complete_client(HelloMsg const& hello, HelloAck const& ack,
                                               HandshakeKeyPair& client_keypair,
                                               std::string const& peer_identity);
};

} // namespace lkb
