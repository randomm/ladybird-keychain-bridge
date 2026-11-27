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
// What this DOES give: an ephemeral ECDH key agreement (forward secrecy for
// sealed frames) plus a transcript binding that detects frame substitution by
// an attacker who does not know the expected peer-identity string.
// What this does NOT give: authentication of the peer. ECDH alone cannot
// authenticate; the OS peer credential (SecCodeCheckValidity / audit-token
// pinning on the helper socket, PasswordsServer era per spec §7) is the sole
// authenticator, and must be enforced before or alongside this handshake.
// The confirmation helpers below then prove possession of the derived session
// key (key confirmation per spec §6.11) — defence in depth, not a substitute.
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

    // Key confirmation (spec §6.11): each side HMACs label+transcript under the
    // session key; the peer must verify it before acting on any sealed frame.
    static ByteBuffer confirmation_mac(ByteBuffer const& session_key, bool is_server,
                                       std::string const& hello_canonical,
                                       std::string const& ack_canonical);
    static bool verify_confirmation(ByteBuffer const& session_key, bool is_server,
                                    std::string const& hello_canonical,
                                    std::string const& ack_canonical, ByteBuffer const& mac);

    // accept_hello rejects replayed hello nonces against the process listener
    // state; tests reset that state between cases.
    static void reset_nonce_cache_for_tests();
};

} // namespace lkb
