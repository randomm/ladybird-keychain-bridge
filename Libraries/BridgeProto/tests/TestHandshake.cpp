#include "Frame.h"
#include "Handshake.h"
#include "testing/TestAssert.h"

#include <fstream>
#include <sstream>
#include <string>

#ifndef FIXTURE_DIR
#define FIXTURE_DIR "."
#endif

using namespace lkb;

static std::string read_fixture(std::string const& name) {
    std::ifstream f(std::string(FIXTURE_DIR) + "/" + name);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

int main() {
    std::string const peer_identity = "lkb-daemon:test-bundle";
    Handshake::reset_nonce_cache_for_tests();

    // full handshake + sealed lookup roundtrip
    {
        auto client = Handshake::start_client("com.example.ladybird");
        EXPECT(!client.is_error());
        if (client.is_error())
            return ::lkb::failures();

        auto server = Handshake::accept_hello(client.value().hello, peer_identity);
        EXPECT(!server.is_error());
        if (server.is_error())
            return ::lkb::failures();
        EXPECT(!server.value().ack.transcript_hex.empty());

        auto client_keys = Handshake::complete_client(client.value().hello, server.value().ack,
                                                      client.value().keypair, peer_identity);
        EXPECT(!client_keys.is_error());
        if (client_keys.is_error())
            return ::lkb::failures();

        EXPECT(client_keys.value() == server.value().key_mac);

        ProtectedChannel up(client_keys.value(), Direction::Request);
        auto wire = up.seal(R"({"cmd":"lookup","origin":"https://x.example"})", 0);
        EXPECT(!wire.is_error());
        std::uint64_t ns = 0;
        auto out = up.unseal(wire.value(), ns, max_request_bytes);
        EXPECT(!out.is_error());
        if (!out.is_error())
            EXPECT_EQ(out.value().payload.get_string("cmd"), std::string("lookup"));
    }

    // transcript binds peer identity: mismatched identity fails the handshake
    {
        auto client = Handshake::start_client("com.example.ladybird");
        auto server = Handshake::accept_hello(client.value().hello, peer_identity);
        auto bad =
            Handshake::complete_client(client.value().hello, server.value().ack,
                                       client.value().keypair, "completely.different.identity");
        EXPECT(bad.is_error());
        if (bad.is_error())
            EXPECT_EQ(static_cast<int>(bad.error().code), static_cast<int>(ErrorCode::Handshake));
    }

    // golden vector: fixed private keys pin the key derivation
    {
        std::string golden = read_fixture("proto_golden.json");
        EXPECT(!golden.empty());
        auto want_key_mac = golden.substr(golden.find("\"key_mac\": \"") + 12);
        want_key_mac = want_key_mac.substr(0, want_key_mac.find('"'));

        auto client_priv = golden.substr(golden.find("\"client_priv\": \"") + 16);
        client_priv = client_priv.substr(0, client_priv.find('"'));
        auto server_priv = golden.substr(golden.find("\"server_priv\": \"") + 16);
        server_priv = server_priv.substr(0, server_priv.find('"'));

        auto client = Handshake::start_client("com.example.ladybird", client_priv,
                                              "00112233445566778899aabbccddeeff");
        EXPECT(!client.is_error());
        auto server = Handshake::accept_hello(client.value().hello, peer_identity, server_priv);
        EXPECT(!server.is_error());
        auto keys = Handshake::complete_client(client.value().hello, server.value().ack,
                                               client.value().keypair, peer_identity);
        EXPECT(!keys.is_error());
        if (!keys.is_error() && !want_key_mac.empty()) {
            static char const* hexd = "0123456789abcdef";
            std::string got;
            for (auto b : keys.value()) {
                got += hexd[b >> 4];
                got += hexd[b & 15];
            }
            EXPECT_EQ(got, want_key_mac);
        }
    }

    // Key confirmation roundtrip: each side proves session-key possession; a
    // wrong key or swapped side fails verification.
    {
        auto client = Handshake::start_client("com.example.ladybird");
        auto server = Handshake::accept_hello(client.value().hello, peer_identity);
        EXPECT(!server.is_error());
        auto keys = Handshake::complete_client(client.value().hello, server.value().ack,
                                               client.value().keypair, peer_identity);
        EXPECT(!keys.is_error());
        if (!keys.is_error() && !server.is_error()) {
            auto hc = client.value().hello.canonical();
            auto ac = server.value().ack.canonical_without_transcript();
            auto client_mac = Handshake::confirmation_mac(keys.value(), false, hc, ac);
            auto server_mac = Handshake::confirmation_mac(server.value().key_mac, true, hc, ac);
            EXPECT(
                Handshake::verify_confirmation(server.value().key_mac, false, hc, ac, client_mac));
            EXPECT(Handshake::verify_confirmation(keys.value(), true, hc, ac, server_mac));
            ByteBuffer wrong(32, 0x11);
            EXPECT(!Handshake::verify_confirmation(wrong, false, hc, ac, client_mac));
            EXPECT(!Handshake::verify_confirmation(keys.value(), true, hc, ac, client_mac));
        }
    }

    // Review fix: proto_version is an actual gate, not a decorative field.
    {
        auto client = Handshake::start_client("com.example.ladybird");
        EXPECT(!client.is_error());
        auto warped = client.value().hello;
        warped.proto_version = 2;
        auto server = Handshake::accept_hello(warped, peer_identity);
        EXPECT(server.is_error());
        if (server.is_error())
            EXPECT_EQ(static_cast<int>(server.error().code),
                      static_cast<int>(ErrorCode::Handshake));
    }

    // Review fix: malformed nonces are refused, and a replayed nonce across
    // reconnects is rejected against the same process's listener state.
    {
        auto client = Handshake::start_client("com.example.ladybird");
        EXPECT(!client.is_error());
        auto junk_nonce = client.value().hello;
        junk_nonce.nonce_hex = "nonsense";
        auto bad = Handshake::accept_hello(junk_nonce, peer_identity);
        EXPECT(bad.is_error());

        auto first = Handshake::accept_hello(client.value().hello, peer_identity);
        EXPECT(!first.is_error());
        auto replay = Handshake::accept_hello(client.value().hello, peer_identity);
        EXPECT(replay.is_error());
        if (replay.is_error())
            EXPECT_EQ(static_cast<int>(replay.error().code),
                      static_cast<int>(ErrorCode::Handshake));
    }

    return ::lkb::failures();
}
