#include "Handshake.h"

#include "Hkdf.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <set>
#include <vector>

namespace lkb {

namespace {

Error hs_err(std::string_view what) {
    return Error{ErrorCode::Handshake, std::string(what)};
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
    if (s.empty() || s.size() % 2 != 0)
        return ErrorOr<ByteBuffer>::error(hs_err("bad hex"));
    auto val = [](char c) -> int {
        if (c <= '9')
            return c - '0';
        return (c | 32) - 'a' + 10;
    };
    ByteBuffer out;
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = val(s[i]);
        int lo = val(s[i + 1]);
        if (hi > 15 || lo > 15 || !std::isxdigit(static_cast<unsigned char>(s[i])) ||
            !std::isxdigit(static_cast<unsigned char>(s[i + 1])))
            return ErrorOr<ByteBuffer>::error(hs_err("bad hex"));
        out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
    }
    return ErrorOr<ByteBuffer>::ok(std::move(out));
}

ErrorOr<std::string> public_hex(EVP_PKEY* pkey) {
    unsigned char buf[133];
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len) !=
        1) {
        unsigned long e = ERR_get_error();
        char eb[256];
        ERR_error_string_n(e, eb, sizeof(eb));
        fprintf(stderr, "pub export openssl error: %s\n", eb);
        return ErrorOr<std::string>::error(hs_err("pub export"));
    }
    return ErrorOr<std::string>::ok(to_hex(ByteBuffer(buf, buf + len)));
}

ErrorOr<ByteBuffer> ecdh(EVP_PKEY* priv_owner, std::string const& peer_pub_hex) {
    auto pub_bytes = from_hex(peer_pub_hex);
    if (pub_bytes.is_error())
        return ErrorOr<ByteBuffer>::error(pub_bytes.error());

    EVP_PKEY* peer = nullptr;
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub_bytes.value().data(),
                                                  pub_bytes.value().size());
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>("prime256v1"), 0);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX* imp = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!imp || EVP_PKEY_fromdata_init(imp) != 1 ||
        EVP_PKEY_fromdata(imp, &peer, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(imp);
        return ErrorOr<ByteBuffer>::error(hs_err("peer import"));
    }
    EVP_PKEY_CTX_free(imp);

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(priv_owner, nullptr);
    ByteBuffer secret;
    if (!dctx || EVP_PKEY_derive_init(dctx) != 1 || EVP_PKEY_derive_set_peer(dctx, peer) != 1) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        return ErrorOr<ByteBuffer>::error(hs_err("derive setup"));
    }
    size_t len = 0;
    if (EVP_PKEY_derive(dctx, nullptr, &len) != 1 || len == 0 || len > 64) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        return ErrorOr<ByteBuffer>::error(hs_err("derive size"));
    }
    secret.resize(len);
    int rc = EVP_PKEY_derive(dctx, secret.data(), &len);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    if (rc != 1)
        return ErrorOr<ByteBuffer>::error(hs_err("derive"));
    secret.resize(len);
    return ErrorOr<ByteBuffer>::ok(std::move(secret));
}

ByteBuffer transcript_hash(std::string const& canonical_hello,
                           std::string const& canonical_ack_no_transcript,
                           std::string const& peer_identity) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, canonical_hello.data(), canonical_hello.size());
    EVP_DigestUpdate(ctx, canonical_ack_no_transcript.data(), canonical_ack_no_transcript.size());
    EVP_DigestUpdate(ctx, peer_identity.data(), peer_identity.size());
    unsigned int outl = 0;
    EVP_DigestFinal_ex(ctx, md, &outl);
    EVP_MD_CTX_free(ctx);
    return ByteBuffer(md, md + outl);
}

ErrorOr<ByteBuffer> session_key(HelloMsg const& hello, HelloAck const& ack_no_t,
                                ByteBuffer const& shared) {
    auto salt_str = hello.canonical() + ack_no_t.canonical_without_transcript();
    ByteBuffer salt(salt_str.begin(), salt_str.end());
    std::string info_str = "lkb-session";
    ByteBuffer info(info_str.begin(), info_str.end());
    return hkdf_sha256(shared, salt, info, 32);
}

} // namespace

HandshakeKeyPair::~HandshakeKeyPair() {
    if (pkey)
        EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey));
}

HandshakeKeyPair::HandshakeKeyPair(HandshakeKeyPair&& o) noexcept : pkey(o.pkey) {
    o.pkey = nullptr;
}

HandshakeKeyPair& HandshakeKeyPair::operator=(HandshakeKeyPair&& o) noexcept {
    if (this != &o) {
        if (pkey)
            EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey));
        pkey = o.pkey;
        o.pkey = nullptr;
    }
    return *this;
}

std::string HelloMsg::canonical() const {
    return to_json().canonical();
}

Json HelloMsg::to_json() const {
    Json j = Json::make_object();
    j.set("caller_bundle_id", Json::make_string(caller_bundle_id));
    j.set("eph_pub", Json::make_string(eph_pub_hex));
    j.set("nonce", Json::make_string(nonce_hex));
    j.set("proto_version", Json::make_int(proto_version));
    return j;
}

std::string HelloAck::canonical_without_transcript() const {
    Json j = Json::make_object();
    j.set("capabilities", capabilities);
    j.set("server_pub", Json::make_string(server_pub_hex));
    j.set("transcript", Json::make_string(""));
    return j.canonical();
}

ErrorOr<HandshakeKeyPair> Handshake::generate_keypair() {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!kctx)
        return ErrorOr<HandshakeKeyPair>::error(hs_err("ctx"));
    HandshakeKeyPair kp;
    int ok = EVP_PKEY_keygen_init(kctx) == 1 &&
             EVP_PKEY_CTX_set_group_name(kctx, "prime256v1") == 1 &&
             EVP_PKEY_keygen(kctx, reinterpret_cast<EVP_PKEY**>(&kp.pkey)) == 1;
    EVP_PKEY_CTX_free(kctx);
    if (!ok || !kp.pkey)
        return ErrorOr<HandshakeKeyPair>::error(hs_err("keygen"));
    return ErrorOr<HandshakeKeyPair>::ok(std::move(kp));
}

ErrorOr<HandshakeKeyPair> Handshake::keypair_from_private_hex(std::string const& priv_hex) {
    auto priv = from_hex(priv_hex);
    if (priv.is_error())
        return ErrorOr<HandshakeKeyPair>::error(priv.error());
    if (priv.value().size() != 32)
        return ErrorOr<HandshakeKeyPair>::error(hs_err("priv size"));

    // Derive the public point from the private scalar (EC_POINT_mul), then hand
    // OpenSSL a complete keypair. Deprecated EC APIs are the practical path for
    // test-key injection without embedding pub in fixtures. OpenSSL 3.x keeps
    // these functional (with deprecation), and this scope is the only use; the
    // live key agreement below is pure EVP.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec)
        return ErrorOr<HandshakeKeyPair>::error(hs_err("ec new"));
    HandshakeKeyPair kp;
    BIGNUM* d = BN_bin2bn(priv.value().data(), static_cast<int>(priv.value().size()), nullptr);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pub = EC_POINT_new(group);
    bool ok = d && pub && EC_KEY_set_private_key(ec, d) == 1 &&
              EC_POINT_mul(group, pub, d, nullptr, nullptr, nullptr) == 1 &&
              EC_KEY_set_public_key(ec, pub) == 1;
    if (ok) {
        EVP_PKEY* pkey = EVP_PKEY_new();
        ok = pkey && EVP_PKEY_assign_EC_KEY(pkey, ec) == 1;
        if (ok) {
            ec = nullptr; // ownership moved into pkey
            kp.pkey = pkey;
        } else if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
    if (ec)
        EC_KEY_free(ec);
    if (pub)
        EC_POINT_free(pub);
    if (d)
        BN_free(d);
#pragma clang diagnostic pop
    if (!ok)
        return ErrorOr<HandshakeKeyPair>::error(hs_err("priv import"));
    return ErrorOr<HandshakeKeyPair>::ok(std::move(kp));
}

ErrorOr<Handshake::ClientStart>
Handshake::start_client(std::string caller_bundle_id, std::string priv_hex, std::string nonce_hex) {
    ClientStart start;
    if (priv_hex.empty()) {
        auto kp = generate_keypair();
        if (kp.is_error())
            return ErrorOr<ClientStart>::error(kp.error());
        start.keypair = std::move(kp.value());
    } else {
        auto kp = keypair_from_private_hex(priv_hex);
        if (kp.is_error())
            return ErrorOr<ClientStart>::error(kp.error());
        start.keypair = std::move(kp.value());
    }

    auto pub = public_hex(static_cast<EVP_PKEY*>(start.keypair.pkey));
    if (pub.is_error())
        return ErrorOr<ClientStart>::error(pub.error());
    start.hello.caller_bundle_id = std::move(caller_bundle_id);
    start.hello.eph_pub_hex = std::move(pub.value());

    if (nonce_hex.empty()) {
        ByteBuffer nonce(16);
        if (RAND_bytes(nonce.data(), 16) != 1)
            return ErrorOr<ClientStart>::error(hs_err("rng"));
        start.hello.nonce_hex = to_hex(nonce);
    } else {
        start.hello.nonce_hex = nonce_hex;
    }
    return ErrorOr<ClientStart>::ok(std::move(start));
}

namespace {

std::mutex g_nonce_mutex;
// Insertion order is tracked alongside the lookup set so the bound evicts the
// OLDEST seen nonces — a full clear() on overflow would reopen a replay window
// for every nonce accepted before the clear.
constexpr size_t nonce_cache_capacity = 1024;
std::set<std::string> g_seen_nonces;
std::deque<std::string> g_seen_nonce_order;

bool valid_nonce_hex(std::string const& s) {
    if (s.empty() || s.size() > 128 || s.size() % 2 != 0)
        return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    }
    return true;
}

void const_time_xor(ByteBuffer const& a, ByteBuffer const& b, bool& mismatch) {
    if (a.size() != b.size()) {
        mismatch = true;
        return;
    }
    std::uint8_t acc = 0;
    for (size_t i = 0; i < a.size(); ++i)
        acc = static_cast<std::uint8_t>(acc ^ (a[i] ^ b[i]));
    if (acc != 0)
        mismatch = true;
}

} // namespace

ErrorOr<Handshake::ServerSide>
Handshake::accept_hello(HelloMsg const& hello, std::string peer_identity, std::string priv_hex) {
    // Review fixes: proto_version is a real gate (a version-mismatched peer
    // would silently corrupt every subsequent frame), hello nonces must be
    // well-formed, and a replayed nonce against this listener is refused.
    if (hello.proto_version != 1)
        return ErrorOr<ServerSide>::error(hs_err("unsupported proto_version"));
    if (!valid_nonce_hex(hello.nonce_hex))
        return ErrorOr<ServerSide>::error(hs_err("malformed nonce"));
    {
        std::lock_guard<std::mutex> lock(g_nonce_mutex);
        if (!g_seen_nonces.insert(hello.nonce_hex).second)
            return ErrorOr<ServerSide>::error(hs_err("replayed nonce"));
        g_seen_nonce_order.push_back(hello.nonce_hex);
        // Bound the cache: replay protection is best-effort across the last
        // nonce_cache_capacity hello nonces of this process, oldest evicted
        // first — never a wholesale clear (that would re-open every old nonce).
        while (g_seen_nonce_order.size() > nonce_cache_capacity) {
            g_seen_nonces.erase(g_seen_nonce_order.front());
            g_seen_nonce_order.pop_front();
        }
    }

    ServerSide server;
    if (priv_hex.empty()) {
        auto kp = generate_keypair();
        if (kp.is_error())
            return ErrorOr<ServerSide>::error(kp.error());
        server.ephemerals = std::move(kp.value());
    } else {
        auto kp = keypair_from_private_hex(priv_hex);
        if (kp.is_error())
            return ErrorOr<ServerSide>::error(kp.error());
        server.ephemerals = std::move(kp.value());
    }

    auto pub = public_hex(static_cast<EVP_PKEY*>(server.ephemerals.pkey));
    if (pub.is_error())
        return ErrorOr<ServerSide>::error(pub.error());
    server.ack.server_pub_hex = std::move(pub.value());
    server.ack.capabilities = Json::make_object();

    auto shared = ecdh(static_cast<EVP_PKEY*>(server.ephemerals.pkey), hello.eph_pub_hex);
    if (shared.is_error())
        return ErrorOr<ServerSide>::error(shared.error());

    auto transcript = transcript_hash(hello.canonical(), server.ack.canonical_without_transcript(),
                                      peer_identity);
    server.ack.transcript_hex = to_hex(transcript);

    auto key = session_key(hello, server.ack, shared.value());
    if (key.is_error())
        return ErrorOr<ServerSide>::error(key.error());
    server.key_mac = std::move(key.value());
    return ErrorOr<ServerSide>::ok(std::move(server));
}

ErrorOr<ByteBuffer> Handshake::complete_client(HelloMsg const& hello, HelloAck const& ack,
                                               HandshakeKeyPair& client_keypair,
                                               std::string const& peer_identity) {
    auto shared = ecdh(static_cast<EVP_PKEY*>(client_keypair.pkey), ack.server_pub_hex);
    if (shared.is_error())
        return ErrorOr<ByteBuffer>::error(shared.error());

    auto transcript =
        transcript_hash(hello.canonical(), ack.canonical_without_transcript(), peer_identity);
    if (to_hex(transcript) != ack.transcript_hex)
        return ErrorOr<ByteBuffer>::error(hs_err("transcript mismatch"));

    return session_key(hello, ack, shared.value());
}

ByteBuffer Handshake::confirmation_mac(ByteBuffer const& session_key, bool is_server,
                                       std::string const& hello_canonical,
                                       std::string const& ack_canonical) {
    // Domain-separated by side: the server's confirmation differs from the
    // client's for the same transcript, so neither side can replay the other.
    std::string data = is_server ? "lkb-confirm-server:" : "lkb-confirm-client:";
    data += hello_canonical;
    data += "|";
    data += ack_canonical;
    ByteBuffer data_buf(data.begin(), data.end());
    auto mac = hmac_sha256(session_key, data_buf);
    if (mac.is_error())
        return {};
    return std::move(mac.value());
}

bool Handshake::verify_confirmation(ByteBuffer const& session_key, bool is_server,
                                    std::string const& hello_canonical,
                                    std::string const& ack_canonical, ByteBuffer const& mac) {
    auto want = confirmation_mac(session_key, is_server, hello_canonical, ack_canonical);
    bool mismatch = false;
    const_time_xor(want, mac, mismatch);
    return !mismatch;
}

void Handshake::reset_nonce_cache_for_tests() {
    std::lock_guard<std::mutex> lock(g_nonce_mutex);
    g_seen_nonces.clear();
    g_seen_nonce_order.clear();
}

} // namespace lkb
