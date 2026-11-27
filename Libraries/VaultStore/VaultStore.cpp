#include "VaultStore.h"

#include "AesGcm.h"
#include "Hkdf.h"

#include <ctime>

namespace lkb {

namespace {

Error db_error(std::string_view what) {
    return Error{ErrorCode::Database, std::string(what)};
}

void put_u32(ByteBuffer& out, std::uint32_t v) {
    out.insert(out.end(), {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16),
                           static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)});
}

bool get_u32(ByteBuffer const& in, size_t& pos, std::uint32_t& out) {
    if (pos + 4 > in.size())
        return false;
    out = static_cast<std::uint32_t>(in[pos]) << 24 |
          static_cast<std::uint32_t>(in[pos + 1]) << 16 |
          static_cast<std::uint32_t>(in[pos + 2]) << 8 | in[pos + 3];
    pos += 4;
    return true;
}

bool get_bytes(ByteBuffer const& in, size_t& pos, ByteBuffer& out) {
    std::uint32_t len = 0;
    if (!get_u32(in, pos, len) || pos + len > in.size())
        return false;
    out.assign(in.begin() + static_cast<long>(pos), in.begin() + static_cast<long>(pos + len));
    pos += len;
    return true;
}

ByteBuffer serialize_record(CredentialRecord const& r) {
    ByteBuffer out;
    put_u32(out, static_cast<std::uint32_t>(r.username.size()));
    out.insert(out.end(), r.username.begin(), r.username.end());
    put_u32(out, static_cast<std::uint32_t>(r.secret.size()));
    out.insert(out.end(), r.secret.begin(), r.secret.end());
    put_u32(out, static_cast<std::uint32_t>(r.extra_fields.size()));
    for (auto& [k, v] : r.extra_fields) {
        put_u32(out, static_cast<std::uint32_t>(k.size()));
        out.insert(out.end(), k.begin(), k.end());
        put_u32(out, static_cast<std::uint32_t>(v.size()));
        out.insert(out.end(), v.begin(), v.end());
    }
    out.push_back(r.form_meta ? 1 : 0);
    if (r.form_meta) {
        put_u32(out, static_cast<std::uint32_t>(r.form_meta->size()));
        out.insert(out.end(), r.form_meta->begin(), r.form_meta->end());
    }
    return out;
}

bool deserialize_record(ByteBuffer const& in, CredentialRecord& r) {
    size_t pos = 0;
    ByteBuffer username, secret;
    if (!get_bytes(in, pos, username) || !get_bytes(in, pos, secret))
        return false;
    r.username.assign(username.begin(), username.end());
    r.secret = std::move(secret);
    std::uint32_t count = 0;
    if (!get_u32(in, pos, count))
        return false;
    for (std::uint32_t i = 0; i < count; ++i) {
        ByteBuffer k, v;
        if (!get_bytes(in, pos, k) || !get_bytes(in, pos, v))
            return false;
        r.extra_fields[std::string(k.begin(), k.end())] = std::string(v.begin(), v.end());
    }
    if (pos + 1 > in.size())
        return false;
    if (in[pos++] == 1) {
        ByteBuffer meta;
        if (!get_bytes(in, pos, meta))
            return false;
        r.form_meta = std::string(meta.begin(), meta.end());
    }
    return pos == in.size();
}

} // namespace

ErrorOr<VaultStore> VaultStore::open(std::string db_path, ByteBuffer master_key) {
    if (master_key.size() != 16 && master_key.size() != 32)
        return ErrorOr<VaultStore>::error(db_error("bad master key size"));

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("sqlite open"));
    }

    char* err = nullptr;
    auto exec = [&](char const* sql) {
        return sqlite3_exec(db, sql, nullptr, nullptr, &err) == SQLITE_OK;
    };
    if (!exec("PRAGMA journal_mode=WAL;") || !exec("PRAGMA foreign_keys=ON;")) {
        sqlite3_free(err);
        sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("pragmas"));
    }

    int version = 0;
    if (sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW)
            version = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (version > 1) {
        sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("vault schema too new"));
    }
    if (!exec("CREATE TABLE IF NOT EXISTS credentials("
              "id INTEGER PRIMARY KEY, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT "
              "NULL,"
              "blob BLOB NOT NULL, created INTEGER NOT NULL, last_used INTEGER NOT NULL, updated "
              "INTEGER NOT NULL);")) {
        sqlite3_free(err);
        sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("create table"));
    }
    if (!exec("CREATE TABLE IF NOT EXISTS never_saved("
              "scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,"
              "PRIMARY KEY (scheme, host, port));")) {
        sqlite3_free(err);
        sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("create never_saved"));
    }
    if (version == 0 && !exec("PRAGMA user_version=1;")) {
        sqlite3_free(err);
        sqlite3_close(db);
        return ErrorOr<VaultStore>::error(db_error("user_version"));
    }

    VaultStore store;
    store.m_db = db;
    store.m_master_key = std::move(master_key);
    return ErrorOr<VaultStore>::ok(std::move(store));
}

VaultStore::~VaultStore() {
    if (m_db)
        sqlite3_close(m_db);
}

VaultStore::VaultStore(VaultStore&& other) noexcept
    : m_db(other.m_db), m_master_key(std::move(other.m_master_key)) {
    other.m_db = nullptr;
}

VaultStore& VaultStore::operator=(VaultStore&& other) noexcept {
    if (this != &other) {
        if (m_db)
            sqlite3_close(m_db);
        m_db = other.m_db;
        m_master_key = std::move(other.m_master_key);
        other.m_db = nullptr;
    }
    return *this;
}

ErrorOr<ByteBuffer> VaultStore::encrypt_record(CredentialRecord const& record) const {
    auto origin_str = record.origin.serialize();
    ByteBuffer aad(origin_str.begin(), origin_str.end());
    ByteBuffer salt{'l', 'k', 'b', '-', 'v', 'a', 'u', 'l', 't', '-', 'v', '1'};
    auto derived = hkdf_sha256(m_master_key, salt, aad, 32);
    if (derived.is_error())
        return ErrorOr<ByteBuffer>::error(derived.error());
    auto payload = serialize_record(record);
    auto enc = AesGcm::encrypt(derived.value(), payload, aad);
    if (enc.is_error())
        return ErrorOr<ByteBuffer>::error(enc.error());
    ByteBuffer blob = std::move(enc.value().nonce);
    blob.insert(blob.end(), enc.value().ciphertext.begin(), enc.value().ciphertext.end());
    return ErrorOr<ByteBuffer>::ok(std::move(blob));
}

ErrorOr<CredentialRecord> VaultStore::decrypt_record(Origin origin, ByteBuffer const& blob,
                                                     std::int64_t created, std::int64_t last_used,
                                                     std::int64_t updated) const {
    if (blob.size() < 12 + 16)
        return ErrorOr<CredentialRecord>::error({ErrorCode::UnexpectedData, "blob too short"});
    auto origin_str = origin.serialize();
    ByteBuffer aad(origin_str.begin(), origin_str.end());
    ByteBuffer salt{'l', 'k', 'b', '-', 'v', 'a', 'u', 'l', 't', '-', 'v', '1'};
    auto derived = hkdf_sha256(m_master_key, salt, aad, 32);
    if (derived.is_error())
        return ErrorOr<CredentialRecord>::error(derived.error());
    ByteBuffer nonce(blob.begin(), blob.begin() + 12);
    ByteBuffer ct(blob.begin() + 12, blob.end());
    auto plain = AesGcm::decrypt(derived.value(), nonce, ct, aad);
    if (plain.is_error())
        return plain.is_error()
                   ? ErrorOr<CredentialRecord>::error({ErrorCode::UnexpectedData, "decrypt failed"})
                   : ErrorOr<CredentialRecord>::error(plain.error());

    CredentialRecord record;
    record.origin = origin;
    record.created = created;
    record.last_used = last_used;
    record.updated = updated;
    if (!deserialize_record(plain.value(), record))
        return ErrorOr<CredentialRecord>::error({ErrorCode::UnexpectedData, "malformed payload"});
    return ErrorOr<CredentialRecord>::ok(std::move(record));
}

namespace {

sqlite3_stmt* prepare_or_null(sqlite3* db, char const* sql) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    return stmt;
}

void bind_origin(sqlite3_stmt* stmt, int& idx, Origin const& origin) {
    sqlite3_bind_text(stmt, idx++, origin.scheme.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, origin.host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx++, origin.port);
}

} // namespace

ErrorOr<std::vector<Match>> VaultStore::find(Origin const& origin,
                                             std::optional<std::string_view> username_hint) {
    sqlite3_stmt* stmt =
        prepare_or_null(m_db, "SELECT id, blob, created, last_used, updated FROM credentials"
                              " WHERE scheme=? AND host=? AND port=?;");
    if (!stmt)
        return ErrorOr<std::vector<Match>>::error(db_error("prepare find"));

    std::vector<Match> matches;
    int idx = 1;
    bind_origin(stmt, idx, origin);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto id = sqlite3_column_int64(stmt, 0);
        auto const* data = static_cast<std::uint8_t const*>(sqlite3_column_blob(stmt, 1));
        int len = sqlite3_column_bytes(stmt, 1);
        ByteBuffer blob(data, data + len);
        auto rec = decrypt_record(origin, blob, sqlite3_column_int64(stmt, 2),
                                  sqlite3_column_int64(stmt, 3), sqlite3_column_int64(stmt, 4));
        if (rec.is_error())
            continue; // exact-origin matches must be authentic; corrupted rows never surface
        if (username_hint && *username_hint != rec.value().username)
            continue;
        matches.push_back({id, std::move(rec.value())});
    }
    sqlite3_finalize(stmt);
    return ErrorOr<std::vector<Match>>::ok(std::move(matches));
}

ErrorOr<void> VaultStore::put(CredentialRecord const& record) {
    auto blob = encrypt_record(record);
    if (blob.is_error())
        return ErrorOr<void>::error(blob.error());

    // Upsert by (origin, username): decrypt the origin's rows and compare.
    sqlite3_stmt* scan = prepare_or_null(
        m_db, "SELECT id, blob FROM credentials WHERE scheme=? AND host=? AND port=?;");
    if (!scan)
        return ErrorOr<void>::error(db_error("prepare put scan"));
    std::int64_t existing_id = -1;
    {
        int idx = 1;
        bind_origin(scan, idx, record.origin);
        while (sqlite3_step(scan) == SQLITE_ROW) {
            auto const* data = static_cast<std::uint8_t const*>(sqlite3_column_blob(scan, 1));
            int len = sqlite3_column_bytes(scan, 1);
            ByteBuffer row_blob(data, data + len);
            auto candidate = decrypt_record(record.origin, row_blob, 0, 0, 0);
            if (!candidate.is_error() && candidate.value().username == record.username) {
                existing_id = sqlite3_column_int64(scan, 0);
                break;
            }
        }
    }
    sqlite3_finalize(scan);

    if (existing_id >= 0) {
        sqlite3_stmt* upd =
            prepare_or_null(m_db, "UPDATE credentials SET blob=?, updated=? WHERE id=?;");
        if (!upd)
            return ErrorOr<void>::error(db_error("prepare put update"));
        sqlite3_bind_blob(upd, 1, blob.value().data(), static_cast<int>(blob.value().size()),
                          SQLITE_TRANSIENT);
        auto upd_now = static_cast<std::int64_t>(std::time(nullptr));
        sqlite3_bind_int64(upd, 2, record.updated > 0 ? record.updated : upd_now);
        sqlite3_bind_int64(upd, 3, existing_id);
        int rc = sqlite3_step(upd);
        sqlite3_finalize(upd);
        if (rc != SQLITE_DONE)
            return ErrorOr<void>::error(db_error("put update"));
        return ErrorOr<void>::ok();
    }

    sqlite3_stmt* ins = prepare_or_null(
        m_db, "INSERT INTO credentials(scheme,host,port,blob,created,last_used,updated) "
              "VALUES(?,?,?,?,?,?,?);");
    if (!ins)
        return ErrorOr<void>::error(db_error("prepare put insert"));
    int idx = 1;
    sqlite3_bind_text(ins, idx++, record.origin.scheme.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, idx++, record.origin.host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(ins, idx++, record.origin.port);
    sqlite3_bind_blob(ins, idx++, blob.value().data(), static_cast<int>(blob.value().size()),
                      SQLITE_TRANSIENT);
    auto now = static_cast<std::int64_t>(std::time(nullptr));
    sqlite3_bind_int64(ins, idx++, record.created > 0 ? record.created : now);
    sqlite3_bind_int64(ins, idx++, record.last_used);
    sqlite3_bind_int64(ins, idx++, record.updated > 0 ? record.updated : now);
    int rc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (rc != SQLITE_DONE)
        return ErrorOr<void>::error(db_error("put insert"));
    return ErrorOr<void>::ok();
}

ErrorOr<void> VaultStore::mark_never(Origin const& origin) {
    sqlite3_stmt* stmt = prepare_or_null(
        m_db, "INSERT OR REPLACE INTO never_saved(scheme, host, port) VALUES(?,?,?);");
    if (!stmt)
        return ErrorOr<void>::error(db_error("prepare mark_never"));
    int idx = 1;
    bind_origin(stmt, idx, origin);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return ErrorOr<void>::error(db_error("mark_never"));
    return ErrorOr<void>::ok();
}

ErrorOr<bool> VaultStore::is_never(Origin const& origin) {
    sqlite3_stmt* stmt =
        prepare_or_null(m_db, "SELECT 1 FROM never_saved WHERE scheme=? AND host=? AND port=?;");
    if (!stmt)
        return ErrorOr<bool>::error(db_error("prepare is_never"));
    int idx = 1;
    bind_origin(stmt, idx, origin);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return ErrorOr<bool>::ok(found);
}

ErrorOr<void> VaultStore::unmark_never(Origin const& origin) {
    sqlite3_stmt* stmt =
        prepare_or_null(m_db, "DELETE FROM never_saved WHERE scheme=? AND host=? AND port=?;");
    if (!stmt)
        return ErrorOr<void>::error(db_error("prepare unmark_never"));
    int idx = 1;
    bind_origin(stmt, idx, origin);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return ErrorOr<void>::error(db_error("unmark_never"));
    return ErrorOr<void>::ok();
}

ErrorOr<void> VaultStore::remove_credential(std::int64_t id) {
    sqlite3_stmt* stmt = prepare_or_null(m_db, "DELETE FROM credentials WHERE id=?;");
    if (!stmt)
        return ErrorOr<void>::error(db_error("prepare remove_credential"));
    sqlite3_bind_int64(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return ErrorOr<void>::error(db_error("remove_credential"));
    return ErrorOr<void>::ok();
}

ErrorOr<std::vector<CredentialRecord>> VaultStore::all(size_t& out_undecodable) {
    out_undecodable = 0;
    sqlite3_stmt* stmt = prepare_or_null(
        m_db, "SELECT scheme, host, port, blob, created, last_used, updated FROM credentials;");
    if (!stmt)
        return ErrorOr<std::vector<CredentialRecord>>::error(db_error("prepare all"));

    std::vector<CredentialRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Origin origin;
        origin.scheme = reinterpret_cast<char const*>(sqlite3_column_text(stmt, 0));
        origin.host = reinterpret_cast<char const*>(sqlite3_column_text(stmt, 1));
        origin.port = static_cast<std::uint16_t>(sqlite3_column_int(stmt, 2));
        auto const* data = static_cast<std::uint8_t const*>(sqlite3_column_blob(stmt, 3));
        int len = sqlite3_column_bytes(stmt, 3);
        ByteBuffer blob(data, data + len);
        // Reconstruct has_explicit_port: stored port differs from scheme default,
        // or serialize() must round-trip for the stored (scheme,host,port) triple.
        origin.has_explicit_port = true;
        auto rec = decrypt_record(origin, blob, sqlite3_column_int64(stmt, 4),
                                  sqlite3_column_int64(stmt, 5), sqlite3_column_int64(stmt, 6));
        if (rec.is_error()) {
            ++out_undecodable;
            continue;
        }
        records.push_back(std::move(rec.value()));
    }
    sqlite3_finalize(stmt);
    return ErrorOr<std::vector<CredentialRecord>>::ok(std::move(records));
}

ErrorOr<void> VaultStore::remove_origin(Origin const& origin) {
    sqlite3_stmt* stmt =
        prepare_or_null(m_db, "DELETE FROM credentials WHERE scheme=? AND host=? AND port=?;");
    if (!stmt)
        return ErrorOr<void>::error(db_error("prepare remove_origin"));
    int idx = 1;
    bind_origin(stmt, idx, origin);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return ErrorOr<void>::error(db_error("remove_origin"));
    return ErrorOr<void>::ok();
}

} // namespace lkb
