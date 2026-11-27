#include "CsvBridge.h"

#include "Origin.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <map>
#include <string>
#include <vector>

namespace lkb {

namespace {

struct CsvRow {
    std::vector<std::string> fields;
};

Error csv_err(std::string_view what, ErrorCode code) {
    return Error{code, std::string(what)};
}

ErrorOr<std::vector<CsvRow>> parse_csv(ByteBuffer const& input) {
    std::vector<CsvRow> rows;
    CsvRow row;
    std::string field;
    size_t i = 0;
    bool in_quotes = false;
    bool field_started_quoted = false;
    auto push_field = [&]() {
        row.fields.push_back(field);
        field.clear();
        field_started_quoted = false;
    };
    auto push_row = [&]() {
        push_field();
        rows.push_back(std::move(row));
        row = {};
        if (rows.size() > csv_max_rows + 1)
            return false;
        return true;
    };

    while (i < input.size()) {
        char c = static_cast<char>(input[i]);
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < input.size() && input[i + 1] == '"') {
                    field += '"';
                    i += 2;
                    continue;
                }
                in_quotes = false;
                ++i;
                continue;
            }
            field += c;
            ++i;
        } else if (c == '"' && field.empty() && !field_started_quoted) {
            in_quotes = true;
            field_started_quoted = true;
            ++i;
        } else if (c == ',') {
            push_field();
            ++i;
        } else if (c == '\n' || c == '\r') {
            if (c == '\r' && i + 1 < input.size() && input[i + 1] == '\n')
                ++i;
            if (!push_row())
                return ErrorOr<std::vector<CsvRow>>::error(
                    csv_err("row cap exceeded", ErrorCode::TooLarge));
            ++i;
        } else {
            if (field_started_quoted)
                return ErrorOr<std::vector<CsvRow>>::error(
                    csv_err("garbage after quoted field", ErrorCode::MalformedCsv));
            field += c;
            if (field.size() > csv_max_field_bytes)
                return ErrorOr<std::vector<CsvRow>>::error(
                    csv_err("field too large", ErrorCode::TooLarge));
            ++i;
        }
    }
    if (in_quotes)
        return ErrorOr<std::vector<CsvRow>>::error(
            csv_err("unbalanced quote", ErrorCode::MalformedCsv));
    if (!field.empty() || !row.fields.empty()) {
        if (!push_row())
            return ErrorOr<std::vector<CsvRow>>::error(
                csv_err("row cap exceeded", ErrorCode::TooLarge));
    }
    return ErrorOr<std::vector<CsvRow>>::ok(std::move(rows));
}

std::string lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool parse_i64(std::string const& s, std::int64_t& out) {
    if (s.empty() || s.size() > 19)
        return false;
    std::int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

std::string escape_formula(std::string const& text) {
    if (!text.empty()) {
        char c = text[0];
        if (c == '=' || c == '+' || c == '-' || c == '@')
            return "'" + text;
    }
    return text;
}

std::string quote_cell(std::string const& text) {
    std::string t = escape_formula(text);
    bool needs = t.find_first_of(",\"\n\r") != std::string::npos;
    if (!needs)
        return t;
    std::string out = "\"";
    for (char c : t) {
        if (c == '"')
            out += "\"\"";
        else
            out += c;
    }
    out += "\"";
    return out;
}

char const* canonical_columns[] = {"Title",    "Username",      "Password",      "URL",
                                   "Notes",    "Created",       "Last Modified", "Last Used",
                                   "Verified", "OTP Auth Token"};

bool is_canonical(std::string const& name) {
    for (auto* c : canonical_columns) {
        if (name == c)
            return true;
    }
    return false;
}

} // namespace

ErrorOr<size_t> import_csv(ByteBuffer const& csv, VaultStore& vault) {
    auto rows = parse_csv(csv);
    if (rows.is_error())
        return ErrorOr<size_t>::error(rows.error());
    auto& data = rows.value();
    if (data.empty())
        return ErrorOr<size_t>::ok(0);
    if (data.size() - 1 > csv_max_rows)
        return ErrorOr<size_t>::error(csv_err("row cap exceeded", ErrorCode::TooLarge));

    std::vector<std::string> header;
    for (auto& h : data[0].fields)
        header.push_back(lower(h));

    int col_username = -1, col_password = -1, col_url = -1;
    int col_created = -1, col_updated = -1, col_lastused = -1;
    for (size_t i = 0; i < header.size(); ++i) {
        if (header[i] == "username")
            col_username = static_cast<int>(i);
        else if (header[i] == "password")
            col_password = static_cast<int>(i);
        else if (header[i] == "url")
            col_url = static_cast<int>(i);
        else if (header[i] == "created")
            col_created = static_cast<int>(i);
        else if (header[i] == "last modified")
            col_updated = static_cast<int>(i);
        else if (header[i] == "last used")
            col_lastused = static_cast<int>(i);
    }

    size_t imported = 0;
    auto now = static_cast<std::int64_t>(std::time(nullptr));
    for (size_t r = 1; r < data.size(); ++r) {
        auto& fields = data[r].fields;
        auto cell = [&](int col) -> std::string {
            if (col < 0 || static_cast<size_t>(col) >= fields.size())
                return {};
            return fields[static_cast<size_t>(col)];
        };
        if (col_url < 0)
            continue;
        auto origin = Origin::parse(cell(col_url));
        if (origin.is_error())
            continue; // unparsable URL: row carries no credential target; extras still ignored

        CredentialRecord record;
        record.origin = std::move(origin.value());
        record.username = cell(col_username);
        auto secret = cell(col_password);
        record.secret = ByteBuffer(secret.begin(), secret.end());
        record.created = now;
        record.last_used = now;
        record.updated = now;
        parse_i64(cell(col_created), record.created);
        parse_i64(cell(col_updated), record.updated);
        parse_i64(cell(col_lastused), record.last_used);

        for (size_t c = 0; c < fields.size() && c < header.size(); ++c) {
            bool mapped = static_cast<int>(c) == col_username ||
                          static_cast<int>(c) == col_password || static_cast<int>(c) == col_url ||
                          static_cast<int>(c) == col_created ||
                          static_cast<int>(c) == col_updated || static_cast<int>(c) == col_lastused;
            bool timestamp_parsed =
                (static_cast<int>(c) == col_created || static_cast<int>(c) == col_updated ||
                 static_cast<int>(c) == col_lastused) &&
                fields[c].empty() == false;
            if (!mapped || !timestamp_parsed) {
                if (!mapped)
                    record.extra_fields[data[0].fields[c]] = fields[c];
                else if (!timestamp_parsed)
                    ; // empty timestamp column: no field, no extra (empty is re-emitted as empty)
            }
            (void)timestamp_parsed;
        }

        auto put = vault.put(record);
        if (put.is_error())
            return ErrorOr<size_t>::error(put.error());
        ++imported;
    }
    return ErrorOr<size_t>::ok(imported);
}

ErrorOr<ByteBuffer> export_csv(VaultStore& vault) {
    size_t undecodable = 0;
    auto records = vault.all(undecodable);
    if (records.is_error())
        return ErrorOr<ByteBuffer>::error(records.error());

    std::vector<std::string> header;
    for (auto* c : canonical_columns)
        header.push_back(c);
    std::vector<std::string> extra_columns;
    for (auto& r : records.value()) {
        for (auto& [k, v] : r.extra_fields) {
            if (is_canonical(k))
                continue;
            if (std::find(extra_columns.begin(), extra_columns.end(), k) == extra_columns.end())
                extra_columns.push_back(k);
        }
    }
    for (auto& e : extra_columns)
        header.push_back(e);

    auto col_of = [&](char const* name) -> int {
        for (size_t i = 0; i < header.size(); ++i) {
            if (header[i] == name)
                return static_cast<int>(i);
        }
        return -1;
    };
    int c_title = col_of("Title"), c_user = col_of("Username"), c_pass = col_of("Password");
    int c_url = col_of("URL"), c_notes = col_of("Notes"), c_created = col_of("Created");
    int c_updated = col_of("Last Modified"), c_lastused = col_of("Last Used");
    int c_verified = col_of("Verified"), c_otp = col_of("OTP Auth Token");

    std::string out;
    for (size_t i = 0; i < header.size(); ++i) {
        if (i)
            out += ',';
        out += header[i];
    }
    out += "\n";

    for (auto& r : records.value()) {
        std::vector<std::string> cells(header.size());
        auto extra = [&](std::string const& key) -> std::string {
            auto it = r.extra_fields.find(key);
            return it == r.extra_fields.end() ? std::string() : it->second;
        };
        if (c_title >= 0)
            cells[c_title] = extra("Title");
        if (c_user >= 0)
            cells[c_user] = r.username;
        if (c_pass >= 0)
            cells[c_pass] = std::string(r.secret.begin(), r.secret.end());
        if (c_url >= 0)
            cells[c_url] = r.origin.serialize();
        if (c_notes >= 0)
            cells[c_notes] = extra("Notes");
        if (c_created >= 0)
            cells[c_created] = std::to_string(r.created);
        if (c_updated >= 0)
            cells[c_updated] = std::to_string(r.updated);
        if (c_lastused >= 0)
            cells[c_lastused] = std::to_string(r.last_used);
        if (c_verified >= 0)
            cells[c_verified] = extra("Verified");
        if (c_otp >= 0)
            cells[c_otp] = extra("OTP Auth Token");
        for (size_t i = 0; i < header.size(); ++i) {
            if (!is_canonical(header[i]))
                cells[i] = extra(header[i]);
        }
        for (size_t i = 0; i < cells.size(); ++i) {
            if (i)
                out += ',';
            out += quote_cell(cells[i]);
        }
        out += "\n";
    }
    return ErrorOr<ByteBuffer>::ok(ByteBuffer(out.begin(), out.end()));
}

} // namespace lkb
