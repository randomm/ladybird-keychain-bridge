#pragma once

#include "KeychainBackend.h"

#include <optional>

namespace lkb {

class FakeKeychainBackend : public KeychainBackend {
public:
    ErrorOr<ByteBuffer> read_master_key() override
    {
        ++m_reads;
        if (m_read_error)
            return ErrorOr<ByteBuffer>::error({ to_error_code(*m_read_error), "injected read error" });
        if (!m_stored)
            return ErrorOr<ByteBuffer>::error({ ErrorCode::NotFound, "absent" });
        return ErrorOr<ByteBuffer>::ok(*m_stored);
    }

    ErrorOr<void> write_master_key(ByteBuffer const& key, Accessibility) override
    {
        ++m_writes;
        if (m_write_error)
            return ErrorOr<void>::error({ to_error_code(*m_write_error), "injected write error" });
        m_stored = key;
        return ErrorOr<void>::ok();
    }

    bool is_available() override { return m_available; }

    void set_read_error(std::optional<KeychainError> e) { m_read_error = e; }
    void set_write_error(std::optional<KeychainError> e) { m_write_error = e; }
    void set_stored(ByteBuffer b) { m_stored = std::move(b); }
    void set_available(bool a) { m_available = a; }
    std::optional<ByteBuffer> const& stored() const { return m_stored; }
    int read_count() const { return m_reads; }
    int write_count() const { return m_writes; }

private:
    std::optional<ByteBuffer> m_stored;
    std::optional<KeychainError> m_read_error;
    std::optional<KeychainError> m_write_error;
    bool m_available { true };
    int m_reads { 0 };
    int m_writes { 0 };
};

}
