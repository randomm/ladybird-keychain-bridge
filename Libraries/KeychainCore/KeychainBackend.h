#pragma once

#include "ByteBuffer.h"
#include "ErrorOr.h"

namespace lkb {

enum class KeychainError {
    NotFound,
    InteractionNotAllowed,
    AuthFailed,
    UnexpectedData,
};

enum class Accessibility {
    WhenUnlocked,
};

inline ErrorCode to_error_code(KeychainError e)
{
    switch (e) {
    case KeychainError::NotFound:
        return ErrorCode::NotFound;
    case KeychainError::InteractionNotAllowed:
        return ErrorCode::InteractionNotAllowed;
    case KeychainError::AuthFailed:
        return ErrorCode::AuthFailed;
    case KeychainError::UnexpectedData:
        return ErrorCode::UnexpectedData;
    }
    return ErrorCode::Invalid;
}

// The single seam to the OS credential store. All tests use FakeKeychainBackend;
// only Apple .mm backends may touch Security.framework.
class KeychainBackend {
public:
    virtual ~KeychainBackend() = default;
    virtual ErrorOr<ByteBuffer> read_master_key() = 0;
    virtual ErrorOr<void> write_master_key(ByteBuffer const&, Accessibility) = 0;
    virtual bool is_available() = 0;
};

}
