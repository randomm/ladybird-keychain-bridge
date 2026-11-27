#pragma once

#include <optional>
#include <string>
#include <utility>

namespace lkb {

enum class ErrorCode {
    Invalid,
    InvalidOrigin,
    NotFound,
    InteractionNotAllowed,
    AuthFailed,
    UnexpectedData,
    Authentication,
    TooLarge,
    MalformedCsv,
    MalformedJson,
    IncompleteFrame,
    Handshake,
    Unauthorized,
    Database,
    IO,
};

struct Error {
    ErrorCode code{ErrorCode::Invalid};
    std::string message;
};

template <typename T> class ErrorOr {
  public:
    static ErrorOr ok(T value) {
        ErrorOr r;
        r.m_value = std::move(value);
        return r;
    }

    static ErrorOr error(Error e) {
        ErrorOr r;
        r.m_error = std::move(e);
        return r;
    }

    bool is_error() const { return m_error.has_value(); }
    T& value() { return *m_value; }
    T const& value() const { return *m_value; }
    Error const& error() const { return *m_error; }

  private:
    std::optional<T> m_value;
    std::optional<Error> m_error;
};

} // namespace lkb

namespace lkb {

template <> class ErrorOr<void> {
  public:
    static ErrorOr ok() { return ErrorOr{}; }
    static ErrorOr error(Error e) {
        ErrorOr r;
        r.m_error = std::move(e);
        return r;
    }
    bool is_error() const { return m_error.has_value(); }
    Error const& error() const { return *m_error; }

  private:
    ErrorOr() = default;
    std::optional<Error> m_error;
};

} // namespace lkb
