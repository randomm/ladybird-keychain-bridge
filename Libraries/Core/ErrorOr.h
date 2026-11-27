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
    IncompleteFrame,
    Handshake,
    Unauthorized,
    Database,
    IO,
};

struct Error {
    ErrorCode code { ErrorCode::Invalid };
    std::string message;
};

template<typename T>
class ErrorOr {
public:
    static ErrorOr ok(T value)
    {
        ErrorOr r;
        r.m_value = std::move(value);
        return r;
    }

    static ErrorOr error(Error e)
    {
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

}

// Statement-expression TRY, clang/gcc only (project targets clang + CI gcc).
#define TRY(expr)                                                             \
    ({                                                                        \
        auto _try_tmp = (expr);                                               \
        if (_try_tmp.is_error())                                              \
            return ::lkb::ErrorOr<decltype(_try_tmp.value())>::error(_try_tmp.error()); \
        std::move(_try_tmp).value();                                          \
    })

namespace lkb {

template<>
class ErrorOr<void> {
public:
    static ErrorOr ok() { return ErrorOr {}; }
    static ErrorOr error(Error e)
    {
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

}
