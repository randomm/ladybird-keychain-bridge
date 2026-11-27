#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>

#include "SecItemKeychainBackend.h"

#include <cstdio>

namespace lkb {

namespace {

CFStringRef cf(std::string const& s)
{
    return CFStringCreateWithCString(nullptr, s.c_str(), kCFStringEncodingUTF8);
}

Error error_from(OSStatus status, std::string_view where)
{
    ErrorCode code = ErrorCode::UnexpectedData;
    switch (status) {
    case errSecItemNotFound:
        code = ErrorCode::NotFound;
        break;
    case errSecInteractionNotAllowed:
        code = ErrorCode::InteractionNotAllowed;
        break;
    case errSecAuthFailed:
    case errSecPkcs12VerifyFailure:
        code = ErrorCode::AuthFailed;
        break;
    case errSecNoSuchKeychain:
        code = ErrorCode::IO;
        break;
    }
    char buf[96];
    snprintf(buf, sizeof(buf), "%.*s: OSStatus %d", static_cast<int>(where.size()), where.data(),
        static_cast<int>(status));
    return Error { code, std::string(buf) };
}

}

ErrorOr<SecItemKeychainBackend> SecItemKeychainBackend::create(std::string service, std::string account,
    std::optional<std::string> keychain_path)
{
    SecItemKeychainBackend backend;
    backend.m_service = std::move(service);
    backend.m_account = std::move(account);

    if (keychain_path) {
        SecKeychainRef kc = nullptr;
        OSStatus status = SecKeychainOpen(keychain_path->c_str(), &kc);
        if (status != noErr || !kc)
            return ErrorOr<SecItemKeychainBackend>::error(error_from(status, "SecKeychainOpen"));
        backend.m_keychain = kc; // retained by SecKeychainOpen's out param
    }
    return ErrorOr<SecItemKeychainBackend>::ok(std::move(backend));
}

SecItemKeychainBackend::~SecItemKeychainBackend()
{
    if (m_keychain)
        CFRelease(static_cast<SecKeychainRef>(m_keychain));
}

SecItemKeychainBackend::SecItemKeychainBackend(SecItemKeychainBackend&& other) noexcept
    : m_service(std::move(other.m_service))
    , m_account(std::move(other.m_account))
    , m_keychain(other.m_keychain)
{
    other.m_keychain = nullptr;
}

SecItemKeychainBackend& SecItemKeychainBackend::operator=(SecItemKeychainBackend&& other) noexcept
{
    if (this != &other) {
        if (m_keychain)
            CFRelease(static_cast<SecKeychainRef>(m_keychain));
        m_service = std::move(other.m_service);
        m_account = std::move(other.m_account);
        m_keychain = other.m_keychain;
        other.m_keychain = nullptr;
    }
    return *this;
}

void fill_base(CFMutableDictionaryRef query, std::string const& service_str,
    std::string const& account_str, void* keychain)
{
    CFStringRef service = cf(service_str);
    CFStringRef account = cf(account_str);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service);
    CFDictionarySetValue(query, kSecAttrAccount, account);
    if (keychain)
        CFDictionarySetValue(query, kSecUseKeychain, static_cast<SecKeychainRef>(keychain));
    CFRelease(service);
    CFRelease(account);
}

ErrorOr<ByteBuffer> SecItemKeychainBackend::read_master_key()
{
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    fill_base(query, m_service, m_account, m_keychain);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);

    if (status != noErr)
        return ErrorOr<ByteBuffer>::error(error_from(status, "SecItemCopyMatching"));
    if (!result || CFGetTypeID(result) != CFDataGetTypeID()) {
        if (result)
            CFRelease(result);
        return ErrorOr<ByteBuffer>::error({ ErrorCode::UnexpectedData, "master key not CFData" });
    }
    auto* data = static_cast<CFDataRef>(result);
    ByteBuffer key;
    key.assign(CFDataGetBytePtr(data), CFDataGetBytePtr(data) + CFDataGetLength(data));
    CFRelease(result);
    return ErrorOr<ByteBuffer>::ok(std::move(key));
}

ErrorOr<void> SecItemKeychainBackend::write_master_key(ByteBuffer const& key, Accessibility)
{
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    fill_base(attrs, m_service, m_account, m_keychain);

    CFDataRef data = CFDataCreate(nullptr, key.data(), static_cast<CFIndex>(key.size()));
    CFMutableDictionaryRef update = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(update, kSecValueData, data);

    OSStatus status = SecItemUpdate(attrs, update);
    if (status == errSecItemNotFound) {
        CFDictionarySetValue(attrs, kSecValueData, data);
        CFDictionarySetValue(attrs, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);
        status = SecItemAdd(attrs, nullptr);
    }
    CFRelease(update);
    CFRelease(data);
    CFRelease(attrs);

    if (status != noErr)
        return ErrorOr<void>::error(error_from(status, "SecItemUpdate/Add"));
    return ErrorOr<void>::ok();
}

bool SecItemKeychainBackend::is_available()
{
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    fill_base(query, m_service, m_account, m_keychain);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (result)
        CFRelease(result);

    // Item present, absent (NotFound) => reachable. Locked/unlockable or missing
    // keychain => unavailable, surfaced honestly.
    return status != errSecInteractionNotAllowed && status != errSecNoSuchKeychain;
}

}
