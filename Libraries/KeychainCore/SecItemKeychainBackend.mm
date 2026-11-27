#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#include "SecItemKeychainBackend.h"

#include <cstdio>
#include <unistd.h> // access()

namespace lkb {

namespace {

CFStringRef cf(std::string const& s) {
    return CFStringCreateWithCString(nullptr, s.c_str(), kCFStringEncodingUTF8);
}

Error error_from(OSStatus status, std::string_view where) {
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
    return Error{code, std::string(buf)};
}

} // namespace

ErrorOr<SecItemKeychainBackend>
SecItemKeychainBackend::create(std::string service, std::string account,
                               std::optional<std::string> keychain_path) {
    SecItemKeychainBackend backend;
    backend.m_service = std::move(service);
    backend.m_account = std::move(account);

    if (keychain_path) {
        // The dedicated-keychain promise is only kept if SecItemAdd can never
        // silently fall back to the default search list. Two empirical traps on
        // Darwin 27: a nonexistent path makes SecItemAdd store into the login
        // keychain, and a path naming the login keychain is plainly forbidden.
        if (keychain_path->find("login.keychain") != std::string::npos)
            return ErrorOr<SecItemKeychainBackend>::error(
                {ErrorCode::IO, "the backend never addresses the login keychain"});
        if (access(keychain_path->c_str(), F_OK) != 0)
            return ErrorOr<SecItemKeychainBackend>::error(
                {ErrorCode::IO, "dedicated keychain file does not exist (create it first)"});
        SecKeychainRef kc = nullptr;
        OSStatus status = SecKeychainOpen(keychain_path->c_str(), &kc);
        if (status != noErr || !kc)
            return ErrorOr<SecItemKeychainBackend>::error(error_from(status, "SecKeychainOpen"));
        backend.m_keychain = kc; // retained by SecKeychainOpen's out param
    }
    return ErrorOr<SecItemKeychainBackend>::ok(std::move(backend));
}

SecItemKeychainBackend::~SecItemKeychainBackend() {
    if (m_keychain)
        CFRelease(static_cast<SecKeychainRef>(m_keychain));
}

SecItemKeychainBackend::SecItemKeychainBackend(SecItemKeychainBackend&& other) noexcept
    : m_service(std::move(other.m_service)), m_account(std::move(other.m_account)),
      m_keychain(other.m_keychain) {
    other.m_keychain = nullptr;
}

SecItemKeychainBackend& SecItemKeychainBackend::operator=(SecItemKeychainBackend&& other) noexcept {
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
               std::string const& account_str) {
    CFStringRef service = cf(service_str);
    CFStringRef account = cf(account_str);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service);
    CFDictionarySetValue(query, kSecAttrAccount, account);
    CFRelease(service);
    CFRelease(account);
}

// Empirically (Darwin 27.3): SecItemCopyMatching/SecItemDelete scoped by
// kSecUseKeychain report errSecItemNotFound for items SecItemAdd stored there,
// while kSecMatchSearchList scoped to the same keychain finds them. Matching
// queries therefore scope by search list; only the add carries kSecUseKeychain.
void scope_to_keychain(CFMutableDictionaryRef query, void* keychain) {
    if (!keychain)
        return; // login keychain: the process default search list already applies
    SecKeychainRef kc = static_cast<SecKeychainRef>(keychain);
    const void* items[] = {kc};
    CFArrayRef list = CFArrayCreate(nullptr, items, 1, &kCFTypeArrayCallBacks);
    CFDictionarySetValue(query, kSecMatchSearchList, list);
    CFRelease(list);
}

ErrorOr<ByteBuffer> SecItemKeychainBackend::read_master_key() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    fill_base(query, m_service, m_account);
    scope_to_keychain(query, m_keychain);
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
        return ErrorOr<ByteBuffer>::error({ErrorCode::UnexpectedData, "master key not CFData"});
    }
    auto* data = static_cast<CFDataRef>(result);
    ByteBuffer key;
    key.assign(CFDataGetBytePtr(data), CFDataGetBytePtr(data) + CFDataGetLength(data));
    CFRelease(result);
    return ErrorOr<ByteBuffer>::ok(std::move(key));
}

ErrorOr<void> SecItemKeychainBackend::write_master_key(ByteBuffer const& key, Accessibility) {
    CFMutableDictionaryRef match = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    fill_base(match, m_service, m_account);
    scope_to_keychain(match, m_keychain);

    CFDataRef data = CFDataCreate(nullptr, key.data(), static_cast<CFIndex>(key.size()));
    CFMutableDictionaryRef update = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(update, kSecValueData, data);

    OSStatus status = SecItemUpdate(match, update);
    if (status == errSecItemNotFound) {
        // Did an item with this identity already exist outside the dedicated
        // keychain? Only an add we caused may be undone below.
        bool foreign_preexisting = false;
        if (m_keychain) {
            CFMutableDictionaryRef pre = CFDictionaryCreateMutable(
                nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            fill_base(pre, m_service, m_account);
            CFDictionarySetValue(pre, kSecMatchLimit, kSecMatchLimitOne);
            foreign_preexisting = SecItemCopyMatching(pre, nullptr) == noErr;
            CFRelease(pre);
        }
        CFMutableDictionaryRef add = CFDictionaryCreateMutable(
            nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        fill_base(add, m_service, m_account);
        if (m_keychain)
            CFDictionarySetValue(add, kSecUseKeychain, static_cast<SecKeychainRef>(m_keychain));
        CFDictionarySetValue(add, kSecValueData, data);
        CFDictionarySetValue(add, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);
        status = SecItemAdd(add, nullptr);
        CFRelease(add);
        // Belt and braces: SecItemAdd can report noErr while storing into the
        // default search list (observed with an unusable kSecUseKeychain). If
        // the item is not visible in the scoped search list, the add landed
        // somewhere else — undo it and fail closed rather than trust fallback.
        if (status == noErr && m_keychain) {
            CFMutableDictionaryRef check = CFDictionaryCreateMutable(
                nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            fill_base(check, m_service, m_account);
            scope_to_keychain(check, m_keychain);
            CFDictionarySetValue(check, kSecReturnData, kCFBooleanTrue);
            CFDictionarySetValue(check, kSecMatchLimit, kSecMatchLimitOne);
            CFTypeRef seen = nullptr;
            OSStatus visible = SecItemCopyMatching(check, &seen);
            if (seen)
                CFRelease(seen);
            CFRelease(check);
            if (visible != noErr) {
                // Never delete an item that existed before our add: undo only
                // what this call can prove it caused.
                if (!foreign_preexisting) {
                    CFMutableDictionaryRef undo =
                        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                                  &kCFTypeDictionaryValueCallBacks);
                    fill_base(undo, m_service, m_account);
                    SecItemDelete(undo); // unscoped: remove wherever it actually landed
                    CFRelease(undo);
                }
                return ErrorOr<void>::error(
                    {ErrorCode::IO, "SecItemAdd fell back to the default keychain — refused"});
            }
        }
    }
    CFRelease(update);
    CFRelease(data);
    CFRelease(match);

    if (status != noErr)
        return ErrorOr<void>::error(error_from(status, "SecItemUpdate/Add"));
    return ErrorOr<void>::ok();
}

ErrorOr<void> SecItemKeychainBackend::delete_master_key() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    fill_base(query, m_service, m_account);
    scope_to_keychain(query, m_keychain);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);

    if (status != noErr && status != errSecItemNotFound)
        return ErrorOr<void>::error(error_from(status, "SecItemDelete"));
    return ErrorOr<void>::ok();
}

bool SecItemKeychainBackend::is_available() {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    fill_base(query, m_service, m_account);
    scope_to_keychain(query, m_keychain);
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

} // namespace lkb
