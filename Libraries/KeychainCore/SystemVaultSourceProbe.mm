// M10 system-mediated surface probes (plan Task 16). Runtime class presence +
// OS availability floors only — no prompts, no signing-dependent calls, no
// keychain access. Behaviour beyond presence is validated solely by the
// owner-run signed matrix (spec §7).
#import <Foundation/Foundation.h>

#include <dlfcn.h>

#include "SystemVaultSourceProbe.h"

namespace lkb {

char const* to_string(ProbeState state) {
    switch (state) {
    case ProbeState::Available:
        return "available";
    case ProbeState::UnvalidatedAdhoc:
        return "unvalidated_adhoc";
    case ProbeState::UnavailableSystemVersion:
        return "unavailable_system_version";
    case ProbeState::UnavailableUnsigned:
        return "unavailable_unsigned";
    case ProbeState::UnavailableAbsent:
        return "unavailable_absent";
    }
    return "unknown";
}

AsProbeResults probe_authorization_apis() {
    AsProbeResults r;

    NSOperatingSystemVersion os = [[NSProcessInfo processInfo] operatingSystemVersion];
    auto at_least = [&](int major, int minor) {
        if (os.majorVersion != major)
            return os.majorVersion > major;
        return os.minorVersion >= minor;
    };
    // AuthenticationServices is lazily loaded: without this, NSClassFromString
    // answers nil for classes that exist, which would be reported as absent.
    dlopen("/System/Library/Frameworks/AuthenticationServices.framework/"
           "AuthenticationServices",
           RTLD_LAZY);

    auto class_present = [](char const* name) {
        return NSClassFromString([NSString stringWithUTF8String:name]) != nil;
    };

    // ASAuthorizationPasswordProvider — macOS 10.15+. Present here, but the
    // autofill mediation flow cannot be exercised from an unsigned ad-hoc CLI.
    if (!at_least(10, 15))
        r.password_provider = ProbeState::UnavailableSystemVersion;
    else if (class_present("ASAuthorizationPasswordProvider"))
        r.password_provider = ProbeState::UnvalidatedAdhoc;

    // ASAuthorizationWebBrowserPublicKeyCredentialManager — macOS 13.3+, but
    // usable only by an app registered as a browser (signing/entitlements this
    // build lacks): present-but-unsigned is its own honest state.
    if (!at_least(13, 3))
        r.passkey_manager = ProbeState::UnavailableSystemVersion;
    else if (class_present("ASAuthorizationWebBrowserPublicKeyCredentialManager"))
        r.passkey_manager = ProbeState::UnavailableUnsigned;

    // Credential Exchange Protocol manager — availability class, if any, is not
    // documented for direct use; presence-checked only.
    if (class_present("ASAuthorizationCXPManager"))
        r.cxp_manager = ProbeState::UnvalidatedAdhoc;

    // ASDeliveredVerificationCodesManager — macOS 27+; caller gating is
    // undocumented, so even presence stays unvalidated (spec: probe-only).
    if (!at_least(27, 0))
        r.delivered_codes = ProbeState::UnavailableSystemVersion;
    else if (class_present("ASDeliveredVerificationCodesManager"))
        r.delivered_codes = ProbeState::UnvalidatedAdhoc;

    return r;
}

} // namespace lkb
