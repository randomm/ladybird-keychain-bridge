#pragma once

#include <string>

namespace lkb {

// M10 (spec §6, §7): the system-mediated surfaces (ASAuthorizationPasswordProvider,
// passkey manager, Credential Exchange Protocol, delivered verification codes) are
// public APIs whose BEHAVIOUR for an unsigned/ad-hoc build is an empirical question.
// This probe records what can be established without a signed browser integration;
// "Available" is reserved for the owner-run signed matrix.
enum class ProbeState {
    Available,                // validated by the owner-run signed matrix
    UnvalidatedAdhoc,         // API present; flow not exercisable from this unsigned build
    UnavailableSystemVersion, // below the API's OS availability floor
    UnavailableUnsigned,      // present but gated on signing/entitlements this build lacks
    UnavailableAbsent,        // OS is new enough, but the class does not resolve
};

char const* to_string(ProbeState state);

struct AsProbeResults {
    ProbeState password_provider{ProbeState::UnavailableAbsent};
    ProbeState passkey_manager{ProbeState::UnavailableAbsent};
    ProbeState cxp_manager{ProbeState::UnavailableAbsent};
    ProbeState delivered_codes{ProbeState::UnavailableAbsent};
};

// Runs the runtime class/version presence probes (no prompts, no network,
// no keychain access).
AsProbeResults probe_authorization_apis();

} // namespace lkb
