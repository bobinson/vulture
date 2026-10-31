// Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
// inline constexpr constants and a string_view table NAME outcomes; a switch arm or a
// guard that returns one is the decision. Every identifier is invented.
// HELD-OUT-TOKENS: constexpr, inline, string_view
#include <string_view>

inline constexpr int Unauthorized = 401; // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)
constexpr std::string_view Forbidden = "forbidden"; // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)

int status_for(const Session& session, const Door& door) {
    if (!session.signed_in()) {
        return Unauthorized; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    }
    switch (door.clearance_against(session)) {
        case Clearance::Below: return Unauthorized; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    }
    return 200;
}
