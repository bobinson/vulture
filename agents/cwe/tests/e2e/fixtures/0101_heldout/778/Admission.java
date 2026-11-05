// Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
// A sealed interface with permitted records NAMES outcomes; a switch-expression arm
// that yields one is the decision. Every identifier is invented.
// HELD-OUT-TOKENS: sealed, permits

sealed interface Admission permits Granted, Forbidden {} // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)

final class Forbidden implements Admission {} // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)

class Turnstile {
    Admission admit(Badge badge) {
        return switch (badge.tier()) {
            case STAFF -> new Granted();
            case VISITOR -> new Forbidden(); // EXPECT: finding check=cwe.insufficient_logging.auth_decision
        };
    }
}
