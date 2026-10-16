// Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
// A sealed hierarchy NAMES outcomes; takeIf/elvis choosing one is the decision.
// Every identifier is invented.
// HELD-OUT-TOKENS: sealed, takeIf

sealed interface Admission {
    data object Granted : Admission
    data object Forbidden : Admission // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)
}

fun admit(pass: Pass): Admission =
    pass.takeIf { it.isActive }?.let { Admission.Granted } ?: Admission.Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
