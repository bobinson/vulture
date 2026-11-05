// Feature 0101, CWE-778 Concept B in Kotlin. Invented identifiers.
const val UNAUTHORIZED = 401 // EXPECT: clean check=cwe.insufficient_logging.auth_decision

enum class Status(val code: Int) {
    UNAUTHORIZED(401), // EXPECT: clean check=cwe.insufficient_logging.auth_decision
    OTHER(500),
}

fun reasonFor(code: Int): Reason = when (code) {
    401 -> Reason.UNAUTHORIZED // EXPECT: clean check=cwe.insufficient_logging.auth_decision
    else -> Reason.OTHER
}

enum class Reason { UNAUTHORIZED, FORBIDDEN } // EXPECT: clean check=cwe.insufficient_logging.auth_decision

data class Flags(val forbidden: Boolean) // EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: data-class field
