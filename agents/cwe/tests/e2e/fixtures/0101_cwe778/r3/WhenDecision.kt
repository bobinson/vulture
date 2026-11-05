// Feature 0101, CWE-778 Concept B (RED round 2, R2-3). Only a LITERAL left-hand
// side (`401 -> Reason.UNAUTHORIZED`) maps a code to a name. A condition, an
// enum member or `else` on the left decides the outcome. Invented identifiers.
class AccessGate {
    fun decide(user: User): HttpStatusCode {
        return when {
            user.banned -> HttpStatusCode.Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
            user.anonymous -> HttpStatusCode.Unauthorized // EXPECT: finding check=cwe.insufficient_logging.auth_decision
            else -> HttpStatusCode.OK
        }
    }

    fun decideRole(role: Role): HttpStatusCode = when (role) {
        Role.GUEST -> HttpStatusCode.Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
        Role.ADMIN -> HttpStatusCode.OK
        else -> HttpStatusCode.Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    }

    fun mapCode(code: Int): Reason = when (code) {
        401 -> Reason.UNAUTHORIZED // EXPECT: clean check=cwe.insufficient_logging.auth_decision
        403, 451 -> Reason.FORBIDDEN // EXPECT: clean check=cwe.insufficient_logging.auth_decision
        else -> Reason.OTHER
    }

    fun mapName(name: String): Reason = when (name) {
        "denied" -> Reason.FORBIDDEN // EXPECT: clean check=cwe.insufficient_logging.auth_decision
        else -> Reason.OTHER
    }
}
