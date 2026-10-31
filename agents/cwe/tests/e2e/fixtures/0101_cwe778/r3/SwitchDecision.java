// Feature 0101, CWE-778 Concept B (RED round 2, R2-3). A Java switch expression's
// `default ->` arm decides the outcome. Invented identifiers.
public class AccessGate {
    public Status decide(Role role) {
        return switch (role) {
            case ADMIN -> Status.OK;
            default -> Status.FORBIDDEN; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
        };
    }

    public Status decideGuest(Role role) {
        return switch (role) {
            case GUEST -> Status.FORBIDDEN; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
            default -> Status.OK;
        };
    }
}
