// Feature 0101, CWE-778 Concept B in Swift. Invented identifiers.
func route(_ r: Reason, completion: (Bool) -> Void) {
    switch r {
    case .unauthorized: completion(false) // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    default: completion(true)
    }
}
