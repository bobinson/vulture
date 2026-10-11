// Feature 0101 held-out (LLD 4.6), CWE-778 Concept B at the idiom level.
// A Go const block with iota NAMES outcomes; returning one after a failed check is
// the decision. Every identifier is invented.
// HELD-OUT-TOKENS: iota
package gate

type Reason int

const (
	Granted Reason = iota
	Unauthorized // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)
	Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision held-out-miss (concept: clean)
)

var reasonText = map[Reason]string{
	Unauthorized: "sign in first", // EXPECT: clean check=cwe.insufficient_logging.auth_decision
	Forbidden:    "not allowed",
}

func admit(claims Claims) Reason {
	if !claims.Valid() {
		return Unauthorized // EXPECT: finding check=cwe.insufficient_logging.auth_decision
	}
	switch claims.Tier {
	case "guest":
		return Forbidden // EXPECT: finding check=cwe.insufficient_logging.auth_decision
	}
	return Granted
}
