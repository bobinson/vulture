package egress

// NewAllowlist constructs an operator Allowlist from a set of canonical
// provider ids (VULTURE_LLM_PROVIDER_ALLOWLIST, §7). An empty set denies
// everything (fail-closed).
//
// Matching is exact and case-sensitive; an empty set denies everything.
func NewAllowlist(providers ...string) Allowlist {
	set := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		set[p] = struct{}{}
	}
	return setAllowlist(set)
}

// setAllowlist is a set-membership Allowlist.
type setAllowlist map[string]struct{}

// Allowed reports whether the provider is in the configured set.
func (s setAllowlist) Allowed(provider string) bool {
	_, ok := s[provider]
	return ok
}
