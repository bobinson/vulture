package egress

// configSelector is the P0 model selector (§7/§25.2): config-driven, no
// magicrouter. The request's model_hint wins when present; otherwise the
// operator-configured primary is used, followed by a fixed fallback chain.
// Policy/residency is a no-op in P0 (single region "local").
type configSelector struct {
	primary   string
	fallbacks []string
}

// NewConfigSelector builds the P0 selector from the configured primary model
// (VULTURE_LLM_MODEL) and optional fallback chain (VULTURE_LLM_FALLBACKS).
func NewConfigSelector(primary string, fallbacks []string) ModelSelector {
	return &configSelector{primary: primary, fallbacks: fallbacks}
}

// Select resolves the model + fallback chain. A non-empty modelHint is
// authoritative (it is the model the agent's SDK asked for); otherwise the
// configured primary is used. The fallback chain is the configured one with
// the chosen primary removed so it never appears twice.
func (s *configSelector) Select(modelHint string, _ PolicyContext) (*ModelSelection, error) {
	primary := modelHint
	if primary == "" {
		primary = s.primary
	}
	fallbacks := make([]string, 0, len(s.fallbacks))
	for _, f := range s.fallbacks {
		if f != "" && f != primary {
			fallbacks = append(fallbacks, f)
		}
	}
	return &ModelSelection{Model: primary, Fallbacks: fallbacks}, nil
}

var _ ModelSelector = (*configSelector)(nil)
