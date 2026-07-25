package egress

import (
	"reflect"
	"testing"
)

func TestConfigSelector_HintWinsOverPrimary(t *testing.T) {
	s := NewConfigSelector("gpt-4o", []string{"gpt-4o-mini"})
	sel, err := s.Select("claude-sonnet", PolicyContext{})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Model != "claude-sonnet" {
		t.Fatalf("model = %q, want the hint claude-sonnet", sel.Model)
	}
}

func TestConfigSelector_PrimaryWhenNoHint(t *testing.T) {
	s := NewConfigSelector("gpt-4o", []string{"gpt-4o-mini", "claude-sonnet"})
	sel, err := s.Select("", PolicyContext{})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Model != "gpt-4o" {
		t.Fatalf("model = %q, want configured primary gpt-4o", sel.Model)
	}
	if !reflect.DeepEqual(sel.Fallbacks, []string{"gpt-4o-mini", "claude-sonnet"}) {
		t.Fatalf("fallbacks = %v, want [gpt-4o-mini claude-sonnet]", sel.Fallbacks)
	}
}

// The chosen primary must not also appear in the fallback chain (no wasted
// duplicate candidate).
func TestConfigSelector_PrimaryDedupedFromFallbacks(t *testing.T) {
	s := NewConfigSelector("gpt-4o", []string{"gpt-4o", "gpt-4o-mini"})
	sel, _ := s.Select("", PolicyContext{})
	if !reflect.DeepEqual(sel.Fallbacks, []string{"gpt-4o-mini"}) {
		t.Fatalf("fallbacks = %v, want [gpt-4o-mini] (primary deduped)", sel.Fallbacks)
	}
	// The full candidate chain the pipeline walks: primary first, then fallbacks.
	cands := sel.Candidates()
	if len(cands) != 2 || cands[0].Model != "gpt-4o" || cands[1].Model != "gpt-4o-mini" {
		t.Fatalf("candidates = %+v, want [gpt-4o gpt-4o-mini]", cands)
	}
}
