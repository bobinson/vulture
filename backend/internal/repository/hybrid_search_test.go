package repository

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// ---------------------------------------------------------------------------
// temporalDecay
// ---------------------------------------------------------------------------

func TestTemporalDecay_RecentDate(t *testing.T) {
	d := temporalDecay(time.Now().Add(-1 * time.Hour))
	if d < 0.99 {
		t.Errorf("expected ~1.0 for recent, got %f", d)
	}
}

func TestTemporalDecay_OldDate(t *testing.T) {
	// 180 days = 2 half-lives → decay ~0.25
	d := temporalDecay(time.Now().Add(-180 * 24 * time.Hour))
	if d > 0.30 || d < 0.20 {
		t.Errorf("expected ~0.25 for 180d, got %f", d)
	}
}

func TestTemporalDecay_ZeroTime(t *testing.T) {
	d := temporalDecay(time.Time{})
	if d != 0.5 {
		t.Errorf("expected 0.5 for zero time, got %f", d)
	}
}

func TestTemporalDecay_HalfLife(t *testing.T) {
	// At exactly one half-life, decay should be ~0.5
	d := temporalDecay(time.Now().Add(-90 * 24 * time.Hour))
	if math.Abs(d-0.5) > 0.05 {
		t.Errorf("expected ~0.5 at half-life, got %f", d)
	}
}

func TestTemporalDecay_FutureDate(t *testing.T) {
	d := temporalDecay(time.Now().Add(24 * time.Hour))
	if d < 0.99 {
		t.Errorf("future date should clamp to ~1.0, got %f", d)
	}
}

// ---------------------------------------------------------------------------
// maxSimilarity
// ---------------------------------------------------------------------------

func TestMaxSimilarity_Empty(t *testing.T) {
	if m := maxSimilarity(nil); m != 0 {
		t.Errorf("expected 0 for nil list, got %f", m)
	}
}

func TestMaxSimilarity_Single(t *testing.T) {
	list := []model.AuditMemory{{Similarity: 0.8}}
	if m := maxSimilarity(list); m != 0.8 {
		t.Errorf("expected 0.8, got %f", m)
	}
}

func TestMaxSimilarity_Multiple(t *testing.T) {
	list := []model.AuditMemory{
		{Similarity: 0.3},
		{Similarity: 0.9},
		{Similarity: 0.5},
	}
	if m := maxSimilarity(list); m != 0.9 {
		t.Errorf("expected 0.9, got %f", m)
	}
}

// ---------------------------------------------------------------------------
// tokenize
// ---------------------------------------------------------------------------

func TestTokenize_Basic(t *testing.T) {
	tokens := tokenize("SQL Injection in login handler")
	expected := []string{"sql", "injection", "in", "login", "handler"}
	for _, e := range expected {
		if !tokens[e] {
			t.Errorf("expected token %q", e)
		}
	}
}

func TestTokenize_StripsShortWords(t *testing.T) {
	tokens := tokenize("A B cd ef")
	if tokens["a"] || tokens["b"] {
		t.Error("single-char tokens should be stripped")
	}
	if !tokens["cd"] || !tokens["ef"] {
		t.Error("2+ char tokens should be kept")
	}
}

func TestTokenize_StripsPunctuation(t *testing.T) {
	tokens := tokenize("(hello), world!")
	if !tokens["hello"] || !tokens["world"] {
		t.Error("punctuation should be stripped")
	}
}

func TestTokenize_Empty(t *testing.T) {
	tokens := tokenize("")
	if len(tokens) != 0 {
		t.Errorf("expected empty set, got %d tokens", len(tokens))
	}
}

// ---------------------------------------------------------------------------
// jaccardSimilarity
// ---------------------------------------------------------------------------

func TestContentSimilarity_Identical(t *testing.T) {
	a := model.AuditMemory{Title: "SQL Injection", Category: "owasp"}
	sim := jaccardSimilarity(a, a)
	if sim != 1.0 {
		t.Errorf("identical items should have similarity 1.0, got %f", sim)
	}
}

func TestContentSimilarity_NoOverlap(t *testing.T) {
	a := model.AuditMemory{Title: "SQL Injection", Category: "owasp"}
	b := model.AuditMemory{Title: "Missing Timeout", Category: "chaos"}
	sim := jaccardSimilarity(a, b)
	if sim > 0.01 {
		t.Errorf("no-overlap should be ~0, got %f", sim)
	}
}

func TestContentSimilarity_PartialOverlap(t *testing.T) {
	a := model.AuditMemory{Title: "SQL Injection in login", Category: "owasp"}
	b := model.AuditMemory{Title: "SQL Injection in auth", Category: "owasp"}
	sim := jaccardSimilarity(a, b)
	// "sql", "injection", "in", "owasp" overlap; "login" vs "auth" differ
	if sim < 0.5 {
		t.Errorf("expected substantial overlap, got %f", sim)
	}
}

func TestContentSimilarity_BothEmpty(t *testing.T) {
	a := model.AuditMemory{}
	b := model.AuditMemory{}
	sim := jaccardSimilarity(a, b)
	if sim != 0.0 {
		t.Errorf("both empty should be 0, got %f", sim)
	}
}

// ---------------------------------------------------------------------------
// weightedFusion
// ---------------------------------------------------------------------------

func TestWeightedFusion_EmptyLists(t *testing.T) {
	result := weightedFusion(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestWeightedFusion_VectorOnly(t *testing.T) {
	vec := []model.AuditMemory{
		{ID: "a", Similarity: 0.9},
		{ID: "b", Similarity: 0.5},
	}
	result := weightedFusion(vec, nil)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	// "a" should be first (higher score)
	if result[0].ID != "a" {
		t.Error("expected 'a' first")
	}
}

func TestWeightedFusion_TextOnly(t *testing.T) {
	txt := []model.AuditMemory{
		{ID: "c", Similarity: 0.8},
	}
	result := weightedFusion(nil, txt)
	if len(result) != 1 || result[0].ID != "c" {
		t.Error("expected single item 'c'")
	}
}

func TestWeightedFusion_BothPresent_VectorWeighted(t *testing.T) {
	vec := []model.AuditMemory{
		{ID: "a", Similarity: 1.0}, // vector-only
	}
	txt := []model.AuditMemory{
		{ID: "b", Similarity: 1.0}, // text-only
	}
	result := weightedFusion(vec, txt)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	// "a" should rank higher because vectorWeight (0.7) > textWeight (0.3)
	if result[0].ID != "a" {
		t.Errorf("vector item should rank first, got %s", result[0].ID)
	}
	if math.Abs(result[0].Similarity-vectorWeight) > 0.01 {
		t.Errorf("expected score ~%f, got %f", vectorWeight, result[0].Similarity)
	}
	if math.Abs(result[1].Similarity-textWeight) > 0.01 {
		t.Errorf("expected score ~%f, got %f", textWeight, result[1].Similarity)
	}
}

func TestWeightedFusion_SharedItem_ScoresAdd(t *testing.T) {
	vec := []model.AuditMemory{
		{ID: "shared", Similarity: 1.0},
	}
	txt := []model.AuditMemory{
		{ID: "shared", Similarity: 1.0},
	}
	result := weightedFusion(vec, txt)
	if len(result) != 1 {
		t.Fatalf("expected 1 merged, got %d", len(result))
	}
	expected := vectorWeight + textWeight // 1.0
	if math.Abs(result[0].Similarity-expected) > 0.01 {
		t.Errorf("expected combined score %f, got %f", expected, result[0].Similarity)
	}
}

func TestWeightedFusion_Normalization(t *testing.T) {
	// When max vector score is 0.5, normalization should scale to 1.0
	vec := []model.AuditMemory{
		{ID: "a", Similarity: 0.5},
		{ID: "b", Similarity: 0.25},
	}
	result := weightedFusion(vec, nil)
	// "a" normalized = 0.5/0.5 * 0.7 = 0.7
	// "b" normalized = 0.25/0.5 * 0.7 = 0.35
	if math.Abs(result[0].Similarity-0.7) > 0.01 {
		t.Errorf("expected 0.7, got %f", result[0].Similarity)
	}
	if math.Abs(result[1].Similarity-0.35) > 0.01 {
		t.Errorf("expected 0.35, got %f", result[1].Similarity)
	}
}

// ---------------------------------------------------------------------------
// mmrFilter
// ---------------------------------------------------------------------------

func TestMmrFilter_LessThanLimit(t *testing.T) {
	items := []model.AuditMemory{
		{ID: "a", Title: "SQL Injection", Similarity: 0.9},
	}
	result := mmrFilter(items, 5)
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}

func TestMmrFilter_ExactLimit(t *testing.T) {
	items := []model.AuditMemory{
		{ID: "a", Title: "A", Similarity: 0.9},
		{ID: "b", Title: "B", Similarity: 0.8},
	}
	result := mmrFilter(items, 2)
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestMmrFilter_DiverseOverSimilar(t *testing.T) {
	// Two near-identical items + one diverse item
	items := []model.AuditMemory{
		{ID: "a", Title: "SQL Injection login", Category: "owasp", Similarity: 0.95},
		{ID: "b", Title: "SQL Injection login", Category: "owasp", Similarity: 0.90},
		{ID: "c", Title: "Missing Circuit Breaker", Category: "chaos", Similarity: 0.85},
	}
	result := mmrFilter(items, 2)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	// Should pick "a" first (highest relevance), then "c" (more diverse than "b")
	if result[0].ID != "a" {
		t.Errorf("expected 'a' first, got %s", result[0].ID)
	}
	if result[1].ID != "c" {
		t.Errorf("expected 'c' second (diverse), got %s", result[1].ID)
	}
}

func TestMmrFilter_PrefersRelevanceWithLambda(t *testing.T) {
	// With high lambda (0.8), relevance matters more than diversity
	items := []model.AuditMemory{
		{ID: "a", Title: "SQL Injection", Category: "owasp", Similarity: 1.0},
		{ID: "b", Title: "XSS Attack", Category: "owasp", Similarity: 0.95},
		{ID: "c", Title: "Timeout Missing", Category: "chaos", Similarity: 0.3},
	}
	result := mmrFilter(items, 2)
	// "a" first (highest), "b" second (high relevance despite some similarity)
	if result[0].ID != "a" {
		t.Errorf("expected 'a' first, got %s", result[0].ID)
	}
	// "b" has 0.95 relevance but some overlap with "a" (owasp)
	// "c" has 0.3 relevance but no overlap
	// MMR for b: 0.8*0.95 - 0.2*sim(a,b)
	// MMR for c: 0.8*0.3 - 0.2*0 = 0.24
	// As long as "b" MMR > 0.24, "b" wins
	if result[1].ID != "b" {
		t.Errorf("expected 'b' second, got %s", result[1].ID)
	}
}

func TestMmrFilter_Empty(t *testing.T) {
	result := mmrFilter(nil, 5)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// applyDecayAndMMR (integration)
// ---------------------------------------------------------------------------

func TestApplyDecayAndMMR_Empty(t *testing.T) {
	result := applyDecayAndMMR(nil, 5)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestApplyDecayAndMMR_RecentItemsRankHigher(t *testing.T) {
	now := time.Now()
	items := []model.AuditMemory{
		{ID: "old", Title: "Old Finding", Similarity: 0.9, CreatedAt: now.Add(-365 * 24 * time.Hour)},
		{ID: "new", Title: "New Finding", Similarity: 0.8, CreatedAt: now.Add(-1 * time.Hour)},
	}
	result := applyDecayAndMMR(items, 2)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	// "new" should rank first despite lower raw score, because temporal decay
	// reduces "old" score significantly
	if result[0].ID != "new" {
		t.Errorf("expected 'new' first after decay, got %s (sim=%f vs %f)",
			result[0].ID, result[0].Similarity, result[1].Similarity)
	}
}

func TestApplyDecayAndMMR_LimitsOutput(t *testing.T) {
	items := make([]model.AuditMemory, 20)
	now := time.Now()
	for i := range items {
		items[i] = model.AuditMemory{
			ID:         fmt.Sprintf("m%d", i),
			Title:      fmt.Sprintf("Finding %d", i),
			Similarity: float64(20-i) / 20.0,
			CreatedAt:  now,
		}
	}
	result := applyDecayAndMMR(items, 5)
	if len(result) != 5 {
		t.Errorf("expected 5, got %d", len(result))
	}
}
