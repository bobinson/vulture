package handler

// 0074 verification item 6: GET /api/audits/cache serves a stored audit like
// GET /api/audits/{id} does — the merge record (merged_descriptions and its
// dropped count) only under ?detail=full. The stored blob is untouched.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func serveCached(t *testing.T, a *model.Audit, query string) string {
	t.Helper()
	svc := &mockAuditService{getCachedAuditFn: func(string, []string) (*model.Audit, error) { return a, nil }}
	w := httptest.NewRecorder()
	NewAuditHandler(svc).CachedAudit(w, httptest.NewRequest(http.MethodGet,
		"/api/audits/cache?source_id=s1&types=cwe"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET cache: %d %s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return string(body["audit"])
}

func TestCachedAudit_MergedDescriptionsOnlyUnderDetailFull_0074(t *testing.T) {
	a := detailAudit()
	orig := a.Findings
	if s := serveCached(t, a, ""); strings.Contains(s, "merged_descriptions") {
		t.Errorf("the default cache response serves merged_descriptions: %s", s)
	}
	if _, ok := orig[0].Validation["merged_descriptions"]; !ok {
		t.Error("the stored blob was modified")
	}
	if s := serveCached(t, detailAudit(), "&detail=full"); !strings.Contains(s, "llm reasoning") {
		t.Errorf("?detail=full must serve the merge record: %s", s)
	}
}
