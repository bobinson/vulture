package handler

// Feature 0074 #15 and #35 on GET /api/audits/{id}.
//
// #15: validation.merged_descriptions (and its _dropped count) is a debugging
// record no client renders; it is left out of the default response and served
// only under ?detail=full. The stored blob is untouched.
//
// #35: the response says whether the audit's findings record their
// contributing tiers at all (origins_recorded), so a client can tell
// "provenance=both selected nothing" from "this audit cannot answer both"
// (pre-0074 audits carry no provenance_origins).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func detailAudit() *model.Audit {
	merged := model.Finding{ID: "f-merged", Provenance: "skill", Validation: map[string]interface{}{
		"status": "likely", "provenance_origins": []interface{}{"skill", "llm"},
		"merged_descriptions":         []interface{}{map[string]interface{}{"description": "llm reasoning"}},
		"merged_descriptions_dropped": 2,
	}}
	plain := model.Finding{ID: "f-plain", Provenance: "skill"}
	return &model.Audit{ID: "a-detail", Status: model.AuditStatusCompleted, Findings: []model.Finding{merged, plain}}
}

func serveDetail(t *testing.T, a *model.Audit, query string) (map[string]interface{}, *model.Audit) {
	t.Helper()
	svc := &mockAuditService{getFn: func(string) (*model.Audit, error) { return a, nil }}
	w := httptest.NewRecorder()
	NewAuditHandler(svc).Get(w, httptest.NewRequest(http.MethodGet, "/api/audits/a-detail"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return raw, a
}

func TestAuditGet_MergedDescriptionsOnlyUnderDetailFull_0074(t *testing.T) {
	a := detailAudit()
	orig := a.Findings // the service's slice: the handler must not write through it
	body, _ := serveDetail(t, a, "")
	if s := mustJSON(t, body["findings"]); strings.Contains(s, "merged_descriptions") {
		t.Errorf("default GET serves merged_descriptions: %s", s)
	}
	if s := mustJSON(t, body["findings"]); !strings.Contains(s, "provenance_origins") {
		t.Errorf("default GET must keep provenance_origins: %s", s)
	}
	if _, ok := orig[0].Validation["merged_descriptions"]; !ok {
		t.Errorf("the default GET wrote through to the service's finding")
	}
	full, _ := serveDetail(t, detailAudit(), "?detail=full")
	s := mustJSON(t, full["findings"])
	if !strings.Contains(s, "llm reasoning") || !strings.Contains(s, "merged_descriptions_dropped") {
		t.Errorf("?detail=full must serve merged_descriptions and the dropped count: %s", s)
	}
}

func TestAuditGet_OriginsRecorded_0074(t *testing.T) {
	body, _ := serveDetail(t, detailAudit(), "?provenance=llm")
	if body["origins_recorded"] != true {
		t.Errorf("origins_recorded = %v, want true for an audit whose findings record tiers (computed before the filter)", body["origins_recorded"])
	}
	pre := &model.Audit{ID: "a-pre", Status: model.AuditStatusCompleted,
		Findings: []model.Finding{{ID: "f", Provenance: "skill", Validation: map[string]interface{}{"status": "likely"}}}}
	body, _ = serveDetail(t, pre, "?provenance=both")
	if v, ok := body["origins_recorded"]; !ok || v != false {
		t.Errorf("origins_recorded = %v (present=%v), want an explicit false for a pre-0074 audit", v, ok)
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
