package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// contextWindowSourceOf reads AuditRequest.ContextWindowSource, failing with
// the plan reference while the field is not declared (R31: the dispatch
// request model must declare context_window_source).
func contextWindowSourceOf(t *testing.T, req *model.AuditRequest) string {
	t.Helper()
	f, ok := reflect.TypeOf(*req).FieldByName("ContextWindowSource")
	if !ok || !strings.HasPrefix(f.Tag.Get("json"), "context_window_source") {
		t.Fatal(`model.AuditRequest must declare ContextWindowSource json:"context_window_source" — 0074 §5.1(a), R31`)
	}
	return reflect.ValueOf(*req).FieldByName("ContextWindowSource").String()
}

// AC34 / §5.1(c): the window source is broker-injected at dispatch and never
// client-supplied. A client that claims `env` could otherwise pose as an
// operator override; the handler zeroes it on the same line that already
// zeroes a client context_window.
func TestAuditHandlerCreate_DiscardsClientContextWindowSource(t *testing.T) {
	got := createForwarded(t, `{"source_id":"s-1","types":["chaos"],"context_window":999999,"context_window_source":"env"}`)
	if src := contextWindowSourceOf(t, got); src != "" {
		t.Errorf("client-supplied context_window_source %q reached the service; must be discarded", src)
	}
	if got.ContextWindow != 0 {
		t.Errorf("client-supplied context_window %d reached the service", got.ContextWindow)
	}
}

// createForwarded POSTs body to the audit handler and returns the request the
// handler forwarded to the audit service.
func createForwarded(t *testing.T, body string) *model.AuditRequest {
	t.Helper()
	var got *model.AuditRequest
	svc := &mockAuditService{createFn: func(req *model.AuditRequest) (*model.Audit, error) {
		got = req
		return &model.Audit{ID: "a-1"}, nil
	}}
	w := httptest.NewRecorder()
	NewAuditHandler(svc).Create(w, httptest.NewRequest("POST", "/api/audits", bytes.NewBufferString(body)))
	if w.Code != http.StatusCreated || got == nil {
		t.Fatalf("create = %d (%s), want 201", w.Code, w.Body.String())
	}
	return got
}
