package server_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/vulture/backend/internal/broker/budget"
	"github.com/vulture/backend/internal/broker/server"
)

// fakeAuditLog records the §14 metering rows the server emits.
type fakeAuditLog struct {
	mu      sync.Mutex
	entries []budget.LedgerEntry
}

func (f *fakeAuditLog) Log(_ context.Context, e budget.LedgerEntry, _ bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, e)
}

// §14 P0 slice: a successful completion emits exactly one audit-log row
// carrying the metering fields (never content).
func TestHandleComplete_EmitsAuditLogRow(t *testing.T) {
	h := newHealthyHarness()
	al := &fakeAuditLog{}
	deps := h.deps()
	deps.AuditLog = al
	srv := server.New(deps)

	rr := doPost(t, srv, completePath, testBearer, completeBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	if len(al.entries) != 1 {
		t.Fatalf("audit-log rows = %d, want 1", len(al.entries))
	}
	e := al.entries[0]
	if e.RunID != "run-1" || e.Model != "gpt-4o" || e.Provider != "openai" || e.InputTokens != 120 {
		t.Fatalf("audit-log entry = %+v, want run-1/gpt-4o/openai/in=120", e)
	}
}
