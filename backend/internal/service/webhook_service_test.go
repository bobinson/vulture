package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

var testBackoff = []time.Duration{0, 5 * time.Millisecond, 10 * time.Millisecond}

func testPayload() *model.WebhookPayload {
	return &model.WebhookPayload{
		AuditID:       "audit-1",
		Status:        "completed",
		FindingsCount: 5,
		Scores:        map[string]int{"owasp": 72},
		CompletedAt:   time.Now().UTC(),
	}
}

func TestWebhookService_DeliverSuccess(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "test-secret", testBackoff)

	payload := testPayload()
	svc.deliver("audit-1", srv.URL, payload)

	assertDelivered(t, repo, received, payload)
}

func assertDelivered(t *testing.T, repo *repository.MockWebhookRepository, received []byte, payload *model.WebhookPayload) {
	t.Helper()
	if len(repo.Recorded) != 1 {
		t.Fatalf("expected 1 recorded delivery, got %d", len(repo.Recorded))
	}
	d := repo.Recorded[0]
	if d.Status != "delivered" {
		t.Errorf("expected status=delivered, got %s", d.Status)
	}
	if d.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", d.Attempts)
	}
	if d.DeliveredAt == nil {
		t.Error("expected DeliveredAt to be set")
	}
	if len(received) == 0 {
		t.Error("expected non-empty body")
	}
	var got model.WebhookPayload
	if err := json.Unmarshal(received, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.AuditID != payload.AuditID {
		t.Errorf("audit_id mismatch: got %s want %s", got.AuditID, payload.AuditID)
	}
}

func TestWebhookService_RetriesThenFails(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "test-secret", testBackoff)

	svc.deliver("audit-2", srv.URL, testPayload())

	mu.Lock()
	got := attempts
	mu.Unlock()
	if got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
	if len(repo.Recorded) != 1 {
		t.Fatalf("expected 1 recorded delivery, got %d", len(repo.Recorded))
	}
	d := repo.Recorded[0]
	if d.Status != "failed" {
		t.Errorf("expected status=failed, got %s", d.Status)
	}
	if d.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", d.Attempts)
	}
	if d.LastError != "status 500" {
		t.Errorf("expected last_error='status 500', got %q", d.LastError)
	}
}

func TestWebhookService_HMACSignature(t *testing.T) {
	secret := "my-webhook-secret"
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Vulture-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, secret, testBackoff)

	payload := testPayload()
	svc.deliver("audit-3", srv.URL, payload)

	body, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if gotSig != expected {
		t.Errorf("signature mismatch:\n  got  %s\n  want %s", gotSig, expected)
	}
}

func TestWebhookService_NoSignatureWhenNoSecret(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Vulture-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "", testBackoff)

	svc.deliver("audit-4", srv.URL, testPayload())

	if gotSig != "" {
		t.Errorf("expected no signature header, got %q", gotSig)
	}
}

func TestWebhookService_EmptyURL_NoOp(t *testing.T) {
	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "secret", testBackoff)

	svc.DeliverAsync("audit-5", "", testPayload())
	// Give goroutine a moment (though empty URL returns immediately)
	time.Sleep(10 * time.Millisecond)

	if len(repo.Recorded) != 0 {
		t.Errorf("expected no recorded deliveries, got %d", len(repo.Recorded))
	}
}

func TestWebhookService_NetworkError_Retries(t *testing.T) {
	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "secret", testBackoff)

	// Use a URL that will fail to connect
	svc.deliver("audit-6", "http://127.0.0.1:1", testPayload())

	if len(repo.Recorded) != 1 {
		t.Fatalf("expected 1 recorded delivery, got %d", len(repo.Recorded))
	}
	d := repo.Recorded[0]
	if d.Status != "failed" {
		t.Errorf("expected status=failed, got %s", d.Status)
	}
	if d.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", d.Attempts)
	}
	if d.LastError == "" {
		t.Error("expected non-empty last_error")
	}
}

func TestWebhookService_DeliveryHeader(t *testing.T) {
	var gotAuditID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuditID = r.Header.Get("X-Vulture-Delivery")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "", testBackoff)

	svc.deliver("audit-7", srv.URL, testPayload())

	if gotAuditID != "audit-7" {
		t.Errorf("expected X-Vulture-Delivery=audit-7, got %q", gotAuditID)
	}
}

func TestWebhookService_RetryThenSucceed(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		n := callCount
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := &repository.MockWebhookRepository{}
	svc := newWebhookServiceForTest(repo, "", testBackoff)

	svc.deliver("audit-8", srv.URL, testPayload())

	mu.Lock()
	got := callCount
	mu.Unlock()
	if got != 3 {
		t.Fatalf("expected 3 calls, got %d", got)
	}
	if len(repo.Recorded) != 1 {
		t.Fatalf("expected 1 recorded delivery, got %d", len(repo.Recorded))
	}
	d := repo.Recorded[0]
	if d.Status != "delivered" {
		t.Errorf("expected status=delivered, got %s", d.Status)
	}
	if d.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", d.Attempts)
	}
}
