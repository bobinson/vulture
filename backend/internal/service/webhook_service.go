package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// WebhookService delivers audit-completion webhooks asynchronously.
type WebhookService interface {
	DeliverAsync(auditID, url string, payload *model.WebhookPayload)
}

type webhookService struct {
	repo    repository.WebhookRepository
	client  *http.Client
	secret  string
	backoff []time.Duration
}

// NewWebhookService creates a production webhook service with standard backoff.
func NewWebhookService(r repository.WebhookRepository) WebhookService {
	return &webhookService{
		repo:    r,
		client:  &http.Client{Timeout: 15 * time.Second},
		secret:  os.Getenv("VULTURE_WEBHOOK_SECRET"),
		backoff: []time.Duration{0, 2 * time.Second, 10 * time.Second},
	}
}

// newWebhookServiceForTest creates a webhook service with fast backoff for tests.
func newWebhookServiceForTest(r repository.WebhookRepository, secret string, backoff []time.Duration) *webhookService {
	return &webhookService{
		repo:    r,
		client:  &http.Client{Timeout: time.Second},
		secret:  secret,
		backoff: backoff,
	}
}

// DeliverAsync fires a webhook in a background goroutine. No-op if url is empty.
func (s *webhookService) DeliverAsync(auditID, url string, payload *model.WebhookPayload) {
	if url == "" {
		return
	}
	go s.deliver(auditID, url, payload)
}

func (s *webhookService) deliver(auditID, url string, payload *model.WebhookPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[webhook] marshal error for audit=%s", auditID)
		return
	}
	sig := s.sign(body)
	delivery := &model.WebhookDelivery{
		ID:        generateWebhookID(),
		AuditID:   auditID,
		URL:       url,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	lastErr := s.attemptWithRetries(delivery, url, body, sig, auditID)
	s.recordOutcome(delivery, lastErr)
}

func (s *webhookService) attemptWithRetries(delivery *model.WebhookDelivery, url string, body []byte, sig, auditID string) string {
	var lastErr string
	for attempt, d := range s.backoff {
		if d > 0 {
			time.Sleep(d)
		}
		delivery.Attempts = attempt + 1
		if err := s.attempt(url, body, sig, auditID); err != nil {
			lastErr = err.Error()
			continue
		}
		return "" // success
	}
	return lastErr
}

func (s *webhookService) recordOutcome(delivery *model.WebhookDelivery, lastErr string) {
	if lastErr == "" {
		now := time.Now().UTC()
		delivery.Status = "delivered"
		delivery.DeliveredAt = &now
	} else {
		delivery.Status = "failed"
		delivery.LastError = lastErr
	}
	if recErr := s.repo.Record(delivery); recErr != nil {
		log.Printf("[webhook] record %s: %v", delivery.Status, recErr)
	}
}

func (s *webhookService) attempt(url string, body []byte, sig, auditID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-Vulture-Signature", sig)
	}
	req.Header.Set("X-Vulture-Delivery", auditID)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return errors.New(fmt.Sprintf("status %d", resp.StatusCode))
	}
	return nil
}

func (s *webhookService) sign(body []byte) string {
	if s.secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(s.secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func generateWebhookID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
