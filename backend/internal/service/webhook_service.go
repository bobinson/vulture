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
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// IPResolver looks up IPs for a host. Swapped in tests via the
// `resolver` parameter of validateWebhookURL.
type IPResolver func(host string) ([]net.IP, error)

// defaultIPResolver uses the package-level net resolver.
func defaultIPResolver(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// ValidateWebhookURL is the exported entry point for upstream callers
// (audit_service.Create validates incoming requests before persistence).
// Wraps validateWebhookURL with the standard DNS resolver.
//
// 0036 Phase 3 — webhook SSRF guard.
func ValidateWebhookURL(raw string) error {
	return validateWebhookURL(raw, defaultIPResolver)
}

// validateWebhookURL rejects URLs that would let a malicious caller
// pivot through the backend into the deployment network. The check
// covers scheme, hostname-to-IP resolution, and per-IP classification
// (loopback / private / link-local / unspecified).
//
// Residual TOCTOU: between this call and net/http.Do, DNS could
// re-resolve to a different IP. A stronger fix uses an http.Transport
// with a custom DialContext that re-checks at dial time; v1 ships
// the LookupIP gate and documents the residual.
func validateWebhookURL(raw string, resolver IPResolver) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (only http/https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}
	ips, err := resolver(host)
	if err != nil {
		return fmt.Errorf("dns resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("dns returned no IPs for %q", host)
	}
	// Reject if ANY resolved IP is internal — picking just one allows
	// a DNS-rebinder returning [public, internal] to bypass the gate.
	for _, ip := range ips {
		if isInternalIP(ip) {
			return fmt.Errorf(
				"host %q resolves to non-public IP %s — refusing", host, ip)
		}
	}
	return nil
}

// isInternalIP returns true for IPs the webhook delivery layer must
// never reach. The set covers:
//   - Loopback (127.0.0.0/8, ::1)
//   - RFC1918 + ULA (10/8, 172.16/12, 192.168/16, fc00::/7) via IsPrivate
//   - Link-local unicast (169.254/16, fe80::/10) — covers AWS metadata
//   - Multicast / unspecified / broadcast
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// WebhookService delivers audit-completion webhooks asynchronously.
type WebhookService interface {
	DeliverAsync(auditID, url string, payload *model.WebhookPayload)
}

type webhookService struct {
	repo     repository.WebhookRepository
	client   *http.Client
	secret   string
	backoff  []time.Duration
	resolver IPResolver
}

// NewWebhookService creates a production webhook service with standard backoff.
func NewWebhookService(r repository.WebhookRepository) WebhookService {
	return &webhookService{
		repo:     r,
		client:   &http.Client{Timeout: 15 * time.Second},
		secret:   os.Getenv("VULTURE_WEBHOOK_SECRET"),
		backoff:  []time.Duration{0, 2 * time.Second, 10 * time.Second},
		resolver: defaultIPResolver,
	}
}

// newWebhookServiceForTest creates a webhook service with fast backoff for tests.
// The resolver is permissive (allows loopback) so existing httptest.NewServer-based
// delivery tests continue exercising the wire-level retry/HMAC logic without
// fighting the 0036 Phase 3 SSRF guard. SSRF behaviour is covered separately
// in webhook_ssrf_test.go which exercises validateWebhookURL directly.
func newWebhookServiceForTest(r repository.WebhookRepository, secret string, backoff []time.Duration) *webhookService {
	return &webhookService{
		repo:    r,
		client:  &http.Client{Timeout: time.Second},
		secret:  secret,
		backoff: backoff,
		// Permissive resolver: maps any host to a fake public IP so the
		// delivery layer's SSRF guard doesn't block test traffic to
		// httptest servers (which bind to 127.0.0.1).
		resolver: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.1")}, nil
		},
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
	// 0036 Phase 3 — re-validate at delivery time, not just at audit
	// creation. The DNS-rebinder threat: an attacker submits
	// http://evil.example/, the validator gets a public IP, the audit
	// is persisted, then evil.example flips its A record to
	// 169.254.169.254 before delivery fires. Re-validation here closes
	// that window (modulo the very last TOCTOU between this lookup
	// and net/http's own dial — addressed by a custom DialContext in
	// a future hardening pass). Tests inject a permissive resolver so
	// httptest.NewServer URLs (which bind 127.0.0.1) still flow through.
	if err := validateWebhookURL(url, s.resolver); err != nil {
		log.Printf("[webhook] refusing to deliver audit=%s: %v", auditID, err)
		return
	}
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
