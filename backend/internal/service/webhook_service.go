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
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
	"github.com/vulture/backend/pkg/netguard"
)

// IPResolver is a service-local alias for netguard's context-bounded
// resolver so callers/tests keep a stable name (0065, §M2).
type IPResolver = netguard.Resolver

// defaultIPResolver delegates to netguard's deadline-bounded resolver.
func defaultIPResolver(ctx context.Context, host string) ([]net.IP, error) {
	return netguard.DefaultResolver(ctx, host)
}

// webhookAllowlistFromEnv parses VULTURE_WEBHOOK_HOST_ALLOWLIST (0065 §2.3) into
// a set of lowercased hostnames the operator has explicitly trusted as internal
// webhook targets. Returns nil when unset/empty (fully guarded, public-only).
func webhookAllowlistFromEnv() map[string]bool {
	allow := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("VULTURE_WEBHOOK_HOST_ALLOWLIST"), ",") {
		if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
			allow[h] = true
		}
	}
	if len(allow) == 0 {
		return nil
	}
	return allow
}

// hostAllowed reports whether host is on the operator's webhook allowlist.
func hostAllowed(allow map[string]bool, host string) bool {
	return len(allow) > 0 && allow[strings.ToLower(host)]
}

// ValidateWebhookURL is the exported entry point for upstream callers
// (audit_service.Create validates incoming requests before persistence). It
// applies the webhook host allowlist (0065 §2.3) around netguard's classifier.
//
// 0036 Phase 3 — webhook SSRF guard.
func ValidateWebhookURL(ctx context.Context, raw string) error {
	err := validateWebhookURL(ctx, raw, netguard.DefaultResolver, webhookAllowlistFromEnv())
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		log.Printf("WARN webhook: %v — blocked; add the host to VULTURE_WEBHOOK_HOST_ALLOWLIST if it is a trusted internal target", err)
	}
	return err
}

// validateWebhookURL rejects URLs that would let a malicious caller pivot
// through the backend into the deployment network. It mirrors gitutil's
// caller-owned-allowlist shape (0065 §2.3): parse → http/https scheme → an
// operator-allowlisted host short-circuits to allow → otherwise netguard's
// single audited internal-IP classifier. A BlockedError is wrapped with an
// actionable hint naming the override flag so the operator can decide.
//
// Residual TOCTOU: between this call and net/http.Do, DNS could re-resolve to a
// different IP. netguard.GuardedDialContext (via allowlistGuardedDial) closes
// that window at dial time; this gate rejects early with a clear message.
func validateWebhookURL(ctx context.Context, raw string, resolver netguard.Resolver, allow map[string]bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse webhook url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook scheme %q not allowed (only http/https)", u.Scheme)
	}
	host := u.Hostname()
	if hostAllowed(allow, host) {
		return nil // operator-trusted internal target (VULTURE_WEBHOOK_HOST_ALLOWLIST)
	}
	if err := netguard.ValidateHostPublic(ctx, host, resolver); err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return fmt.Errorf("%w; if %q is a trusted internal webhook target, add it to VULTURE_WEBHOOK_HOST_ALLOWLIST", err, host)
		}
		return err
	}
	return nil
}

// allowlistGuardedDial returns a DialContext that dials an operator-allowlisted
// host directly (the internal target is explicitly trusted, 0065 §2.3) and
// otherwise falls through to netguard.GuardedDialContext, which refuses internal
// IPs at dial time (closing the DNS-rebind window for everything else).
func allowlistGuardedDial(allow map[string]bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 10 * time.Second}
	guarded := netguard.GuardedDialContext(base)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil && hostAllowed(allow, host) {
			return base.DialContext(ctx, network, addr)
		}
		return guarded(ctx, network, addr)
	}
}

// WebhookService delivers audit-completion webhooks asynchronously.
type WebhookService interface {
	DeliverAsync(auditID, url string, payload *model.WebhookPayload)
}

type webhookService struct {
	repo      repository.WebhookRepository
	client    *http.Client
	secret    string
	backoff   []time.Duration
	resolver  IPResolver
	allowlist map[string]bool // operator-trusted internal hosts (0065 §2.3)
}

// NewWebhookService creates a production webhook service with standard backoff.
func NewWebhookService(r repository.WebhookRepository) WebhookService {
	s := &webhookService{
		repo:      r,
		secret:    os.Getenv("VULTURE_WEBHOOK_SECRET"),
		backoff:   []time.Duration{0, 2 * time.Second, 10 * time.Second},
		resolver:  defaultIPResolver,
		allowlist: webhookAllowlistFromEnv(),
	}
	s.client = s.buildClient(true) // guarded dialer in production
	return s
}

// buildClient constructs the delivery HTTP client. 0065 §2.1: CheckRedirect
// re-runs the SSRF guard on every redirect hop (using the service resolver so
// tests stay hermetic), refusing any hop whose host resolves to an internal
// IP. When guarded, the transport's dialer (netguard.GuardedDialContext) also
// refuses internal IPs at dial time, closing the residual DNS-rebind TOCTOU.
func (s *webhookService) buildClient(guarded bool) *http.Client {
	c := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return validateWebhookURL(req.Context(), req.URL.String(), s.resolver, s.allowlist)
		},
	}
	if guarded {
		c.Transport = &http.Transport{DialContext: allowlistGuardedDial(s.allowlist)}
	}
	return c
}

// newWebhookServiceForTest creates a webhook service with fast backoff for tests.
// The permissive resolver maps any hostname to a fake public IP so the delivery
// layer's SSRF guard (netguard, 0065) doesn't block test traffic; delivery tests
// therefore address the httptest server via a public-looking hostname (netguard
// classifies literal loopback IPs directly, bypassing the resolver). The
// transport rewrites the dial to loopback so the wire-level retry/HMAC logic is
// still exercised against the real httptest server. SSRF behaviour itself is
// covered separately in webhook_ssrf_test.go (validateWebhookURL) and the
// netguard package tests.
func newWebhookServiceForTest(r repository.WebhookRepository, secret string, backoff []time.Duration) *webhookService {
	s := &webhookService{
		repo:    r,
		secret:  secret,
		backoff: backoff,
		// Permissive resolver: maps any hostname to a fake public IP so the
		// delivery layer's SSRF guard doesn't block test traffic to the
		// httptest server (which the transport below dials on loopback).
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.1")}, nil
		},
	}
	// 0065 §2.1: use the production client so CheckRedirect (the per-hop
	// SSRF guard) is exercised in tests, but unguarded (no netguard dialer)
	// and with a loopback-rewriting transport so httptest servers addressed
	// via public-looking hostnames are still reached on 127.0.0.1.
	s.client = s.buildClient(false)
	s.client.Timeout = time.Second
	s.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := net.Dialer{Timeout: time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
	return s
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := validateWebhookURL(ctx, url, s.resolver, s.allowlist); err != nil {
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
		return fmt.Errorf("status %d", resp.StatusCode)
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
