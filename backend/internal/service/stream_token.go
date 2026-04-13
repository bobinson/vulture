package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

const (
	streamTokenTTL     = 60 * time.Second
	streamTokenBytes   = 32
	cleanupInterval    = 60 * time.Second
)

type streamToken struct {
	AuditID   string
	UserID    string
	ExpiresAt time.Time
	Used      bool
}

// StreamTokenStore manages short-lived, single-use tokens for SSE stream authentication.
// Tokens are stored in memory keyed by their SHA-256 hash. The raw token is returned
// to the client once and never stored.
type StreamTokenStore struct {
	mu      sync.Mutex
	tokens  map[string]*streamToken
	userRepo repository.UserRepository
	done    chan struct{}
}

// NewStreamTokenStore creates a store and starts a background cleanup goroutine.
func NewStreamTokenStore(userRepo repository.UserRepository) *StreamTokenStore {
	s := &StreamTokenStore{
		tokens:   make(map[string]*streamToken),
		userRepo: userRepo,
		done:     make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Stop terminates the background cleanup goroutine.
func (s *StreamTokenStore) Stop() {
	close(s.done)
}

// Create generates a new stream token scoped to an audit and user.
// Returns the raw token string to be sent to the client.
func (s *StreamTokenStore) Create(auditID, userID string) (string, error) {
	raw := make([]byte, streamTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate stream token: %w", err)
	}
	rawStr := base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(rawStr)

	s.mu.Lock()
	s.tokens[hash] = &streamToken{
		AuditID:   auditID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(streamTokenTTL),
	}
	s.mu.Unlock()

	return rawStr, nil
}

// Validate checks a raw token against the store. Returns the associated user if
// the token is valid, not expired, not already used, and scoped to the given audit.
// The token is marked as used on successful validation (single-use).
func (s *StreamTokenStore) Validate(rawToken, auditID string) (*model.User, error) {
	hash := hashToken(rawToken)

	s.mu.Lock()
	tok, ok := s.tokens[hash]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("stream token not found")
	}
	if tok.Used {
		s.mu.Unlock()
		return nil, fmt.Errorf("stream token already used")
	}
	if time.Now().After(tok.ExpiresAt) {
		delete(s.tokens, hash)
		s.mu.Unlock()
		return nil, fmt.Errorf("stream token expired")
	}
	if tok.AuditID != auditID {
		s.mu.Unlock()
		return nil, fmt.Errorf("stream token audit mismatch")
	}
	tok.Used = true
	userID := tok.UserID
	s.mu.Unlock()

	user, err := s.userRepo.GetUser(userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("stream token user not found")
	}
	return user, nil
}

func (s *StreamTokenStore) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.tokens {
				if now.After(v.ExpiresAt) || v.Used {
					delete(s.tokens, k)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
