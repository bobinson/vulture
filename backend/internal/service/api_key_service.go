package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// APIKeyService manages machine-to-machine API keys.
type APIKeyService interface {
	// Create mints a new key. Returns the plaintext exactly ONCE (for the caller
	// to show to the user); the stored APIKey contains only the bcrypt hash.
	Create(name, createdBy string) (plaintext string, stored *model.APIKey, err error)

	// Verify checks a presented bearer token against stored hashes. Returns the
	// matched APIKey on success, an error on mismatch or revocation. Updates
	// last_used_at as a side effect (best-effort).
	Verify(plaintext string) (*model.APIKey, error)

	// List returns all non-revoked keys created by the given user.
	List(createdBy string) ([]model.APIKey, error)

	// Revoke marks a key as revoked (RevokedAt = now). Idempotent.
	Revoke(id string) error
}

type apiKeyService struct {
	repo repository.APIKeyRepository
}

// NewAPIKeyService returns an APIKeyService backed by the given repository.
func NewAPIKeyService(r repository.APIKeyRepository) APIKeyService {
	return &apiKeyService{repo: r}
}

func (s *apiKeyService) Create(name, createdBy string) (string, *model.APIKey, error) {
	plaintext, hash, err := model.GenerateAPIKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate: %w", err)
	}
	k := &model.APIKey{
		ID:        uuid.NewString(),
		Prefix:    model.APIKeyPrefix(plaintext),
		Hash:      hash,
		Name:      name,
		Scopes:    []string{"read", "write"},
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.repo.Create(k); err != nil {
		return "", nil, fmt.Errorf("store: %w", err)
	}
	return plaintext, k, nil
}

func (s *apiKeyService) Verify(plaintext string) (*model.APIKey, error) {
	prefix := model.APIKeyPrefix(plaintext)
	k, err := s.repo.FindByPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	if k == nil {
		return nil, fmt.Errorf("invalid api key")
	}
	if !model.VerifyAPIKey(plaintext, k.Hash) {
		return nil, fmt.Errorf("invalid api key")
	}
	_ = s.repo.TouchLastUsed(k.ID) // best-effort
	return k, nil
}

func (s *apiKeyService) List(createdBy string) ([]model.APIKey, error) {
	return s.repo.List(createdBy)
}

func (s *apiKeyService) Revoke(id string) error {
	return s.repo.Revoke(id)
}
