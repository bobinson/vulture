package repository

import "github.com/vulture/backend/internal/model"

// APIKeyRepository manages API key persistence for machine-to-machine auth.
type APIKeyRepository interface {
	Create(k *model.APIKey) error
	FindByPrefix(prefix string) (*model.APIKey, error) // returns nil, nil if not found or revoked
	List(createdBy string) ([]model.APIKey, error)     // only non-revoked
	Revoke(id string) error
	TouchLastUsed(id string) error
}
