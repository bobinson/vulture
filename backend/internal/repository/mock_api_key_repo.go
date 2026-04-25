package repository

import (
	"sync"
	"time"

	"github.com/vulture/backend/internal/model"
)

// MockAPIKeyRepo implements APIKeyRepository using an in-memory map.
type MockAPIKeyRepo struct {
	mu   sync.Mutex
	keys map[string]*model.APIKey // by id
}

// NewMockAPIKeyRepo returns a ready-to-use in-memory API key repository.
func NewMockAPIKeyRepo() *MockAPIKeyRepo {
	return &MockAPIKeyRepo{keys: make(map[string]*model.APIKey)}
}

func (m *MockAPIKeyRepo) Create(k *model.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *k
	m.keys[k.ID] = &cp
	return nil
}

func (m *MockAPIKeyRepo) FindByPrefix(prefix string) (*model.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys {
		if k.Prefix == prefix && k.RevokedAt == nil {
			cp := *k
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MockAPIKeyRepo) List(createdBy string) ([]model.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []model.APIKey
	for _, k := range m.keys {
		if k.CreatedBy == createdBy && k.RevokedAt == nil {
			result = append(result, *k)
		}
	}
	return result, nil
}

func (m *MockAPIKeyRepo) Revoke(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[id]; ok {
		now := time.Now().UTC()
		k.RevokedAt = &now
	}
	return nil
}

func (m *MockAPIKeyRepo) TouchLastUsed(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[id]; ok {
		now := time.Now().UTC()
		k.LastUsedAt = &now
	}
	return nil
}
