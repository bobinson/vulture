package service

import (
	"strings"
	"testing"
	"time"

	"github.com/vulture/backend/internal/repository"
)

func TestAPIKeyService_CreateReturnsPlaintextAndStores(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	plaintext, stored, err := svc.Create("ci-gha", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(plaintext, "vk_") {
		t.Errorf("plaintext should start with vk_, got %q", plaintext)
	}
	if stored.Hash == plaintext {
		t.Error("stored hash must not equal plaintext")
	}
	if stored.Name != "ci-gha" {
		t.Errorf("expected name ci-gha, got %q", stored.Name)
	}
	if stored.CreatedBy != "user-1" {
		t.Errorf("expected createdBy user-1, got %q", stored.CreatedBy)
	}
	if stored.ID == "" {
		t.Error("expected non-empty ID")
	}
	if len(stored.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(stored.Scopes))
	}
	hasRead, hasWrite := false, false
	for _, s := range stored.Scopes {
		if s == "read" {
			hasRead = true
		}
		if s == "write" {
			hasWrite = true
		}
	}
	if !hasRead || !hasWrite {
		t.Errorf("scopes should contain read and write, got %v", stored.Scopes)
	}
}

func TestAPIKeyService_CreateStoresHashOnly(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	plaintext, stored, err := svc.Create("deploy", "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// bcrypt hashes always start with "$2a$" or "$2b$"
	if !strings.HasPrefix(stored.Hash, "$2") {
		t.Errorf("expected bcrypt hash prefix, got %q", stored.Hash[:10])
	}
	if stored.Hash == plaintext {
		t.Error("stored hash must not be the plaintext key")
	}
}

func TestAPIKeyService_VerifyAcceptsValidKey(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	plaintext, created, err := svc.Create("test-key", "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	verified, err := svc.Verify(plaintext)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.ID != created.ID {
		t.Errorf("expected ID %q, got %q", created.ID, verified.ID)
	}
}

func TestAPIKeyService_VerifyRejectsWrongKey(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	_, _, err := svc.Create("test-key", "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = svc.Verify("vk_totally_wrong_value")
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("expected 'invalid api key' error, got %q", err.Error())
	}
}

func TestAPIKeyService_VerifyRejectsRevokedKey(t *testing.T) {
	repo := repository.NewMockAPIKeyRepo()
	svc := NewAPIKeyService(repo)
	plaintext, created, err := svc.Create("revoke-me", "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Revoke(created.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = svc.Verify(plaintext)
	if err == nil {
		t.Fatal("expected error for revoked key, got nil")
	}
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("expected 'invalid api key' error, got %q", err.Error())
	}
}

func TestAPIKeyService_VerifyTouchesLastUsed(t *testing.T) {
	repo := repository.NewMockAPIKeyRepo()
	svc := NewAPIKeyService(repo)
	plaintext, _, err := svc.Create("touch-test", "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Before verify: LastUsedAt should be nil. Check via List.
	before, err := svc.List("user-1")
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	if len(before) != 1 {
		t.Fatalf("expected 1 key, got %d", len(before))
	}
	if before[0].LastUsedAt != nil {
		t.Error("expected LastUsedAt to be nil before verify")
	}

	now := time.Now().UTC()
	if _, err := svc.Verify(plaintext); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// After verify: LastUsedAt should be set (within 2 seconds of now).
	after, err := svc.List("user-1")
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("expected 1 key, got %d", len(after))
	}
	if after[0].LastUsedAt == nil {
		t.Fatal("expected LastUsedAt to be set after verify")
	}
	diff := after[0].LastUsedAt.Sub(now)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("LastUsedAt %v not within 2s of %v", after[0].LastUsedAt, now)
	}
}

func TestAPIKeyService_ListFiltersByCreator(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	for i := 0; i < 2; i++ {
		if _, _, err := svc.Create("key-a", "user-A"); err != nil {
			t.Fatalf("create user-A key %d: %v", i, err)
		}
	}
	if _, _, err := svc.Create("key-b", "user-B"); err != nil {
		t.Fatalf("create user-B key: %v", err)
	}

	listA, err := svc.List("user-A")
	if err != nil {
		t.Fatalf("list user-A: %v", err)
	}
	if len(listA) != 2 {
		t.Errorf("expected 2 keys for user-A, got %d", len(listA))
	}

	listB, err := svc.List("user-B")
	if err != nil {
		t.Fatalf("list user-B: %v", err)
	}
	if len(listB) != 1 {
		t.Errorf("expected 1 key for user-B, got %d", len(listB))
	}
}

func TestAPIKeyService_RevokeIsIdempotent(t *testing.T) {
	svc := NewAPIKeyService(repository.NewMockAPIKeyRepo())
	_, created, err := svc.Create("idem-key", "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Revoke(created.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := svc.Revoke(created.ID); err != nil {
		t.Fatalf("second revoke should not error: %v", err)
	}
}
