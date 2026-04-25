package repository

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vulture/backend/internal/model"
	_ "modernc.org/sqlite"
)

func setupSQLiteAPIKeyRepo(t *testing.T) APIKeyRepository {
	t.Helper()
	tmpDB := t.TempDir() + "/test.db"
	db, err := sql.Open("sqlite", tmpDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureSQLite(db); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	migrateAddColumns(db)
	t.Cleanup(func() { db.Close() })
	return NewSQLiteAPIKeyRepo(db)
}

func setupMockAPIKeyRepo(t *testing.T) APIKeyRepository {
	return NewMockAPIKeyRepo()
}

// TODO: TestAPIKeyRepo_Postgres — requires a live PostgreSQL instance.
// Uncomment and configure DSN when integration test infrastructure is available.
// func setupPostgresAPIKeyRepo(t *testing.T) APIKeyRepository { ... }
// func TestAPIKeyRepo_Postgres(t *testing.T) { runAPIKeyRepoSuite(t, setupPostgresAPIKeyRepo) }

func makeTestAPIKey(t *testing.T, createdBy string) *model.APIKey {
	t.Helper()
	plaintext, hash, err := model.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	return &model.APIKey{
		ID:        uuid.NewString(),
		Prefix:    model.APIKeyPrefix(plaintext),
		Hash:      hash,
		Name:      "test-key-" + uuid.NewString()[:8],
		Scopes:    []string{"read", "write"},
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func runAPIKeyRepoSuite(t *testing.T, setup func(*testing.T) APIKeyRepository) {
	t.Run("CreateAndFindByPrefix", func(t *testing.T) {
		repo := setup(t)
		userID := uuid.NewString()
		k := makeTestAPIKey(t, userID)

		if err := repo.Create(k); err != nil {
			t.Fatalf("Create: %v", err)
		}

		found, err := repo.FindByPrefix(k.Prefix)
		if err != nil {
			t.Fatalf("FindByPrefix: %v", err)
		}
		if found == nil {
			t.Fatal("FindByPrefix returned nil")
		}
		if found.ID != k.ID {
			t.Errorf("ID mismatch: got %s, want %s", found.ID, k.ID)
		}
		if found.Prefix != k.Prefix {
			t.Errorf("Prefix mismatch: got %s, want %s", found.Prefix, k.Prefix)
		}
		if found.Hash != k.Hash {
			t.Errorf("Hash mismatch")
		}
		if found.Name != k.Name {
			t.Errorf("Name mismatch: got %s, want %s", found.Name, k.Name)
		}
		if len(found.Scopes) != 2 || found.Scopes[0] != "read" || found.Scopes[1] != "write" {
			t.Errorf("Scopes mismatch: got %v", found.Scopes)
		}
		if found.CreatedBy != userID {
			t.Errorf("CreatedBy mismatch: got %s, want %s", found.CreatedBy, userID)
		}
		// Timestamp round-trip tolerance: RFC3339 drops sub-second precision
		if found.CreatedAt.Sub(k.CreatedAt).Abs() > 2*time.Second {
			t.Errorf("CreatedAt drift: got %v, want %v", found.CreatedAt, k.CreatedAt)
		}
	})

	t.Run("FindByPrefixReturnsNilForRevoked", func(t *testing.T) {
		repo := setup(t)
		userID := uuid.NewString()
		k := makeTestAPIKey(t, userID)

		if err := repo.Create(k); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Revoke(k.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		found, err := repo.FindByPrefix(k.Prefix)
		if err != nil {
			t.Fatalf("FindByPrefix: %v", err)
		}
		if found != nil {
			t.Errorf("expected nil for revoked key, got %+v", found)
		}
	})

	t.Run("ListOmitsRevoked", func(t *testing.T) {
		repo := setup(t)
		userID := uuid.NewString()
		k1 := makeTestAPIKey(t, userID)
		k2 := makeTestAPIKey(t, userID)

		if err := repo.Create(k1); err != nil {
			t.Fatalf("Create k1: %v", err)
		}
		if err := repo.Create(k2); err != nil {
			t.Fatalf("Create k2: %v", err)
		}
		if err := repo.Revoke(k1.ID); err != nil {
			t.Fatalf("Revoke k1: %v", err)
		}

		keys, err := repo.List(userID)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		if keys[0].ID != k2.ID {
			t.Errorf("expected key %s, got %s", k2.ID, keys[0].ID)
		}
	})

	t.Run("ListFiltersByCreatedBy", func(t *testing.T) {
		repo := setup(t)
		userA := uuid.NewString()
		userB := uuid.NewString()
		kA := makeTestAPIKey(t, userA)
		kB := makeTestAPIKey(t, userB)

		if err := repo.Create(kA); err != nil {
			t.Fatalf("Create kA: %v", err)
		}
		if err := repo.Create(kB); err != nil {
			t.Fatalf("Create kB: %v", err)
		}

		keysA, err := repo.List(userA)
		if err != nil {
			t.Fatalf("List userA: %v", err)
		}
		if len(keysA) != 1 {
			t.Fatalf("expected 1 key for userA, got %d", len(keysA))
		}
		if keysA[0].ID != kA.ID {
			t.Errorf("expected key %s for userA, got %s", kA.ID, keysA[0].ID)
		}

		keysB, err := repo.List(userB)
		if err != nil {
			t.Fatalf("List userB: %v", err)
		}
		if len(keysB) != 1 {
			t.Fatalf("expected 1 key for userB, got %d", len(keysB))
		}
		if keysB[0].ID != kB.ID {
			t.Errorf("expected key %s for userB, got %s", kB.ID, keysB[0].ID)
		}
	})

	t.Run("TouchLastUsedUpdates", func(t *testing.T) {
		repo := setup(t)
		userID := uuid.NewString()
		k := makeTestAPIKey(t, userID)

		if err := repo.Create(k); err != nil {
			t.Fatalf("Create: %v", err)
		}

		// Initially nil
		found, err := repo.FindByPrefix(k.Prefix)
		if err != nil {
			t.Fatalf("FindByPrefix: %v", err)
		}
		if found.LastUsedAt != nil {
			t.Errorf("expected LastUsedAt to be nil initially, got %v", found.LastUsedAt)
		}

		before := time.Now().UTC().Add(-2 * time.Second)
		if err := repo.TouchLastUsed(k.ID); err != nil {
			t.Fatalf("TouchLastUsed: %v", err)
		}

		found, err = repo.FindByPrefix(k.Prefix)
		if err != nil {
			t.Fatalf("FindByPrefix after touch: %v", err)
		}
		if found.LastUsedAt == nil {
			t.Fatal("expected LastUsedAt to be set after touch")
		}
		if found.LastUsedAt.Before(before) {
			t.Errorf("LastUsedAt %v is before expected %v", found.LastUsedAt, before)
		}
	})

	t.Run("TouchLastUsedMissingIDIsSilent", func(t *testing.T) {
		repo := setup(t)
		err := repo.TouchLastUsed(uuid.NewString())
		if err != nil {
			t.Errorf("TouchLastUsed on missing ID should not error, got: %v", err)
		}
	})
}

func TestAPIKeyRepo_SQLite(t *testing.T) {
	runAPIKeyRepoSuite(t, setupSQLiteAPIKeyRepo)
}

func TestAPIKeyRepo_Mock(t *testing.T) {
	runAPIKeyRepoSuite(t, setupMockAPIKeyRepo)
}
