package service

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"

	"golang.org/x/crypto/bcrypt"
)

// TestAuthService_Login_NonexistentEmail_ConstantWork is the 0065 §3.2 / F16 RED
// baseline for the login timing oracle. It is deterministic (§M9): rather than
// measuring wall-clock latency it counts invocations of the bcryptCompare seam.
//
// A Login for an email with no matching user must still perform one constant-work
// bcrypt comparison (against a dummy hash) so that response time does not reveal
// whether the account exists. Current code short-circuits on the missing user and
// calls bcryptCompare zero times -> this test FAILS (the seam does not yet exist,
// so the package does not even compile).
//
// §R7 test hygiene: the seam is process-global, so restore it in t.Cleanup and do
// NOT mark this case t.Parallel.
func TestAuthService_Login_NonexistentEmail_ConstantWork(t *testing.T) {
	var calls int
	bcryptCompare = func(hashedPassword, password []byte) error {
		calls++
		return bcrypt.CompareHashAndPassword(hashedPassword, password)
	}
	t.Cleanup(func() { bcryptCompare = bcrypt.CompareHashAndPassword })

	repo := &mockUserRepo{
		getUserByEmailFn: func(email string) (*model.User, error) {
			return nil, nil // no such user
		},
	}
	svc := NewAuthService(repo, testSecret)

	_, err := svc.Login(&model.LoginRequest{
		Email:    "ghost@example.com",
		Password: "whatever",
	})
	if err == nil {
		t.Fatal("expected invalid credentials error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error = %q, want 'invalid credentials'", err.Error())
	}
	if calls != 1 {
		t.Fatalf("bcryptCompare called %d times for a nonexistent email, want exactly 1 (constant-work path)", calls)
	}
}
