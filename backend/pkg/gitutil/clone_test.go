package gitutil

import (
	"context"
	"testing"
	"time"
)

func TestCloneInvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Clone(ctx, "https://invalid.example.com/nonexistent/repo.git", t.TempDir(), 1)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestCloneCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Clone(ctx, "https://github.com/octocat/Hello-World.git", t.TempDir(), 1)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
