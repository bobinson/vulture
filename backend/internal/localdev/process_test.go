package localdev

import (
	"context"
	"testing"
	"time"
)

func TestManagerStartAndStop(t *testing.T) {
	mgr := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a simple echo process
	err := mgr.Start(ctx, "echo-test", "/tmp", nil, "sh", "-c", "echo hello && sleep 10")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Check status
	statuses := mgr.Status()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 process, got %d", len(statuses))
	}
	if statuses[0].Name != "echo-test" {
		t.Errorf("expected name echo-test, got %s", statuses[0].Name)
	}
	if statuses[0].PID <= 0 {
		t.Errorf("expected positive PID, got %d", statuses[0].PID)
	}

	// Stop all
	mgr.StopAll()
	mgr.WaitAll()
}

func TestManagerStartNoCommand(t *testing.T) {
	mgr := NewManager()
	ctx := context.Background()
	err := mgr.Start(ctx, "empty", "/tmp", nil)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("/test/root")
	if cfg.ProjectRoot != "/test/root" {
		t.Errorf("expected /test/root, got %s", cfg.ProjectRoot)
	}
	if cfg.BackendPort != "8080" {
		t.Errorf("expected 8080, got %s", cfg.BackendPort)
	}
	if cfg.FrontendPort != "3001" {
		t.Errorf("expected 3001, got %s", cfg.FrontendPort)
	}
	if len(cfg.AgentPorts) != 4 {
		t.Errorf("expected 4 agent ports, got %d", len(cfg.AgentPorts))
	}
}
