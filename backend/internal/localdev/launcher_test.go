package localdev

import (
	"testing"
)

func TestPrintBanner(t *testing.T) {
	cfg := DefaultConfig("/test")
	// Should not panic in any mode / agent-state combination.
	printBanner(cfg, ModeDev, true)
	printBanner(cfg, ModeInstall, true)
	printBanner(cfg, ModeInstall, false)
}

func TestNewLauncher(t *testing.T) {
	cfg := DefaultConfig("/test")
	l := NewLauncher(cfg)
	if l == nil {
		t.Fatal("expected non-nil launcher")
	}
	if l.Manager() == nil {
		t.Fatal("expected non-nil manager")
	}
}
