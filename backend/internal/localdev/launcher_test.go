package localdev

import (
	"testing"
)

func TestPrintBanner(t *testing.T) {
	cfg := DefaultConfig("/test")
	// Should not panic
	printBanner(cfg)
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
