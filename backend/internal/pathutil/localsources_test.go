package pathutil

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// The local-path policy (feature 0102): one value, derived in one place,
// that browse, ingest and dispatch all gate through Allow.

const localSourcesDisabledText = "local paths are disabled on this server: set VULTURE_SOURCE_ROOT to allow them in centralized mode"

// wantDisabled fails unless err is the disabled sentinel with its exact text,
// since browse and ingest send that text to the client.
func wantDisabled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrLocalSourcesDisabled) || err.Error() != localSourcesDisabledText {
		t.Errorf("Allow() = %v; want ErrLocalSourcesDisabled with text %q", err, localSourcesDisabledText)
	}
}

func TestLocalSources_ZeroValueDisabled(t *testing.T) {
	var p LocalSources
	if p.Enabled {
		t.Fatal("zero LocalSources is enabled; the zero value must be disabled")
	}
	wantDisabled(t, p.Allow())
}

func TestNewLocalSources_TruthTable(t *testing.T) {
	const root = "/srv/vulture/sources"
	for _, c := range []struct {
		root                string
		localMode, readOnly bool
		enabled             bool
	}{
		{"", false, false, false},  // centralized, no root
		{"", false, true, false},   // read-only viewer
		{"", true, false, true},    // local mode
		{"", true, true, false},    // read-only beats local mode
		{root, false, false, true}, // centralized with a root
		{root, false, true, false}, // read-only beats a root
		{root, true, false, true},  // local mode with a root
		{root, true, true, false},  // read-only beats both
	} {
		name := fmt.Sprintf("root=%q/local=%v/readonly=%v", c.root, c.localMode, c.readOnly)
		t.Run(name, func(t *testing.T) {
			got := NewLocalSources(c.root, c.localMode, c.readOnly)
			if want := (LocalSources{Root: c.root, Enabled: c.enabled}); got != want {
				t.Fatalf("NewLocalSources = %+v; want %+v", got, want)
			}
			wantAllow(t, got, c.enabled)
		})
	}
}

// wantAllow checks Allow against the policy's expected state.
func wantAllow(t *testing.T, p LocalSources, enabled bool) {
	t.Helper()
	err := p.Allow()
	if !enabled {
		wantDisabled(t, err)
		return
	}
	if err != nil {
		t.Errorf("Allow() on %+v = %v; want nil", p, err)
	}
}

// TestLocalSources_AllowDisabledTouchesNoFS: a disabled policy refuses without
// looking at its root. A root that is missing, relative or unusable by any
// syscall still yields the bare sentinel, and Allow makes no allocation (a
// stat, lstat or path resolution would).
func TestLocalSources_AllowDisabledTouchesNoFS(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	for _, root := range []string{"", gone, "relative/root", "/nul\x00byte"} {
		p := LocalSources{Root: root}
		wantDisabled(t, p.Allow())
		if allocs := testing.AllocsPerRun(100, func() { _ = p.Allow() }); allocs != 0 {
			t.Errorf("Allow() with root %q allocated %.0f times per call; want 0", root, allocs)
		}
	}
}
