package pluginregistry

import (
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoader_RejectsSymlinkedPluginToml(t *testing.T) {
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Skip("requires /etc/passwd")
	}
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "evil")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pluginDir, "plugin.toml")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}

	logger, buf := captureLogger()
	plugins := Load(LoadOptions{
		ExtraDirs:      []string{dir},
		IncludeVirtual: false,
		Logger:         logger,
	})
	if len(plugins) != 0 {
		t.Errorf("expected zero plugins from symlinked dir, got %d", len(plugins))
	}
	if want := "refusing to follow symlinked"; !contains(buf.String(), want) {
		t.Errorf("log should contain %q; got %q", want, buf.String())
	}
}

func TestSaveState_AtomicOnEncodeFailure(t *testing.T) {
	// SaveState writes to a .tmp sibling then renames. We can't
	// easily inject an encode failure without re-architecting, but
	// we can at least verify the "no .tmp left behind" property
	// after a successful round-trip and that the .tmp doesn't leak
	// into the dir on success.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.toml")
	if err := SaveState(path, StateFile{Plugins: map[string]PluginState{
		"x": {Enabled: true},
	}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.toml" {
		t.Errorf("expected only state.toml in dir; got %v", entries)
	}
}

func TestSaveState_DoesNotWipePriorOnRenameTargetExists(t *testing.T) {
	// Simulate the real-world flow: save once, then save again.
	// The second save must atomically replace the first without
	// any intermediate empty-file window observable on disk.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.toml")
	first := StateFile{Plugins: map[string]PluginState{"a": {Enabled: true}}}
	if err := SaveState(path, first); err != nil {
		t.Fatal(err)
	}
	second := StateFile{Plugins: map[string]PluginState{"b": {Enabled: false}}}
	if err := SaveState(path, second); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Plugins["b"]; !ok {
		t.Error("second save did not land")
	}
	if _, ok := got.Plugins["a"]; ok {
		t.Error("first save not replaced")
	}
}

func TestSaveState_Permissions0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.toml")
	if err := SaveState(path, StateFile{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("state.toml mode = %o; want 600", mode)
	}
}

func TestDefault_ConcurrentBuildsReturnSameInstance(t *testing.T) {
	ResetDefault()
	t.Cleanup(ResetDefault)

	const N = 32
	var wg sync.WaitGroup
	results := make([]Registry, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = Default()
		}(i)
	}
	wg.Wait()

	for i := 1; i < N; i++ {
		if results[i] != results[0] {
			t.Errorf("Default() returned different instances under contention: results[%d] != results[0]", i)
		}
	}
}

func TestResetDefault_NextCallRebuilds(t *testing.T) {
	ResetDefault()
	first := Default()
	ResetDefault()
	second := Default()
	t.Cleanup(ResetDefault)
	if first == second {
		t.Error("ResetDefault should cause Default() to return a fresh instance")
	}
}

func TestBuild_StateLoadFailureFallsBackToDefaults(t *testing.T) {
	// Provide a path that exists but is a directory — LoadState
	// will fail to ReadFile. Build should log, fall back to empty
	// state, and still return a usable registry.
	dir := t.TempDir()
	logger := log.New(io.Discard, "", 0)
	r, err := Build(LoadOptions{IncludeVirtual: true, Logger: logger}, dir)
	if err != nil {
		t.Fatalf("Build should not error on bad state path, got %v", err)
	}
	if len(r.All()) == 0 {
		t.Error("registry should still have virtual plugins")
	}
}

func TestLoadState_DirInsteadOfFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadState(dir)
	if err == nil {
		t.Error("expected error for directory in place of state file")
	}
	// Must not be ErrNotExist — that path is treated as empty.
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("dir-as-state should not collapse to ErrNotExist")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
