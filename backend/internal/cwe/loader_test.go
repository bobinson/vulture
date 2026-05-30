package cwe

// RED-phase tests for feature 0050 v1.1: mapping_file external loader.
//
// These tests reference symbols that the GREEN phase will introduce in
// backend/internal/cwe/loader.go and backend/pkg/pluginregistry/manifest.go:
//
//   - cwe.loadMappingFile(plugin)                        (helper, returns (map, error))
//   - cwe.ErrMappingFileVirtualPlugin                    (sentinel)
//   - cwe.ErrMappingFileOutsideDir                       (sentinel)
//   - cwe.ErrMappingFileSymlinkUnsafe                    (sentinel)
//   - cwe.ErrMappingFileMissing                          (sentinel)
//   - cwe.ErrMappingFileUnreadable                       (sentinel)
//   - cwe.ErrMappingFileTooLarge                         (sentinel)
//   - cwe.ErrMappingFileBadJSON                          (sentinel)
//   - cwe.ErrMappingFileSchemaVersion                    (sentinel)
//   - cwe.ErrMappingFileTooManyEntries                   (sentinel)
//   - pluginregistry.MaxNormalisationEntries             (exported constant)
//   - pluginregistry.CWERe                               (exported regexp)
//
// Until the GREEN phase lands, this file is expected to fail to compile.
// That IS the RED state.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// helper: build a minimum-valid plugin with Path pointing at a synthetic
// plugin.toml inside dir, and the supplied mapping_file string.
func mkPluginWithMappingFile(dir, mappingFile string) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name:        "semgrep",
				Version:     "1.0.0",
				APIVersion:  pluginregistry.APIVersionV1,
				Publisher:   "x",
				Description: "y",
			},
			Trust:   pluginregistry.TrustBlock{Tier: pluginregistry.TierInTree},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree, ModulePath: "x"},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan,
				Emits: []string{"finding", "result"},
			}},
			Normalization: pluginregistry.NormalizationBlock{
				MappingFile: mappingFile,
			},
		},
		Source:  "local",
		Path:    filepath.Join(dir, "plugin.toml"),
		Enabled: true,
	}
}

// AC 1: a valid mapping file is loaded and returns its entries.
func TestLoadMappingFile_ValidFile_AC1(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	payload := `{"schema_version":"1","entries":{"rule-x":"CWE-89","rule-y":"CWE-79"}}`
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	got, err := loadMappingFile(plug)
	if err != nil {
		t.Fatalf("loadMappingFile: %v", err)
	}
	if got["rule-x"] != "CWE-89" {
		t.Errorf("rule-x = %q; want CWE-89", got["rule-x"])
	}
	if got["rule-y"] != "CWE-79" {
		t.Errorf("rule-y = %q; want CWE-79", got["rule-y"])
	}
	if len(got) != 2 {
		t.Errorf("len(entries) = %d; want 2", len(got))
	}
}

// AC 10: virtual plugin (empty Path) with non-empty mapping_file is rejected.
func TestLoadMappingFile_VirtualPlugin_AC10(t *testing.T) {
	plug := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name:        "semgrep",
				Version:     "1.0.0",
				APIVersion:  pluginregistry.APIVersionV1,
				Publisher:   "x",
				Description: "y",
			},
			Trust:   pluginregistry.TrustBlock{Tier: pluginregistry.TierInTree},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree, ModulePath: "x"},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan, Emits: []string{"finding"},
			}},
			Normalization: pluginregistry.NormalizationBlock{
				MappingFile: "rules/m.json",
			},
		},
		Path:    "", // virtual
		Enabled: true,
	}
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileVirtualPlugin) {
		t.Fatalf("err = %v; want ErrMappingFileVirtualPlugin", err)
	}
}

// AC 9e: empty / whitespace-only mapping_file is a silent no-op — empty
// map + nil error. This case is the default for plugins without external
// mappings and must not warn.
func TestLoadMappingFile_EmptyMappingFile_AC9e(t *testing.T) {
	dir := t.TempDir()

	for _, mf := range []string{"", "   ", "\t  \n"} {
		t.Run(fmt.Sprintf("mf=%q", mf), func(t *testing.T) {
			plug := mkPluginWithMappingFile(dir, mf)
			got, err := loadMappingFile(plug)
			if err != nil {
				t.Fatalf("expected nil error for empty mapping_file; got %v", err)
			}
			if len(got) != 0 {
				t.Errorf("expected empty map for empty mapping_file; got %d entries", len(got))
			}
		})
	}
}

// AC 7: missing file → ErrMappingFileMissing.
func TestLoadMappingFile_MissingFile_AC7(t *testing.T) {
	dir := t.TempDir()
	plug := mkPluginWithMappingFile(dir, "rules/does-not-exist.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileMissing) {
		t.Fatalf("err = %v; want ErrMappingFileMissing", err)
	}
}

// AC 8: malformed JSON → ErrMappingFileBadJSON.
func TestLoadMappingFile_MalformedJSON_AC8(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), []byte(`{not valid json`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileBadJSON) {
		t.Fatalf("err = %v; want ErrMappingFileBadJSON", err)
	}
}

// AC 3: schema_version != "1" → ErrMappingFileSchemaVersion.
func TestLoadMappingFile_SchemaVersionMismatch_AC3(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	payload := `{"schema_version":"2","entries":{"rule-x":"CWE-89"}}`
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileSchemaVersion) {
		t.Fatalf("err = %v; want ErrMappingFileSchemaVersion", err)
	}
}

// AC 4: > MaxNormalisationEntries → ErrMappingFileTooManyEntries.
func TestLoadMappingFile_OverCardinality_AC4(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	// 10001 entries — one above the cap.
	entries := make(map[string]string, pluginregistry.MaxNormalisationEntries+1)
	for i := 0; i <= pluginregistry.MaxNormalisationEntries; i++ {
		entries[fmt.Sprintf("rule-%d", i)] = "CWE-89"
	}
	payload, err := json.Marshal(map[string]any{
		"schema_version": "1",
		"entries":        entries,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err = loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileTooManyEntries) {
		t.Fatalf("err = %v; want ErrMappingFileTooManyEntries", err)
	}
}

// AC 9d: file > 16 MiB → ErrMappingFileTooLarge, no JSON parse.
// BLOCKER #2 fix: post-read length check, not io.LimitReader.
func TestLoadMappingFile_OverSize_AC9d(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	// Build a 17 MiB file. Content is intentionally not valid JSON; the
	// length check should reject before JSON parse, so size-rejection
	// must win over bad-json detection.
	big := make([]byte, 17*1024*1024)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), big, 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileTooLarge) {
		t.Fatalf("err = %v; want ErrMappingFileTooLarge", err)
	}
}

// AC 9 / BLOCKER #3: per-entry skip on invalid CWE, not file-level fail.
// 9999 valid + 1 "NOT-CWE" entry → returns exactly 9999 entries + nil err.
func TestLoadMappingFile_PerEntryInvalidCWE_AC9_BLOCKER3(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	entries := make(map[string]string, 10000)
	for i := 0; i < 9999; i++ {
		entries[fmt.Sprintf("rule-%d", i)] = "CWE-89"
	}
	entries["rule-bad"] = "NOT-CWE"
	payload, err := json.Marshal(map[string]any{
		"schema_version": "1",
		"entries":        entries,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	got, err := loadMappingFile(plug)
	if err != nil {
		t.Fatalf("expected nil error (per-entry skip); got %v", err)
	}
	if len(got) != 9999 {
		t.Errorf("len(entries) = %d; want 9999 (the one bad entry must be skipped, not the whole file)", len(got))
	}
	if _, present := got["rule-bad"]; present {
		t.Errorf("rule-bad should have been skipped; was kept with value %q", got["rule-bad"])
	}
}

// AC 5: classic traversal → ErrMappingFileOutsideDir.
// Also: BLOCKER #1 specific case — sibling-dir attack
// (manifestDir="/tmp/plug-test", mapping_file="../plug-test-evil/x.json").
func TestLoadMappingFile_TraversalRejected_AC5(t *testing.T) {
	t.Run("classic_dotdot", func(t *testing.T) {
		dir := t.TempDir()
		plug := mkPluginWithMappingFile(dir, "../../etc/passwd")
		_, err := loadMappingFile(plug)
		if !errors.Is(err, ErrMappingFileOutsideDir) {
			t.Fatalf("err = %v; want ErrMappingFileOutsideDir", err)
		}
	})

	t.Run("sibling_dir_attack_BLOCKER1", func(t *testing.T) {
		// Re-create the LLD's BLOCKER #1 scenario inside a private temp
		// root. manifestDir is /<tempRoot>/plug-test; the attacking
		// mapping_file points at /<tempRoot>/plug-test-evil/x.json.
		// strings.HasPrefix(cleaned, manifestDir) would be true under
		// the naive impl, but the corrected separator-suffixed check
		// must reject.
		root := t.TempDir()
		good := filepath.Join(root, "plug-test")
		evil := filepath.Join(root, "plug-test-evil")
		if err := os.MkdirAll(good, 0o755); err != nil {
			t.Fatalf("mkdir good: %v", err)
		}
		if err := os.MkdirAll(evil, 0o755); err != nil {
			t.Fatalf("mkdir evil: %v", err)
		}
		// Even materialise the file the attacker would target.
		if err := os.WriteFile(filepath.Join(evil, "x.json"),
			[]byte(`{"schema_version":"1","entries":{"x":"CWE-89"}}`), 0o644); err != nil {
			t.Fatalf("write attacker file: %v", err)
		}
		plug := mkPluginWithMappingFile(good, "../plug-test-evil/x.json")
		_, err := loadMappingFile(plug)
		if !errors.Is(err, ErrMappingFileOutsideDir) {
			t.Fatalf("sibling-dir traversal not rejected: err = %v; want ErrMappingFileOutsideDir", err)
		}
	})
}

// AC 6: file IS a symlink → ErrMappingFileSymlinkUnsafe.
func TestLoadMappingFile_SymlinkFinalComponent_AC6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	// Create a real file outside the manifest dir.
	real := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(real, []byte(`{"schema_version":"1","entries":{"x":"CWE-89"}}`), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}
	// Symlink rules/m.json → real.json (target lives outside manifestDir).
	linkPath := filepath.Join(dir, "rules", "m.json")
	if err := os.Symlink(real, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileSymlinkUnsafe) {
		t.Fatalf("err = %v; want ErrMappingFileSymlinkUnsafe", err)
	}
}

// AC 9c / MAJOR #4: intermediate directory is a symlink → reject.
// filepath.EvalSymlinks must catch the divergence even though the final
// component is just a filename.
func TestLoadMappingFile_SymlinkIntermediateDir_AC9c_MAJOR4(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	// Build a real target dir holding a sensible file.
	target := filepath.Join(t.TempDir(), "real-rules")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "m.json"),
		[]byte(`{"schema_version":"1","entries":{"x":"CWE-89"}}`), 0o644); err != nil {
		t.Fatalf("write file in target: %v", err)
	}
	// Make manifestDir/rules a symlink to that target.
	if err := os.Symlink(target, filepath.Join(dir, "rules")); err != nil {
		t.Fatalf("symlink intermediate dir: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	_, err := loadMappingFile(plug)
	if !errors.Is(err, ErrMappingFileSymlinkUnsafe) {
		t.Fatalf("err = %v; want ErrMappingFileSymlinkUnsafe (intermediate dir is a symlink)", err)
	}
}

// MAJOR #5: at-cap succeeds, cap+1 fails — asserts the loader CONSUMES
// pluginregistry.MaxNormalisationEntries (rather than duplicating a
// local copy). Reading the constant here pins the source-of-truth.
func TestLoadMappingFile_UsesExportedCardinalityConstant_MAJOR5(t *testing.T) {
	// Sanity: the exported constant must be visible at compile time.
	cap := pluginregistry.MaxNormalisationEntries
	if cap <= 0 {
		t.Fatalf("MaxNormalisationEntries = %d; want >0", cap)
	}

	t.Run("at_cap_succeeds", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
			t.Fatalf("mkdir rules: %v", err)
		}
		entries := make(map[string]string, cap)
		for i := 0; i < cap; i++ {
			entries[fmt.Sprintf("rule-%d", i)] = "CWE-89"
		}
		payload, err := json.Marshal(map[string]any{
			"schema_version": "1",
			"entries":        entries,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), payload, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		plug := mkPluginWithMappingFile(dir, "rules/m.json")
		got, err := loadMappingFile(plug)
		if err != nil {
			t.Fatalf("at-cap load failed: %v", err)
		}
		if len(got) != cap {
			t.Errorf("len(entries) = %d; want %d", len(got), cap)
		}
	})

	t.Run("cap_plus_one_fails", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
			t.Fatalf("mkdir rules: %v", err)
		}
		entries := make(map[string]string, cap+1)
		for i := 0; i <= cap; i++ {
			entries[fmt.Sprintf("rule-%d", i)] = "CWE-89"
		}
		payload, err := json.Marshal(map[string]any{
			"schema_version": "1",
			"entries":        entries,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), payload, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		plug := mkPluginWithMappingFile(dir, "rules/m.json")
		_, err = loadMappingFile(plug)
		if !errors.Is(err, ErrMappingFileTooManyEntries) {
			t.Fatalf("err = %v; want ErrMappingFileTooManyEntries (cap+1 entries)", err)
		}
	})
}

// MINOR #9: the loader's per-entry validation MUST use the exported
// pluginregistry.CWERe regex. We pin its observable behaviour here
// (matches CWE-89, rejects NOT-CWE) so a divergent loader-local copy
// would be caught.
func TestLoadMappingFile_UsesExportedCWERe_MINOR9(t *testing.T) {
	// Direct behavioural pin on the exported regex itself.
	if !pluginregistry.CWERe.MatchString("CWE-89") {
		t.Fatalf("pluginregistry.CWERe must match \"CWE-89\"")
	}
	if pluginregistry.CWERe.MatchString("NOT-CWE") {
		t.Fatalf("pluginregistry.CWERe must reject \"NOT-CWE\"")
	}

	// Behavioural assertion via the loader: the per-entry filter must
	// agree with the exported regex on a representative mix.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	payload := `{"schema_version":"1","entries":{
		"good-1":"CWE-89",
		"good-2":"CWE-79",
		"bad-1":"NOT-CWE",
		"bad-2":"cwe-89",
		"bad-3":"CWE-",
		"bad-4":""
	}}`
	if err := os.WriteFile(filepath.Join(dir, "rules", "m.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	plug := mkPluginWithMappingFile(dir, "rules/m.json")
	got, err := loadMappingFile(plug)
	if err != nil {
		t.Fatalf("loadMappingFile: %v", err)
	}
	// Only the two CWERe-matching values should survive.
	wantKept := map[string]string{"good-1": "CWE-89", "good-2": "CWE-79"}
	if len(got) != len(wantKept) {
		t.Errorf("kept %d entries; want %d", len(got), len(wantKept))
	}
	for k, v := range wantKept {
		if got[k] != v {
			t.Errorf("got[%q] = %q; want %q", k, got[k], v)
		}
	}
	for badKey := range map[string]struct{}{"bad-1": {}, "bad-2": {}, "bad-3": {}, "bad-4": {}} {
		if _, present := got[badKey]; present {
			t.Errorf("%s should have been skipped by CWERe; was kept with value %q", badKey, got[badKey])
		}
	}
}

// Defensive: a sentinel error wrap must keep errors.Is matching even when
// the loader formats additional context into its return value. Pins the
// "tests use errors.Is" contract from the LLD.
func TestLoadMappingFile_SentinelErrorsAreWrapped(t *testing.T) {
	dir := t.TempDir()
	plug := mkPluginWithMappingFile(dir, "rules/does-not-exist.json")
	_, err := loadMappingFile(plug)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, ErrMappingFileMissing) {
		t.Fatalf("errors.Is(err, ErrMappingFileMissing) = false; err = %v", err)
	}
	// The wrapped error string should still include some context. (We do
	// not pin the exact format; we only assert it is non-trivial.)
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("error string must not be blank")
	}
}
