package cwe

// RED-phase tests for feature 0050: CWE Normalisation Engine.
//
// These tests are written BEFORE the implementation. They reference
// the Layer interface, New, and NewFromMaps constructors that the
// GREEN-phase agent will add in layer.go / embed.go. Until that
// lands, this file will fail to compile — that IS the expected
// RED state. The acceptance criteria each test covers are encoded
// in the test name suffix (AC#).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// helper: build a layer that has ONE plugin's normalization maps
// merged in. Used by tests that want to verify per-plugin scoping.
func mkLayerWithPlugin(t *testing.T, pluginName string, ruleToCWE, prefixToCWE map[string]string) Layer {
	t.Helper()
	return NewFromMaps(
		map[string]map[string]string{pluginName: ruleToCWE},
		map[string]map[string]string{pluginName: prefixToCWE},
		nil, // no system category map
		nil, // no system check-id prefix map
	)
}

// AC 1: per-plugin rule_to_cwe must beat the canonical short-circuit.
// Even when Category looks like "CWE-89", a plugin's mapping for the
// specific CheckID wins. This is the BLOCKER #3 fix: per-plugin rules
// ALWAYS win, even over canonical-looking categories.
func TestLayer_PluginRuleBeatsCanonicalCategory_AC1(t *testing.T) {
	layer := mkLayerWithPlugin(t, "semgrep",
		map[string]string{"rule-X": "CWE-564"},
		nil)

	got := layer.Normalize("semgrep", "CWE-89", "rule-X")
	if got != "CWE-564" {
		t.Errorf("Normalize(semgrep, CWE-89, rule-X) = %q; want CWE-564 (plugin rule wins over canonical category)", got)
	}
}

// AC 2: plugin prefix map wins over the system category fallback.
// Finding's Category is the well-known OWASP A03 string, but the
// plugin's prefix mapping should fire first.
func TestLayer_PluginPrefixBeatsSystemCategory_AC2(t *testing.T) {
	layer := NewFromMaps(
		nil,
		map[string]map[string]string{
			"semgrep": {"semgrep.python.sql.": "CWE-943"},
		},
		// System would map A03-injection → CWE-89, but plugin prefix
		// must beat it.
		map[string]string{"A03-injection": "CWE-89"},
		nil,
	)

	got := layer.Normalize("semgrep", "A03-injection", "semgrep.python.sql.injection")
	if got != "CWE-943" {
		t.Errorf("Normalize(semgrep, A03-injection, semgrep.python.sql.injection) = %q; want CWE-943 (plugin prefix wins)", got)
	}
}

// AC 3: longest-prefix accumulator must beat shorter-prefix matches
// REGARDLESS of map iteration order. We run the assertion many times
// to stress Go's randomised map iteration and confirm determinism.
func TestLayer_LongestPrefixWins_AC3(t *testing.T) {
	layer := mkLayerWithPlugin(t, "semgrep", nil, map[string]string{
		"python.":                                  "CWE-693",
		"python.django.security.sql-injection":     "CWE-89",
		"python.django.":                           "CWE-20",
	})

	const checkID = "python.django.security.sql-injection.unsafe-raw"
	// Iterate many times — Go's map iteration order is randomised, so
	// a buggy implementation that takes "first match" would fail
	// intermittently. Determinism is the contract.
	for i := 0; i < 200; i++ {
		got := layer.Normalize("semgrep", "anything", checkID)
		if got != "CWE-89" {
			t.Fatalf("iter %d: Normalize(checkID=%q) = %q; want CWE-89 (longest prefix wins regardless of map order)", i, checkID, got)
		}
	}
}

// AC 4: system CheckID prefix beats system Category — at the SYSTEM
// level, the more-specific check_id_prefix match overrides the coarser
// category map. MAJOR #6 fix.
func TestLayer_SystemCheckIDPrefixBeatsSystemCategory_AC4(t *testing.T) {
	layer := NewFromMaps(
		nil, nil,
		// System category map says A03-injection → CWE-89.
		map[string]string{"A03-injection": "CWE-89"},
		// System check_id_prefix says owasp.injection.command → CWE-78.
		map[string]string{"owasp.injection.command": "CWE-78"},
	)

	got := layer.Normalize("owasp", "A03-injection", "owasp.injection.command")
	if got != "CWE-78" {
		t.Errorf("system: Normalize(owasp, A03-injection, owasp.injection.command) = %q; want CWE-78 (CheckID prefix beats Category)", got)
	}
}

// AC 5: canonical short-circuit (cheap path) — when no plugin or
// system rules match, a Category already in CWE-NNN form returns
// as-is.
func TestLayer_CanonicalShortCircuit_AC5(t *testing.T) {
	layer := NewFromMaps(nil, nil, nil, nil)

	got := layer.Normalize("cwe", "CWE-89", "")
	if got != "CWE-89" {
		t.Errorf("canonical short-circuit: Normalize(cwe, CWE-89, \"\") = %q; want CWE-89", got)
	}
}

// AC 6: composite canonical — when Category is a pipe-separated list
// of canonical CWE IDs (xss-agent style), return the FIRST.
func TestLayer_CompositeCanonical_FirstWins_AC6(t *testing.T) {
	layer := NewFromMaps(nil, nil, nil, nil)

	got := layer.Normalize("xss", "CWE-79|CWE-113|CWE-644|CWE-1336", "")
	if got != "CWE-79" {
		t.Errorf("composite canonical: got %q; want CWE-79 (first of pipe-separated list)", got)
	}
}

// AC 7: completely unknown input → empty string, never a panic.
func TestLayer_NoMatchReturnsEmpty_AC7(t *testing.T) {
	layer := NewFromMaps(nil, nil, nil, nil)

	cases := []struct {
		name, agentType, category, checkID string
	}{
		{"all garbage", "zz", "garbage", "garbage"},
		{"empty all", "", "", ""},
		{"whitespace category", "any", "   ", ""},
		{"only nonsense check id", "any", "nonsense", "no.prefix.matches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := layer.Normalize(tc.agentType, tc.category, tc.checkID)
			if got != "" {
				t.Errorf("Normalize(%q, %q, %q) = %q; want \"\"",
					tc.agentType, tc.category, tc.checkID, got)
			}
		})
	}
}

// AC 8: cross-language contract test. Every in-tree non-CWE,
// non-arbitrary category string emitted by `agents/*/skills/*.py`
// MUST resolve to a non-empty CWE through the default (registry-built)
// Layer. The string list below was produced by grepping the actual
// Python skill files at the time this test was written.
//
// Drift between Python skill emission and Go's category map will
// fail this test loudly at CI time, which is the entire point of
// the contract.
//
// Note: pure CWE-* categories (e.g. "CWE-89") are excluded — they
// hit the canonical short-circuit and are uninteresting from a
// drift-detection standpoint. Agent-internal "category" values that
// are not standardised compliance/owasp/ssdf strings (e.g.
// "blast-radius", "retry-pattern", "dead_code", "malloc") are
// also excluded — they are chaos/c-runtime-specific labels that
// don't have a stable CWE mapping in v1.0 and are explicitly NOT
// part of the system baseline data (see LLD §"System baseline data").
func TestLayer_InTreeCategoriesAllMap_AC8(t *testing.T) {
	// Use the default registry-built layer — same code path the
	// production server uses. A nil registry yields a system-only
	// layer (per LLD §"Reliability").
	layer := New(nil)

	// These are the standardised category strings emitted by the
	// in-tree agents (owasp, ssdf). Hard-coded list (not derived
	// at runtime) so a Python-side rename of any of them fails the
	// test rather than silently passing.
	contractCategories := []string{
		// OWASP Top 10
		"A01-access-control",
		"A02-crypto-failure",
		"A03-injection",
		"A04-insecure-design",
		"A05-security-misconfig",
		"A06-vulnerable-components",
		"A07-auth-failure",
		"A08-data-integrity",
		"A09-logging-failure",
		"A10-ssrf",
		// NIST SSDF v1.1
		"PO-prepare-organization",
		"PS-protect-software",
		"PW-produce-well-secured-software",
		"RV-respond-to-vulnerabilities",
	}

	for _, cat := range contractCategories {
		t.Run(cat, func(t *testing.T) {
			// AgentType is intentionally generic — the system
			// category map is plugin-agnostic.
			got := layer.Normalize("owasp", cat, "")
			if got == "" {
				t.Errorf("contract: Normalize(owasp, %q, \"\") returned empty; system category_to_cwe.json must cover this string", cat)
			}
		})
	}
}

// AC 11: VULTURE_CWE_SYSTEM_MAP_DIR allows operators to override the
// embedded baseline without rebuilding. A file in the override dir
// with the same name as the embedded JSON must take precedence (or
// be merged last-write-wins).
func TestLayer_OperatorOverride_VULTURE_CWE_SYSTEM_MAP_DIR_AC11(t *testing.T) {
	dir := t.TempDir()
	overridePath := filepath.Join(dir, "category_to_cwe.json")
	overrideJSON := []byte(`{"A03-injection": "CWE-9999"}`)
	if err := os.WriteFile(overridePath, overrideJSON, 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	t.Setenv("VULTURE_CWE_SYSTEM_MAP_DIR", dir)

	// `New(nil)` re-reads the override env var at construction time.
	layer := New(nil)
	got := layer.Normalize("owasp", "A03-injection", "")
	if got != "CWE-9999" {
		t.Errorf("override: Normalize(owasp, A03-injection, \"\") = %q; want CWE-9999 (override JSON in VULTURE_CWE_SYSTEM_MAP_DIR must take precedence)", got)
	}
}

// AC 11 sub-case: missing/unreadable override files fall back to
// embedded defaults without erroring or panicking. Defensive: an
// operator typo in the dir path must not break normalisation.
func TestLayer_OperatorOverride_MissingDirFallsBack_AC11(t *testing.T) {
	t.Setenv("VULTURE_CWE_SYSTEM_MAP_DIR", "/does/not/exist/anywhere")

	layer := New(nil)
	// A03-injection should still resolve from the embedded defaults.
	got := layer.Normalize("owasp", "A03-injection", "")
	if got == "" {
		t.Errorf("missing override dir must fall back to embedded defaults; got empty for A03-injection")
	}
}

// Defensive: a Layer built via New(nil) must never panic on any
// pathological input combo. Documented in LLD §"Reliability + chaos".
func TestLayer_NeverPanicsOnEmpty(t *testing.T) {
	layer := New(nil)

	// Must not panic; return value irrelevant.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Layer.Normalize panicked on empty input: %v", r)
		}
	}()
	_ = layer.Normalize("", "", "")
}

// Reference-only: this test exists to pin the resolution-order
// contract end-to-end (LLD §"Resolution order"). Each row of the
// table represents one branch of the order; the assertion checks
// that the branch labelled "winner" actually wins given all the
// lower-priority branches set up to "lose".
func TestLayer_ResolutionOrder_FullTable(t *testing.T) {
	cases := []struct {
		name      string
		layer     Layer
		agentType string
		category  string
		checkID   string
		want      string
		why       string
	}{
		{
			name: "1_plugin_rule_to_cwe_wins_over_everything",
			layer: NewFromMaps(
				map[string]map[string]string{"semgrep": {"rule-X": "CWE-1"}},
				map[string]map[string]string{"semgrep": {"rule-": "CWE-2"}},
				map[string]string{"CWE-3": "CWE-3"},
				map[string]string{"rule-": "CWE-4"},
			),
			agentType: "semgrep", category: "CWE-3", checkID: "rule-X",
			want: "CWE-1", why: "plugin rule_to_cwe is step 1, highest priority",
		},
		{
			name: "2_plugin_prefix_wins_when_no_rule",
			layer: NewFromMaps(
				nil,
				map[string]map[string]string{"semgrep": {"rule-": "CWE-2"}},
				map[string]string{"CWE-3": "CWE-3"},
				map[string]string{"rule-": "CWE-4"},
			),
			agentType: "semgrep", category: "CWE-3", checkID: "rule-X",
			want: "CWE-2", why: "plugin prefix is step 2, must beat canonical short-circuit (step 3)",
		},
		{
			name: "3_canonical_short_circuit_when_no_plugin_match",
			layer: NewFromMaps(
				nil, nil,
				nil,
				map[string]string{"sys-prefix.": "CWE-99"},
			),
			agentType: "cwe", category: "CWE-89", checkID: "no.match",
			want: "CWE-89", why: "canonical short-circuit is step 3",
		},
		{
			name: "5_system_checkid_prefix_when_no_canonical",
			layer: NewFromMaps(
				nil, nil,
				map[string]string{"A03-injection": "CWE-89-via-category"},
				map[string]string{"owasp.injection.command": "CWE-78"},
			),
			agentType: "owasp", category: "A03-injection", checkID: "owasp.injection.command.shell",
			want: "CWE-78", why: "system check_id_prefix (step 5) beats system category (step 6)",
		},
		{
			name: "6_system_category_when_no_prefix",
			layer: NewFromMaps(
				nil, nil,
				map[string]string{"A03-injection": "CWE-89"},
				nil,
			),
			agentType: "owasp", category: "A03-injection", checkID: "",
			want: "CWE-89", why: "system category map (step 6) — last positive step",
		},
		{
			name: "7_empty_when_nothing_matches",
			layer: NewFromMaps(nil, nil, nil, nil),
			agentType: "zz", category: "unknown", checkID: "unknown.id",
			want: "", why: "step 7 fallthrough",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.layer.Normalize(tc.agentType, tc.category, tc.checkID)
			if got != tc.want {
				t.Errorf("Normalize(%q, %q, %q) = %q; want %q (reason: %s)",
					tc.agentType, tc.category, tc.checkID, got, tc.want, tc.why)
			}
		})
	}
}

// LLD §"Per-plugin scoping correctness": per-plugin maps must NOT
// pollute other plugins' findings. A finding emitted by "owasp"
// must not be normalised by semgrep's rule_to_cwe map.
func TestLayer_PerPluginScopeIsolation(t *testing.T) {
	layer := mkLayerWithPlugin(t, "semgrep",
		map[string]string{"rule-X": "CWE-564"},
		nil)

	// Same CheckID, but emitted by a different agent. semgrep's
	// rule_to_cwe must NOT apply.
	got := layer.Normalize("owasp", "garbage", "rule-X")
	if got != "" {
		t.Errorf("per-plugin scope leaked: Normalize(owasp, garbage, rule-X) = %q; want \"\" (semgrep rule_to_cwe must not apply to owasp findings)", got)
	}
}

// Layer constructed from a real pluginregistry.Registry must read
// per-plugin maps via the manifest's NormalizationBlock. This is
// the public-API path; New(registry) without NewFromMaps.
func TestLayer_NewReadsRegistryNormalizationBlock(t *testing.T) {
	plug := pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name: "semgrep", Version: "1.0.0", APIVersion: pluginregistry.APIVersionV1,
				Publisher: "x", Description: "y",
			},
			Trust:   pluginregistry.TrustBlock{Tier: pluginregistry.TierCommunitySigned, Signature: "cosign://example/x"},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeContainer, Image: "x:1", Port: 28999},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan, Emits: []string{"finding", "result"},
			}},
			Normalization: pluginregistry.NormalizationBlock{
				RuleToCWE:   map[string]string{"semgrep.python.sql-1": "CWE-89"},
				PrefixToCWE: map[string]string{"semgrep.python.django.": "CWE-89"},
			},
		},
		Source:  "local",
		Enabled: true,
	}

	reg := &cweTestRegistry{plugins: []pluginregistry.Plugin{plug}}
	layer := New(reg)

	// rule_to_cwe exact-match must fire even when category is empty.
	if got := layer.Normalize("semgrep", "", "semgrep.python.sql-1"); got != "CWE-89" {
		t.Errorf("registry-read rule_to_cwe: got %q, want CWE-89", got)
	}
	// prefix_to_cwe must also fire.
	if got := layer.Normalize("semgrep", "", "semgrep.python.django.unsafe-raw"); got != "CWE-89" {
		t.Errorf("registry-read prefix_to_cwe: got %q, want CWE-89", got)
	}
}

// cweTestRegistry is a tiny in-package stand-in for
// pluginregistry.Registry. We can't import the fakeRegistry from
// stagerouter (different package) so we re-declare a minimal one.
type cweTestRegistry struct {
	plugins []pluginregistry.Plugin
}

func (r *cweTestRegistry) All() []pluginregistry.Plugin { return r.plugins }
func (r *cweTestRegistry) Enabled() []pluginregistry.Plugin {
	out := make([]pluginregistry.Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}
func (r *cweTestRegistry) ByName(name string) (pluginregistry.Plugin, bool) {
	for _, p := range r.plugins {
		if p.Name() == name {
			return p, true
		}
	}
	return pluginregistry.Plugin{}, false
}

// ---------------------------------------------------------------------------
// Feature 0050 v1.1 — mapping_file external loader (RED phase additions).
// ---------------------------------------------------------------------------

// helper used by the v1.1 tests below: builds a Plugin with a real
// on-disk Path so the loader can resolve mapping_file relative to it.
func mkPluginAtPath(name, path string, inline map[string]string, mappingFile string) pluginregistry.Plugin {
	return pluginregistry.Plugin{
		Manifest: pluginregistry.Manifest{
			Plugin: pluginregistry.PluginBlock{
				Name: name, Version: "1.0.0", APIVersion: pluginregistry.APIVersionV1,
				Publisher: "x", Description: "y",
			},
			Trust:   pluginregistry.TrustBlock{Tier: pluginregistry.TierInTree},
			Runtime: pluginregistry.RuntimeBlock{Type: pluginregistry.RuntimeInTree, ModulePath: "x"},
			Capabilities: []pluginregistry.Capability{{
				Phase: pluginregistry.PhaseScan, Emits: []string{"finding", "result"},
			}},
			Normalization: pluginregistry.NormalizationBlock{
				RuleToCWE:   inline,
				MappingFile: mappingFile,
			},
		},
		Source:  "local",
		Path:    path,
		Enabled: true,
	}
}

// AC 1 (v1.1): Layer.New(registry) loads the external mapping_file and
// merges its entries into the per-plugin rule_to_cwe map.
func TestLayer_New_LoadsMappingFile_AC1(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "semgrep")
	if err := os.MkdirAll(filepath.Join(pluginDir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pluginToml := filepath.Join(pluginDir, "plugin.toml")
	if err := os.WriteFile(pluginToml, []byte(""), 0o644); err != nil {
		t.Fatalf("write plugin.toml stub: %v", err)
	}
	payload := `{"schema_version":"1","entries":{"rule-x":"CWE-89"}}`
	if err := os.WriteFile(filepath.Join(pluginDir, "rules", "m.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write mapping_file: %v", err)
	}

	plug := mkPluginAtPath("semgrep", pluginToml, nil, "rules/m.json")
	reg := &cweTestRegistry{plugins: []pluginregistry.Plugin{plug}}
	layer := New(reg)

	if got := layer.Normalize("semgrep", "anything", "rule-x"); got != "CWE-89" {
		t.Errorf("Normalize(semgrep, anything, rule-x) = %q; want CWE-89 (loaded from external mapping_file)", got)
	}
}

// AC 2 (v1.1): inline rule_to_cwe wins over external mapping_file when
// both define the same rule_id.
func TestLayer_New_InlineWinsOverExternal_AC2(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "semgrep")
	if err := os.MkdirAll(filepath.Join(pluginDir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pluginToml := filepath.Join(pluginDir, "plugin.toml")
	if err := os.WriteFile(pluginToml, []byte(""), 0o644); err != nil {
		t.Fatalf("write plugin.toml stub: %v", err)
	}
	// External says CWE-89; inline says CWE-79 — inline must win.
	payload := `{"schema_version":"1","entries":{"rule-x":"CWE-89"}}`
	if err := os.WriteFile(filepath.Join(pluginDir, "rules", "m.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write mapping_file: %v", err)
	}

	plug := mkPluginAtPath("semgrep", pluginToml,
		map[string]string{"rule-x": "CWE-79"},
		"rules/m.json")
	reg := &cweTestRegistry{plugins: []pluginregistry.Plugin{plug}}
	layer := New(reg)

	if got := layer.Normalize("semgrep", "anything", "rule-x"); got != "CWE-79" {
		t.Errorf("inline must win over external: got %q; want CWE-79", got)
	}
}

// LLD §Reliability: a missing mapping_file must NOT break Layer
// construction. Inline entries continue to work; the plugin simply
// loses its external contributions.
func TestLayer_New_GracefulDegradationOnLoadError(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "semgrep")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pluginToml := filepath.Join(pluginDir, "plugin.toml")
	if err := os.WriteFile(pluginToml, []byte(""), 0o644); err != nil {
		t.Fatalf("write plugin.toml stub: %v", err)
	}
	// mapping_file references a file that doesn't exist; inline still has
	// a valid mapping for rule-y.
	plug := mkPluginAtPath("semgrep", pluginToml,
		map[string]string{"rule-y": "CWE-22"},
		"rules/missing.json")
	reg := &cweTestRegistry{plugins: []pluginregistry.Plugin{plug}}

	// Construction must not panic, even though the external file is missing.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Layer.New panicked on missing mapping_file: %v", r)
		}
	}()
	layer := New(reg)

	if got := layer.Normalize("semgrep", "anything", "rule-y"); got != "CWE-22" {
		t.Errorf("inline rule must still resolve: got %q; want CWE-22", got)
	}
	// The external entry obviously is not present.
	if got := layer.Normalize("semgrep", "anything", "rule-from-missing-file"); got != "" {
		t.Errorf("missing-external rule must not resolve: got %q; want \"\"", got)
	}
}

// AC 11 (v1.1): vulture-on-vulture. The bundled Semgrep plugin
// scenario: realistic rule_id values map through the external file to
// the expected CWE.
func TestLayer_New_BuiltinPlugin_AC11_VultureOnVulture(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "semgrep")
	if err := os.MkdirAll(filepath.Join(pluginDir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pluginToml := filepath.Join(pluginDir, "plugin.toml")
	if err := os.WriteFile(pluginToml, []byte(""), 0o644); err != nil {
		t.Fatalf("write plugin.toml stub: %v", err)
	}
	payload := `{"schema_version":"1","entries":{
		"python.django.security.unsafe-raw-sql":"CWE-89",
		"python.cryptography.fernet":"CWE-310",
		"javascript.express.audit.xss":"CWE-79"
	}}`
	if err := os.WriteFile(filepath.Join(pluginDir, "rules", "sem.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write mapping_file: %v", err)
	}

	plug := mkPluginAtPath("semgrep", pluginToml, nil, "rules/sem.json")
	reg := &cweTestRegistry{plugins: []pluginregistry.Plugin{plug}}
	layer := New(reg)

	cases := []struct {
		checkID string
		wantCWE string
	}{
		{"python.django.security.unsafe-raw-sql", "CWE-89"},
		{"python.cryptography.fernet", "CWE-310"},
		{"javascript.express.audit.xss", "CWE-79"},
	}
	for _, tc := range cases {
		t.Run(tc.checkID, func(t *testing.T) {
			got := layer.Normalize("semgrep", "", tc.checkID)
			if got != tc.wantCWE {
				t.Errorf("Normalize(semgrep, \"\", %q) = %q; want %q",
					tc.checkID, got, tc.wantCWE)
			}
		})
	}
}
