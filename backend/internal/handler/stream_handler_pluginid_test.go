package handler

import (
	"encoding/json"
	"testing"

	"github.com/vulture/backend/internal/model"
)

// snapshotJSON builds a StateSnapshot-style payload carrying a single finding
// with the supplied id (empty for native, non-empty for plugin-supplied).
func snapshotJSON(t *testing.T, id string) json.RawMessage {
	t.Helper()
	payload := map[string]interface{}{
		"findings": []map[string]interface{}{
			{
				"id":        id,
				"title":     "Hardcoded Secret",
				"file_path": "src/a.py",
				"category":  "secrets",
				"severity":  "high",
			},
		},
		"score": 80.0,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return b
}

func deltaAddJSON(t *testing.T, id string) json.RawMessage {
	t.Helper()
	finding := map[string]interface{}{
		"id":        id,
		"title":     "Hardcoded Secret",
		"file_path": "src/a.py",
		"category":  "secrets",
		"severity":  "high",
	}
	fb, _ := json.Marshal(finding)
	patches := []map[string]interface{}{
		{"op": "add", "path": "/findings/-", "value": json.RawMessage(fb)},
	}
	b, err := json.Marshal(patches)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	return b
}

// TestParseSnapshot_PluginIdNamespacedPerAudit proves a deterministic plugin id
// produces distinct persisted ids across audits (so ON CONFLICT can't drop the
// re-scan) while the fingerprint stays cross-audit stable.
func TestParseSnapshot_PluginIdNamespacedPerAudit(t *testing.T) {
	const rawID = "rules.foo:src/a.py:10"

	var f1, f2 []model.Finding
	parseSnapshot(snapshotJSON(t, rawID), "A1", "semgrep", &f1, map[string]int{})
	parseSnapshot(snapshotJSON(t, rawID), "A2", "semgrep", &f2, map[string]int{})

	if len(f1) != 1 || len(f2) != 1 {
		t.Fatalf("expected 1 finding each, got %d and %d", len(f1), len(f2))
	}
	if f1[0].ID == f2[0].ID {
		t.Fatalf("plugin id should be namespaced per audit, but both audits got %q", f1[0].ID)
	}
	if want := namespaceFindingID("A1", rawID); f1[0].ID != want {
		t.Errorf("A1 id = %q, want %q", f1[0].ID, want)
	}
	if want := namespaceFindingID("A2", rawID); f2[0].ID != want {
		t.Errorf("A2 id = %q, want %q", f2[0].ID, want)
	}
	if f1[0].Fingerprint != f2[0].Fingerprint {
		t.Errorf("fingerprint should be cross-audit stable: %q != %q", f1[0].Fingerprint, f2[0].Fingerprint)
	}
}

func TestExtractDeltaFindings_PluginIdNamespaced(t *testing.T) {
	const rawID = "rules.foo:src/a.py:10"

	var f1, f2 []model.Finding
	extractDeltaFindings(deltaAddJSON(t, rawID), "A1", "semgrep", &f1)
	extractDeltaFindings(deltaAddJSON(t, rawID), "A2", "semgrep", &f2)

	if len(f1) != 1 || len(f2) != 1 {
		t.Fatalf("expected 1 finding each, got %d and %d", len(f1), len(f2))
	}
	if f1[0].ID == f2[0].ID {
		t.Fatalf("plugin id should be namespaced per audit, both got %q", f1[0].ID)
	}
	if want := namespaceFindingID("A1", rawID); f1[0].ID != want {
		t.Errorf("A1 id = %q, want %q", f1[0].ID, want)
	}
}

// TestNativeIdUnchanged confirms an empty-id (native) finding is still assigned
// via generateFindingID, byte-identical to the pre-change behaviour.
func TestNativeIdUnchanged(t *testing.T) {
	var fs []model.Finding
	parseSnapshot(snapshotJSON(t, ""), "A1", "chaos", &fs, map[string]int{})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	want := generateFindingID("A1", "Hardcoded Secret", "src/a.py", 0)
	if fs[0].ID != want {
		t.Errorf("native id = %q, want %q", fs[0].ID, want)
	}
}

// TestRollupIdPreserved confirms a rollup-parent's preset id is untouched.
func TestRollupIdPreserved(t *testing.T) {
	const rollupID = "rollup-parent-1234"
	payload := map[string]interface{}{
		"findings": []map[string]interface{}{
			{
				"id":        rollupID,
				"title":     "Rollup",
				"file_path": "",
				"category":  "secrets",
				"severity":  "high",
				"is_rollup": true,
			},
		},
	}
	b, _ := json.Marshal(payload)
	var fs []model.Finding
	parseSnapshot(b, "A1", "semgrep", &fs, map[string]int{})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].ID != rollupID {
		t.Errorf("rollup id should be preserved verbatim: got %q, want %q", fs[0].ID, rollupID)
	}
}

func TestNamespaceFindingID_DeterministicAndWidth(t *testing.T) {
	a := namespaceFindingID("A1", "raw")
	b := namespaceFindingID("A1", "raw")
	if a != b {
		t.Errorf("namespaceFindingID should be deterministic: %q != %q", a, b)
	}
	if len(a) != 32 {
		t.Errorf("namespaced id should be 32 hex chars, got %d: %s", len(a), a)
	}
	if namespaceFindingID("A1", "raw") == namespaceFindingID("A2", "raw") {
		t.Error("different auditIDs should produce different namespaced ids")
	}
}
