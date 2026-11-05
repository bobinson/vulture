package modelmeta

// Feature 0074 #6 / contract C6: VULTURE_LLM_CTX_SIZE counts only when it
// trims to a positive integer. The same fixture pins the Python resolver
// (agents/shared provider tests), so the runtimes cannot disagree.
//
// #13: a measured (probed) window above the largest registry window is not a
// value; the registry answers instead.

import (
	"encoding/json"
	"os"
	"testing"
)

type ctxOverrideCase struct {
	Override string `json:"override"`
	Honoured bool   `json:"honoured"`
	Window   int    `json:"window"`
}

func TestCtxOverrideSharedFixture_0074(t *testing.T) {
	raw, err := os.ReadFile("testdata/ctx_override_cases_0074.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Cases []ctxOverrideCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Cases) == 0 {
		t.Fatalf("decode fixture: %v (%d cases)", err, len(doc.Cases))
	}
	for _, c := range doc.Cases {
		w, src := ResolveMeasuredContextWindow("gpt-4o", c.Override, 0)
		if c.Honoured && (src != SourceEnv || w != c.Window) {
			t.Errorf("override %q: got (%d, %s), want (%d, env)", c.Override, w, src, c.Window)
		}
		if !c.Honoured && (src == SourceEnv || w != 128_000) {
			t.Errorf("override %q: got (%d, %s), want the table window (128000, table)", c.Override, w, src)
		}
	}
}

func TestMeasuredWindowClampedToRegistryMax_0074(t *testing.T) {
	cases := []struct {
		measured int
		want     int
		src      string
	}{
		{65_536, 65_536, SourceProbe},
		{MaxRegistryWindow, MaxRegistryWindow, SourceProbe},
		{MaxRegistryWindow + 1, 128_000, SourceTable},
		{1 << 40, 128_000, SourceTable},
		{0, 128_000, SourceTable},
		{-5, 128_000, SourceTable},
	}
	for _, c := range cases {
		w, src := ResolveMeasuredContextWindow("gpt-4o", "", c.measured)
		if w != c.want || src != c.src {
			t.Errorf("measured %d: got (%d, %s), want (%d, %s)", c.measured, w, src, c.want, c.src)
		}
	}
}

// MaxRegistryWindow is the largest window the registry knows, table or family.
func TestMaxRegistryWindowIsTheLargestEntry_0074(t *testing.T) {
	maxW := 0
	for _, w := range contextWindows {
		maxW = max(maxW, w)
	}
	for _, f := range modelFamilyCtx {
		maxW = max(maxW, f.ctx)
	}
	if MaxRegistryWindow != maxW {
		t.Fatalf("MaxRegistryWindow = %d, want the registry's largest entry %d", MaxRegistryWindow, maxW)
	}
}
