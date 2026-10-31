package modelmeta

import "testing"

// 0074 AC1 (Go side) / §5.1(a): the broker's window resolution must say HOW it
// obtained the number, not only the number. A family-substring guess and an
// operator override are indistinguishable today once they cross the process
// boundary (defect A1, "provenance laundering"). The resolver returns the
// source beside the window; `probe` is not a modelmeta source (modelmeta is a
// pure lookup, the probe lives in broker/serve, §5.2).
func TestResolveContextWindowWithSource_NamesHowTheWindowWasObtained(t *testing.T) {
	cases := []struct {
		name, model, override string
		wantWindow            int
		wantSource            string
	}{
		{"operator override", "z-ai/glm-5.2", "50000", 50_000, "env"},
		{"exact table", "gpt-4o", "", 128_000, "table"},
		{"exact table beats family", "qwen3:8b", "", 32_000, "table"},
		{"family substring guess", "qwen/qwen3.6-35b-a3b", "", 32_768, "family"},
		{"unknown model", "totally-unknown-model-xyz", "", DefaultContextWindow, "default"},
		{"invalid override falls to registry", "z-ai/glm-5.2", "not-a-number", 131_072, "family"},
		{"non-positive override falls to registry", "gpt-4o", "0", 128_000, "table"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, src := ResolveContextWindowWithSource(c.model, c.override)
			if w != c.wantWindow || string(src) != c.wantSource {
				t.Errorf("ResolveContextWindowWithSource(%q,%q) = (%d,%q), want (%d,%q)",
					c.model, c.override, w, src, c.wantWindow, c.wantSource)
			}
		})
	}
}

// 0074 §5.1(a): the new sibling never disagrees with the existing bare-int
// resolver on the number — it only adds the source.
func TestResolveContextWindowWithSource_AgreesWithResolveContextWindow(t *testing.T) {
	for _, m := range []string{"gpt-4o", "gemini-2.5-flash", "gemma-2-9b", "o3", "nope", "qwen/qwen3.6-35b-a3b"} {
		w, _ := ResolveContextWindowWithSource(m, "")
		if want := ResolveContextWindow(m, ""); w != want {
			t.Errorf("%q: with-source window %d, bare resolver %d", m, w, want)
		}
	}
}
