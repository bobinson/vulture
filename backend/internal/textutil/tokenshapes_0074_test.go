package textutil

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type tokenShapeCases struct {
	Mask []struct {
		Name string   `json:"name"`
		Text string   `json:"text"`
		Gone []string `json:"gone"`
	} `json:"mask"`
	Keep []string `json:"keep"`
}

func loadTokenShapeCases(t *testing.T) tokenShapeCases {
	t.Helper()
	b, err := os.ReadFile("testdata/token_shapes_0074.json")
	if err != nil {
		t.Fatal(err)
	}
	var c tokenShapeCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// 0074 verification item 1: Go masks the distinctive token shapes in finding
// text, so an older agent's unmasked merge description is still masked here.
func TestMaskTokenShapes_MasksEveryFixtureShape(t *testing.T) {
	for _, c := range loadTokenShapeCases(t).Mask {
		got := MaskTokenShapes(c.Text)
		for _, raw := range c.Gone {
			if strings.Contains(got, raw) {
				t.Errorf("%s: %q survived in %q", c.Name, raw, got)
			}
		}
		if !strings.Contains(got, RedactionPlaceholder) {
			t.Errorf("%s: no placeholder in %q", c.Name, got)
		}
	}
}

func TestMaskTokenShapes_LeavesProseAlone(t *testing.T) {
	for _, text := range loadTokenShapeCases(t).Keep {
		if got := MaskTokenShapes(text); got != text {
			t.Errorf("benign text changed: %q -> %q", text, got)
		}
	}
}

func TestMaskTokenShapes_IsIdempotent(t *testing.T) {
	for _, c := range loadTokenShapeCases(t).Mask {
		once := MaskTokenShapes(c.Text)
		if twice := MaskTokenShapes(once); twice != once {
			t.Errorf("%s: not idempotent: %q -> %q", c.Name, once, twice)
		}
	}
}
