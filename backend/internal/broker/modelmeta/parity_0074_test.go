package modelmeta

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Helpers for the 0074 AC6 registry-parity canary (TestFamilyOrder_MirrorsPython).
// They read the Python source of truth so the canary can never be satisfied by
// editing a hand-maintained copy of it.

// pyProviderPath is provider.py relative to this package directory
// (backend/internal/broker/modelmeta → repo root is four levels up).
var pyProviderPath = filepath.Join("..", "..", "..", "..", "agents", "shared", "shared", "llm", "provider.py")

var (
	pyExactRow  = regexp.MustCompile(`^\s*"([^"]+)":\s*([0-9_]+),`)
	pyFamilyRow = regexp.MustCompile(`^\s*\("([^"]+)",\s*([0-9_]+)\),`)
)

type pyEntry struct {
	key string
	val int
}

func readPythonProvider(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(pyProviderPath)
	if err != nil {
		t.Fatalf("read %s: %v", pyProviderPath, err)
	}
	return string(b)
}

// pyBlock returns the lines between the line starting with header and the
// first line that is exactly closer (the literal's closing bracket).
func pyBlock(t *testing.T, src, header, closer string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(src, "\n"+header)
	if !ok {
		t.Fatalf("provider.py: %q not found", header)
	}
	body, _, _ := strings.Cut(rest, "\n"+closer+"\n")
	return strings.Split(body, "\n")
}

// parsePyRows extracts (key, value) rows from a block, in source order.
func parsePyRows(t *testing.T, lines []string, row *regexp.Regexp) []pyEntry {
	t.Helper()
	var out []pyEntry
	for _, ln := range lines {
		if m := row.FindStringSubmatch(ln); m != nil {
			out = append(out, pyEntry{m[1], pyInt(t, m[2])})
		}
	}
	if len(out) == 0 {
		t.Fatal("provider.py: parsed zero rows — the canary would pass vacuously")
	}
	return out
}

func pyInt(t *testing.T, lit string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.ReplaceAll(lit, "_", ""))
	if err != nil {
		t.Fatalf("provider.py: bad int literal %q", lit)
	}
	return n
}

func parsePyFamilies(t *testing.T, src string) []pyEntry {
	return parsePyRows(t, pyBlock(t, src, "_MODEL_FAMILY_CTX: list[tuple[str, int]] = [", "]"), pyFamilyRow)
}

func parsePyExact(t *testing.T, src string) []pyEntry {
	return parsePyRows(t, pyBlock(t, src, "CONTEXT_WINDOWS: dict[str, int] = {", "}"), pyExactRow)
}

// assertFamilyParity: identical length, and at every position the same
// substring AND the same window.
func assertFamilyParity(t *testing.T, py []pyEntry) {
	t.Helper()
	if len(modelFamilyCtx) != len(py) {
		t.Errorf("family list length: Go %d, Python %d (sync with _MODEL_FAMILY_CTX)", len(modelFamilyCtx), len(py))
	}
	for i := 0; i < min(len(py), len(modelFamilyCtx)); i++ {
		assertFamilyAt(t, i, py[i])
	}
}

func assertFamilyAt(t *testing.T, i int, want pyEntry) {
	t.Helper()
	if g := modelFamilyCtx[i]; g.sub != want.key || g.ctx != want.val {
		t.Errorf("family[%d]: Go (%q,%d), Python (%q,%d)", i, g.sub, g.ctx, want.key, want.val)
	}
}

// assertExactParity: the exact-match maps hold the same keys with the same
// values, in both directions.
func assertExactParity(t *testing.T, py []pyEntry) {
	t.Helper()
	for _, e := range py {
		assertExactKey(t, e)
	}
	if len(contextWindows) != len(py) {
		t.Errorf("exact map size: Go %d, Python %d (the key sets differ)", len(contextWindows), len(py))
	}
}

func assertExactKey(t *testing.T, want pyEntry) {
	t.Helper()
	if got, ok := contextWindows[want.key]; !ok || got != want.val {
		t.Errorf("exact map: Python %q=%d, Go has %d (present=%v)", want.key, want.val, got, ok)
	}
}
