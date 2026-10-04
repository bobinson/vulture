package handler

// Feature 0074 T2.4, static half (review #29): the tier-family code — the Go
// merge record and filter, the UI helper and the MCP helpers — selects rows
// and records tiers only. None of it may WRITE a voter input
// (validation_status / validation_confidence, or the blob's status /
// confidence). The behaviour tests pin AC11 at runtime; this pins the source,
// so a later edit cannot start moving verdicts from a provenance helper.
// The TS and MCP files are read, never modified.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

type voterWriteScan struct {
	path     string
	extract  func(t *testing.T, src string) string
	patterns []*regexp.Regexp
}

var (
	goVoterWrites = []*regexp.Regexp{
		regexp.MustCompile(`\.Validation(Status|Confidence)\s*=[^=]`),
		regexp.MustCompile(`\[\s*"(status|confidence)"\s*\]\s*=[^=]`),
		regexp.MustCompile(`"(status|confidence)"\s*:`),
		regexp.MustCompile(`Validation(Status|Confidence)\s*:`),
	}
	tsVoterWrites = []*regexp.Regexp{
		regexp.MustCompile(`validation_(status|confidence)\s*(=[^=>]|:)`),
		regexp.MustCompile(`\.(status|confidence)\s*=[^=>]`),
		regexp.MustCompile(`\[\s*["'](validation_status|validation_confidence|status|confidence)["']\s*\]\s*=[^=]`),
	}
	pyVoterWrites = []*regexp.Regexp{
		regexp.MustCompile(`\[\s*["'](validation_status|validation_confidence|status|confidence)["']\s*\]\s*=[^=]`),
		regexp.MustCompile(`["'](validation_status|validation_confidence|status|confidence)["']\s*:`),
		regexp.MustCompile(`(setdefault|update)\(\s*["']?(validation_status|validation_confidence|status|confidence)`),
	}
)

func wholeFile(_ *testing.T, src string) string { return src }

// mcpProvenanceHelpers is the source of the MCP tool's 0074 helpers: every
// top-level def whose name is one of them, up to the next top-level line.
func mcpProvenanceHelpers(t *testing.T, src string) string {
	t.Helper()
	names := []string{"_tier", "_is_llm_tier", "_tier_family", "_provenance_origins", "_is_llm_family",
		"_spans_both_families", "_origins_recorded", "_provenance_pred"}
	var b strings.Builder
	for _, n := range names {
		body := topLevelDef(src, n)
		if body == "" {
			t.Fatalf("mcp/server.py has no top-level def %s; update the scan list", n)
		}
		b.WriteString(body)
	}
	return b.String()
}

// topLevelDef returns `def name(` through the line before the next
// non-indented, non-blank line.
func topLevelDef(src, name string) string {
	start := strings.Index(src, "\ndef "+name+"(")
	if start < 0 {
		return ""
	}
	lines := strings.Split(src[start+1:], "\n")
	end := 1
	for end < len(lines) && (lines[end] == "" || strings.HasPrefix(lines[end], " ")) {
		end++
	}
	return strings.Join(lines[:end], "\n")
}

var voterWriteScans = []voterWriteScan{
	{"dedup_record.go", wholeFile, goVoterWrites},
	{"provenance_filter.go", wholeFile, goVoterWrites},
	{"../../../frontend/src/lib/provenance.ts", wholeFile, tsVoterWrites},
	{"../../../mcp/server.py", mcpProvenanceHelpers, pyVoterWrites},
}

func TestTierFamilyCodeNeverWritesVoterInputs_0074(t *testing.T) {
	for _, s := range voterWriteScans {
		raw, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatalf("read %s: %v", s.path, err)
		}
		code := s.extract(t, string(raw))
		for _, p := range s.patterns {
			if m := p.FindString(code); m != "" {
				t.Errorf("%s writes a voter input (%q matches %s): provenance code selects rows, it never moves a verdict (AC11/O4)",
					s.path, m, p)
			}
		}
	}
}

// The scan must be able to fail: each pattern set catches a planted write.
func TestVoterWriteScanCatchesAPlantedWrite_0074(t *testing.T) {
	planted := map[string][]*regexp.Regexp{
		`f.ValidationStatus = "confirmed"`:          goVoterWrites,
		`v["confidence"] = 0.9`:                     goVoterWrites,
		`f.validation_status = "confirmed";`:        tsVoterWrites,
		`return { ...f, validation_confidence: 1 }`: tsVoterWrites,
		`finding["validation_status"] = "x"`:        pyVoterWrites,
		`validation.update(status="x")`:             pyVoterWrites,
	}
	for code, pats := range planted {
		if !anyMatch(pats, code) {
			t.Errorf("planted write %q is not caught", code)
		}
	}
}

func anyMatch(pats []*regexp.Regexp, code string) bool {
	for _, p := range pats {
		if p.MatchString(code) {
			return true
		}
	}
	return false
}
