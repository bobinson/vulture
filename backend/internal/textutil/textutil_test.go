package textutil

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Feature 0074 #45: CutAtRune never splits a rune, whatever byte the budget
// lands on, and never exceeds the budget.
func TestCutAtRune(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"", 0, ""},
		{"abc", 5, "abc"},
		{"abc", 3, "abc"},
		{"abc", 2, "ab"},
		{"abc", 0, ""},
		{"aé", 2, "a"},   // é is 2 bytes: a cut inside it backs off
		{"aé", 3, "aé"},  // exactly fits
		{"€x", 1, ""},    // € is 3 bytes: cut at byte 1 and 2 back off to 0
		{"€x", 2, ""},    //
		{"€x", 3, "€"},   //
		{"a😀b", 4, "a"},  // 4-byte rune, cut at byte 2, 3 and 4 back off to 1
		{"a😀b", 5, "a😀"}, //
		{"ééé", 5, "éé"}, // budget lands mid-rune after two whole runes
	}
	for _, c := range cases {
		got := CutAtRune(c.s, c.n)
		if got != c.want || !utf8.ValidString(got) {
			t.Errorf("CutAtRune(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

// Every budget over a mixed-width string yields a valid prefix within budget.
func TestCutAtRuneEveryBudget(t *testing.T) {
	s := strings.Repeat("aé€😀", 4)
	for n := 0; n <= len(s); n++ {
		got := CutAtRune(s, n)
		if len(got) > n || !utf8.ValidString(got) || !strings.HasPrefix(s, got) {
			t.Fatalf("CutAtRune(_, %d) = %q: over budget, invalid or not a prefix", n, got)
		}
	}
}

// Feature 0074 #15: the Go port of the agent's secret-line redactor
// reproduces the agent's output byte for byte over a shared fixture.
func TestRedactSecretLineMatchesTheAgent_0074(t *testing.T) {
	raw, err := os.ReadFile("testdata/secret_line_cases_0074.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Cases []struct {
			In  string `json:"in"`
			Out string `json:"out"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	for _, c := range doc.Cases {
		if got := RedactSecretLine(c.In); got != c.Out {
			t.Errorf("RedactSecretLine(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

type secretCase struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

func loadSecretCases(t *testing.T) (lineCases, proseCases []secretCase) {
	t.Helper()
	raw, err := os.ReadFile("testdata/secret_line_cases_0074.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Cases      []secretCase `json:"cases"`
		ProseCases []secretCase `json:"prose_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(doc.ProseCases) == 0 {
		t.Fatal("fixture has no prose_cases")
	}
	return doc.Cases, doc.ProseCases
}

// Feature 0074 re-audit #15/T3: RedactSecretText is prose-aware. A secret
// named in a sentence ("Found password: hunter2 in settings.py") or a
// key-like token (sk-live-..., AKIA...) is masked, and every code-line case
// still maps to its pinned output.
func TestRedactSecretTextMasksProseSecrets_0074(t *testing.T) {
	lineCases, proseCases := loadSecretCases(t)
	for _, c := range append(lineCases, proseCases...) {
		if got := RedactSecretText(c.In); got != c.Out {
			t.Errorf("RedactSecretText(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestRedactSecretTextRedactsEveryLine_0074(t *testing.T) {
	got := RedactSecretText("first line\napi_key = \"AKIA123\"\npassword: hunter2")
	want := "first line\napi_key = \"" + RedactionPlaceholder + "\"\npassword: " + RedactionPlaceholder
	if got != want {
		t.Fatalf("RedactSecretText = %q, want %q", got, want)
	}
}

// Feature 0074 T3: the spelled-out classes the code-line patterns compile
// with are exactly unicode.IsSpace (whitespace) and [A-Za-z0-9_] plus every
// non-ASCII non-space rune (word), whatever RE2's own \s and \w are.
func TestSpelledClassesAreGoSpaceAndWord_0074(t *testing.T) {
	space := regexp.MustCompile(`^` + spaceClass + `$`)
	nonSpace := regexp.MustCompile(`^` + nonSpaceClass + `$`)
	word := regexp.MustCompile(`^[` + wordChars + `]$`)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if utf8.ValidRune(r) {
			assertSpelledClasses(t, r, space, nonSpace, word)
		}
	}
}

func assertSpelledClasses(t *testing.T, r rune, space, nonSpace, word *regexp.Regexp) {
	t.Helper()
	s := string(r)
	got := [3]bool{space.MatchString(s), nonSpace.MatchString(s), word.MatchString(s)}
	want := [3]bool{unicode.IsSpace(r), !unicode.IsSpace(r), wantWord(r)}
	if got != want {
		t.Errorf("rune %U: space/nonSpace/word = %v, want %v", r, got, want)
	}
}

// wantWord is [A-Za-z0-9_] or a non-ASCII rune that is not whitespace.
func wantWord(r rune) bool {
	if r >= 0x80 {
		return !unicode.IsSpace(r)
	}
	return r == '_' || strings.ContainsRune("0123456789", r) || unicode.IsLetter(r)
}
