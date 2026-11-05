package requestid

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// validSink keeps the compiler from discarding the call being measured.
var validSink bool

func TestHeader_Name(t *testing.T) {
	if Header != "X-Request-ID" {
		t.Errorf("Header = %q, want X-Request-ID", Header)
	}
}

// Valid admits 1..64 bytes of [A-Za-z0-9._-] and nothing else.
func TestValid_Table(t *testing.T) {
	cases := map[string]bool{
		"a":                                    true,
		"ci-run-42.a_b":                        true,
		"0123456789abcdef":                     true,
		"ABCxyz.-_":                            true,
		"550e8400-e29b-41d4-a716-446655440000": true,
		strings.Repeat("z", 64):                true,
		"":                                     false,
		strings.Repeat("z", 65):                false,
		"x y":                                  false,
		`quote"d`:                              false,
		"<script>":                             false,
		"ci/run":                               false,
		"a:b":                                  false,
		"a+b=":                                 false,
		"tab\there":                            false,
		"line\nbreak":                          false,
		"nul\x00":                              false,
		"caf\u00e9":                            false,
		"\xff":                                 false,
	}
	for id, want := range cases {
		if got := Valid(id); got != want {
			t.Errorf("Valid(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestNew_SixteenHexUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := New()
		wantNewID(t, id, seen)
		seen[id] = true
	}
}

func wantNewID(t *testing.T, id string, seen map[string]bool) {
	t.Helper()
	if !hex16.MatchString(id) || !Valid(id) {
		t.Fatalf("New() = %q, want 16 lowercase hex characters that Valid accepts", id)
	}
	if seen[id] {
		t.Fatalf("New() repeated %q", id)
	}
}

// Ensure returns the id already on the response, or sets and returns a new one.
func TestEnsure_ReusesOrSets(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set(Header, "ci-run-42.a_b")
	if got := Ensure(w); got != "ci-run-42.a_b" {
		t.Errorf("Ensure with the header set = %q, want the header's value", got)
	}

	w = httptest.NewRecorder()
	got := Ensure(w)
	wantNewID(t, got, nil)
	if w.Header().Get(Header) != got || Ensure(w) != got {
		t.Errorf("Ensure without a header returned %q but the response carries %q; a second Ensure must return the same id", got, w.Header().Get(Header))
	}
}

// Valid runs on every request: no allocation, whatever the input.
func TestValid_ZeroAllocs(t *testing.T) {
	inputs := []string{"ci-run-42.a_b", strings.Repeat("z", 64), strings.Repeat("z", 65), `x y"<script>`, ""}
	for _, id := range inputs {
		if n := testing.AllocsPerRun(100, func() { validSink = Valid(id) }); n != 0 {
			t.Errorf("Valid(%.20q) allocates %v times per call, want 0", id, n)
		}
	}
}
