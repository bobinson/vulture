package reveal

// 0074 verification item 1b: verify a masked value against the scanned source.
// All values are synthetic.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var configTS = "const a = 1;\nconst token = \"" + jwt + "\";\nconst b = 2;\n"

const maskedSnippet = "1: const a = 1;\n2: const token = \"***REDACTED***\";\n3: const b = 2;"

func check(root, path, snippet string, values bool) Result {
	return Check(Request{Root: root, FilePath: path, Snippet: snippet, LineStart: 2, LineEnd: 2, Values: values})
}

func TestCheck_ValueOfAMaskedRow(t *testing.T) {
	root := tree(t, map[string]string{"src/config.ts": configTS})
	got := check(root, "src/config.ts", maskedSnippet, true)
	if !got.SourceAvailable || !got.MatchesScan || got.Reason != "" || got.RowsChecked != 3 {
		t.Fatalf("got %+v", got)
	}
	if len(got.Spans) != 1 {
		t.Fatalf("spans %+v", got.Spans)
	}
	s := got.Spans[0]
	if s.Line != 2 || s.Ordinal != 0 || s.Column != 16 || s.Kind != "jwt" || s.Value != jwt || s.Length == nil || *s.Length != len(jwt) {
		t.Errorf("span %+v", s)
	}
}

func TestCheck_NoValueUnlessAsked(t *testing.T) {
	root := tree(t, map[string]string{"src/config.ts": configTS})
	got := check(root, "src/config.ts", maskedSnippet, false)
	if !got.MatchesScan || got.Spans[0].Value != "" || got.ValuesIncluded {
		t.Errorf("a span carried a value without being asked: %+v", got)
	}
}

func TestCheck_AbsolutePathInsideRoot(t *testing.T) {
	root := tree(t, map[string]string{"src/config.ts": configTS})
	if got := check(root, filepath.Join(root, "src/config.ts"), maskedSnippet, true); !got.MatchesScan {
		t.Errorf("an absolute path under the root must resolve: %+v", got)
	}
}

func TestCheck_ChangedFileGivesNoValue(t *testing.T) {
	root := tree(t, map[string]string{"src/config.ts": strings.Replace(configTS, "const b = 2;", "const b = 3;", 1)})
	got := check(root, "src/config.ts", maskedSnippet, true)
	if got.MatchesScan || got.Reason != ReasonChanged {
		t.Fatalf("got %+v", got)
	}
	for _, s := range got.Spans {
		if s.Value != "" {
			t.Errorf("a value was returned from a file that changed since the scan: %+v", s)
		}
	}
}

// A prompt-injected file_path cannot read a file the scan did not mask.
func TestCheck_UnrelatedFileGivesNothing(t *testing.T) {
	root := tree(t, map[string]string{"src/config.ts": configTS, ".env": "SECRET=hunter2-synthetic\n"})
	got := check(root, ".env", maskedSnippet, true)
	if got.MatchesScan || len(valuesOf(got)) != 0 {
		t.Errorf("an unrelated file yielded values: %+v", got)
	}
}

func valuesOf(r Result) []string {
	var out []string
	for _, s := range r.Spans {
		if s.Value != "" {
			out = append(out, s.Value)
		}
	}
	return out
}

func TestCheck_RefusesPathsOutsideTheRoot(t *testing.T) {
	outside := tree(t, map[string]string{"secret.ts": configTS})
	root := tree(t, map[string]string{"src/a.ts": "x\n"})
	if err := os.Symlink(filepath.Join(outside, "secret.ts"), filepath.Join(root, "src/link.ts")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../" + filepath.Base(outside) + "/secret.ts", filepath.Join(outside, "secret.ts"), "src/link.ts"} {
		got := check(root, p, maskedSnippet, true)
		if got.Reason != ReasonOutsideRoot || len(valuesOf(got)) != 0 {
			t.Errorf("%s: got %+v, want %s", p, got, ReasonOutsideRoot)
		}
	}
}

func TestCheck_Refusals(t *testing.T) {
	root := tree(t, map[string]string{
		"bin.dat":  "1: \x00binary\n",
		"big.ts":   strings.Repeat("x", maxFileBytes+1),
		"src/a.ts": configTS,
	})
	cases := []struct {
		name, root, path, snippet, want string
	}{
		{"empty root", "", "src/a.ts", maskedSnippet, ReasonUnavailable},
		{"missing file", root, "src/none.ts", maskedSnippet, ReasonUnavailable},
		{"directory", root, "src", maskedSnippet, ReasonNotRegular},
		{"too large", root, "big.ts", maskedSnippet, ReasonTooLarge},
		{"binary", root, "bin.dat", maskedSnippet, ReasonBinary},
	}
	for _, c := range cases {
		if got := check(c.root, c.path, c.snippet, true); got.Reason != c.want || len(valuesOf(got)) != 0 {
			t.Errorf("%s: got %+v, want %s", c.name, got, c.want)
		}
	}
}

func TestCheck_NoLineGivesNoLocation(t *testing.T) {
	root := tree(t, map[string]string{"src/a.ts": configTS})
	got := Check(Request{Root: root, FilePath: "src/a.ts", Snippet: "const token = \"***REDACTED***\";", Values: true})
	if got.Reason != ReasonNoLocation || len(valuesOf(got)) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestCheck_AmbiguousAlignmentGivesNoValue(t *testing.T) {
	cases := map[string]struct{ file, snippet string }{
		"adjacent placeholders": {"k = " + jwt + "x\n", "1: k = ***REDACTED******REDACTED***"},
		"placeholder in source": {"k = \"***REDACTED***\" + \"" + jwt + "\"\n", "1: k = \"***REDACTED***\" + \"***REDACTED***\""},
	}
	for name, c := range cases {
		root := tree(t, map[string]string{"a.py": c.file})
		got := Check(Request{Root: root, FilePath: "a.py", Snippet: c.snippet, LineStart: 1, LineEnd: 1, Values: true})
		if got.Reason != ReasonAmbiguous || len(valuesOf(got)) != 0 {
			t.Errorf("%s: got %+v, want %s", name, got, ReasonAmbiguous)
		}
	}
}

func TestCheck_CRLFAndUnicodeColumns(t *testing.T) {
	root := tree(t, map[string]string{"a.py": "é = 1\r\nkey = \"" + jwt + "\"\r\n"})
	got := Check(Request{Root: root, FilePath: "a.py", Snippet: "1: é = 1\n2: key = \"***REDACTED***\"",
		LineStart: 2, LineEnd: 2, Values: true})
	if !got.MatchesScan || got.Spans[0].Column != 8 || got.Spans[0].Value != jwt {
		t.Errorf("got %+v", got)
	}
}

func TestCheck_PasswordLikeKindsHideTheirLength(t *testing.T) {
	root := tree(t, map[string]string{"a.py": "DB = \"postgres://app:hunter2-synthetic@db/app\"\n"})
	got := Check(Request{Root: root, FilePath: "a.py", Snippet: "1: DB = \"***REDACTED***db/app\"",
		LineStart: 1, LineEnd: 1, Values: false})
	if !got.MatchesScan || got.Spans[0].Kind != "url_userinfo" || got.Spans[0].Length != nil {
		t.Errorf("got %+v", got)
	}
}

func TestCheck_CutRowIsAPrefix(t *testing.T) {
	long := "k = \"" + jwt + "\" + \"" + strings.Repeat("y", 500) + "\""
	root := tree(t, map[string]string{"a.py": long + "\n"})
	row := "1: " + ("k = \"***REDACTED***\" + \"" + strings.Repeat("y", 500))[:400]
	got := Check(Request{Root: root, FilePath: "a.py", Snippet: row, LineStart: 1, LineEnd: 1, Values: true})
	if !got.MatchesScan || got.Spans[0].Value != jwt {
		t.Errorf("got %+v", got)
	}
}

func TestCheck_OrdinalsFollowTheRowsPlaceholders(t *testing.T) {
	root := tree(t, map[string]string{"a.py": "f(\"" + jwt + "\", \"AKIA0123456789ABCDEF\")\n"})
	got := Check(Request{Root: root, FilePath: "a.py", Snippet: "1: f(\"***REDACTED***\", \"[redacted]\")",
		LineStart: 1, LineEnd: 1, Values: true})
	if !got.MatchesScan || len(got.Spans) != 2 || got.Spans[0].Ordinal != 0 || got.Spans[1].Ordinal != 1 ||
		got.Spans[1].Kind != "aws_key_id" {
		t.Errorf("got %+v", got)
	}
}

// Re-audit finding 1: a stored row must sit within the finding's lines, and a
// row with (almost) no literal text proves nothing about the file, so its
// value must have a recognised secret shape.
func TestCheck_RowsOutsideTheFindingAreRefused(t *testing.T) {
	body := "DB_PASSWORD=hunter2\nOTHER=plainvalue\n" + strings.Repeat("x = 1\n", 60)
	root := tree(t, map[string]string{".env": body})
	got := Check(Request{Root: root, FilePath: ".env", Snippet: "1: ***REDACTED***\n2: ***REDACTED***",
		LineStart: 50, LineEnd: 50, Values: true})
	if got.MatchesScan || len(valuesOf(got)) != 0 {
		t.Errorf("rows far from the finding were honoured: %+v", got)
	}
}

func TestCheck_ShapelessWholeLineIsAmbiguous(t *testing.T) {
	root := tree(t, map[string]string{".env": "DB_PASSWORD=hunter2\n"})
	for _, snip := range []string{"1: ***REDACTED***", "1: D***REDACTED***"} {
		got := Check(Request{Root: root, FilePath: ".env", Snippet: snip, LineStart: 1, LineEnd: 1, Values: true})
		if got.Reason != ReasonAmbiguous || len(valuesOf(got)) != 0 {
			t.Errorf("%q: got %+v, want ambiguous", snip, got)
		}
	}
}

func TestCheck_ShapedWholeLineStillReveals(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0t\n-----END RSA PRIVATE KEY-----\n"
	root := tree(t, map[string]string{"k.pem": pem})
	snip := "1: -----BEGIN RSA PRIVATE KEY-----\n2: ***REDACTED***\n3: -----END RSA PRIVATE KEY-----"
	got := Check(Request{Root: root, FilePath: "k.pem", Snippet: snip, LineStart: 2, LineEnd: 2, Values: true})
	if !got.MatchesScan || len(valuesOf(got)) != 1 || got.Spans[0].Kind != "private_key" {
		t.Errorf("got %+v", got)
	}
}

// Re-audit finding 3: a FIFO must be refused, never opened for reading.
func TestCheck_FifoIsRefusedWithoutBlocking(t *testing.T) {
	root := tree(t, map[string]string{"a.ts": "x\n"})
	if err := syscallMkfifo(filepath.Join(root, "pipe")); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan Result, 1)
	go func() { done <- check(root, "pipe", maskedSnippet, true) }()
	select {
	case got := <-done:
		if got.Reason != ReasonNotRegular {
			t.Errorf("got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Check blocked on a FIFO")
	}
}

// Live verification (togetherapp): secret_scan config findings carry ONE
// unnumbered row, the cited line without its indentation. Those rows map to
// line_start onwards, and the line's leading whitespace is tolerated.
func TestCheck_UnnumberedRowsMapToTheFindingLine(t *testing.T) {
	cfg := "server:\n  port: 8080\n  api_secret_key: sk_live_0123456789abcdefSYNTH\n"
	root := tree(t, map[string]string{"config.yml": cfg})
	got := Check(Request{Root: root, FilePath: "config.yml", Snippet: "api_secret_key: ***REDACTED***",
		LineStart: 3, LineEnd: 3, Values: true})
	if !got.MatchesScan || len(got.Spans) != 1 || got.Spans[0].Value != "sk_live_0123456789abcdefSYNTH" ||
		got.Spans[0].Line != 3 || got.Spans[0].Column != 19 || got.Spans[0].Kind != "stripe_key" {
		t.Errorf("got %+v", got)
	}
}

func TestCheck_UnnumberedRowAtTheWrongLineIsChanged(t *testing.T) {
	root := tree(t, map[string]string{"config.yml": "a: 1\napi_secret_key: x\n"})
	got := Check(Request{Root: root, FilePath: "config.yml", Snippet: "api_secret_key: ***REDACTED***",
		LineStart: 1, LineEnd: 1, Values: true})
	if got.MatchesScan || len(valuesOf(got)) != 0 {
		t.Errorf("got %+v", got)
	}
}

// Live verification (togetherapp): window cuts leave rows that are PREFIXES of
// their file lines at any length (the window stage's own rule), and a cut
// masked row still reveals a value anchored by literal text after it.
func TestCheck_TruncatedRowsArePrefixes(t *testing.T) {
	file := "const a = 1; // a long trailing comment that the window cut\nconst token = \"" + jwt + "\"; // tail\n"
	root := tree(t, map[string]string{"a.ts": file})
	snip := "1: const a = 1; // a long\n2: const token = \"***REDACTED***\"; // ta"
	got := Check(Request{Root: root, FilePath: "a.ts", Snippet: snip, LineStart: 2, LineEnd: 2, Values: true})
	if !got.MatchesScan || len(valuesOf(got)) != 1 || got.Spans[0].Value != jwt {
		t.Errorf("got %+v", got)
	}
}

// A skill that stores a normalised "key.path: ***" (not a copy of the file
// row) cannot be aligned: that is a missing location, not a changed file.
func TestCheck_NormalisedUnnumberedSnippetIsNoLocation(t *testing.T) {
	root := tree(t, map[string]string{"c.json": "{\n  \"db_password\": \"hunter2-synthetic\"\n}\n"})
	got := Check(Request{Root: root, FilePath: "c.json", Snippet: "config.db_password: ***REDACTED***",
		LineStart: 2, LineEnd: 2, Values: true})
	if got.Reason != ReasonNoLocation || len(valuesOf(got)) != 0 {
		t.Errorf("got %+v", got)
	}
}
