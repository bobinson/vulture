// Package reveal verifies a masked value against the scanned source (feature
// 0074 verification item 1b).
//
// Nothing raw is stored anywhere: a finding keeps its masked snippet. On
// request, the snippet's numbered rows are aligned against the file the audit
// scanned, each placeholder standing for the text it masked. The answer says
// where each masked value sits (line, column, kind, and the length for
// fixed-format tokens), whether the file still reproduces the masked rows, and
// — only when asked AND every row aligned — the values themselves.
//
// The values are never more than what the stored masked rows already locate:
// a row must match the file outside its placeholders, so a prompt-injected
// file_path cannot turn this into a file reader. Files are opened through
// os.Root, which the kernel confines to the source root (no `..`, no symlink
// escape, no check-then-open race).
package reveal

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/vulture/backend/internal/pathutil"
)

// Refusal and outcome reasons. "" means every row aligned.
const (
	ReasonUnavailable = "source_unavailable"
	ReasonOutsideRoot = "outside_source_root"
	ReasonNotRegular  = "not_a_regular_file"
	ReasonTooLarge    = "too_large"
	ReasonBinary      = "binary"
	ReasonNoLocation  = "no_location"
	ReasonChanged     = "changed_since_scan"
	ReasonAmbiguous   = "ambiguous"
	ReasonOutsideFind = "outside_finding"
)

// findingContext is how far a stored row may sit from the finding's own lines:
// a snippet window never spans more (extract_snippet caps it at 40 rows).
const findingContext = 60

// minLiteralChars: a row with less literal text than this proves nothing
// about the file around its placeholder, so its value must have a recognised
// secret shape (a PEM body row is all placeholder; "D***REDACTED***" is not
// evidence that the rest of a line is a secret).
const minLiteralChars = 8

// maxRevealChars caps the text one response may reveal.
const maxRevealChars = 16 * 1024

// maxFileBytes matches the scanner's per-file read cap (VULTURE_MAX_FILE_SIZE default).
const maxFileBytes = 512 * 1024

// maxRows bounds the rows one request checks.
const maxRows = 80

// placeholders are the agents' masking placeholders.
var placeholders = []string{"***REDACTED***", "[redacted]"}

// Request is one verification.
type Request struct {
	Root      string // the audit's source root
	FilePath  string // the finding's file_path (relative, or absolute under the root)
	Snippet   string // the stored, masked code_snippet
	LineStart int
	LineEnd   int
	Values    bool // include each value (the caller decides who may)
}

// Span is one masked value.
type Span struct {
	Line int `json:"line"`
	// Ordinal is the placeholder's 0-based position within its stored row, so
	// a client can put the value back into the masked row it came from.
	Ordinal int    `json:"ordinal"`
	Column  int    `json:"column"` // 1-based, in Unicode code points
	Length  *int   `json:"length,omitempty"`
	Kind    string `json:"kind"`
	Value   string `json:"value,omitempty"`
}

// Result is the verification.
type Result struct {
	SourceAvailable bool   `json:"source_available"`
	MatchesScan     bool   `json:"matches_scan"`
	ValuesIncluded  bool   `json:"values_included"`
	File            string `json:"file,omitempty"`
	RowsChecked     int    `json:"rows_checked"`
	Spans           []Span `json:"spans"`
	Reason          string `json:"reason,omitempty"`
}

// Check verifies req. It never returns an error: every failure is a Reason.
func Check(req Request) Result {
	res := Result{Spans: []Span{}}
	rel, lines, reason := source(req)
	res.File, res.SourceAvailable, res.Reason = rel, lines != nil, reason
	if reason != "" {
		return res
	}
	rows, numbered := snippetRows(req.Snippet, req.LineStart)
	if res.Reason = rowsReason(rows, req); res.Reason != "" {
		return res
	}
	res = alignAll(res, rows, lines, req.Values)
	if !numbered && res.Reason == ReasonChanged {
		// An unnumbered snippet claims no coordinates: one that does not match
		// the cited line is a normalised rendering (e.g. "key.path: ***"), not
		// a copy of a file row, so there is no location to verify.
		res.Reason = ReasonNoLocation
	}
	return res
}

// source resolves and reads the finding's file under the root.
func source(req Request) (string, []string, string) {
	if req.Root == "" {
		return "", nil, ReasonUnavailable
	}
	rel, ok := relativePath(req.FilePath, req.Root)
	if !ok {
		return "", nil, ReasonOutsideRoot
	}
	lines, reason := readLines(req.Root, rel)
	return rel, lines, reason
}

// rowsReason: the stored rows locate something, and only around the finding.
func rowsReason(rows []row, req Request) string {
	switch {
	case len(rows) == 0 || req.LineStart < 1:
		return ReasonNoLocation
	case !withinFinding(rows, req.LineStart, req.LineEnd):
		return ReasonOutsideFind
	}
	return ""
}

// alignAll aligns every row; values are kept only when all of them aligned
// and the total stays under maxRevealChars.
func alignAll(res Result, rows []row, lines []string, values bool) Result {
	for _, r := range rows {
		spans, reason := alignRow(r, lines)
		res.RowsChecked++
		res.Spans = append(res.Spans, spans...)
		res.Reason = firstReason(res.Reason, reason)
	}
	res.MatchesScan = res.Reason == ""
	if res.MatchesScan && revealedChars(res.Spans) > maxRevealChars {
		res.Reason = ReasonTooLarge
	}
	res.ValuesIncluded = values && res.Reason == ""
	if !res.ValuesIncluded {
		dropValues(res.Spans)
	}
	return res
}

// withinFinding: every stored row lies within findingContext lines of the
// finding's own range.
func withinFinding(rows []row, start, end int) bool {
	end = max(end, start)
	for _, r := range rows {
		if r.line < start-findingContext || r.line > end+findingContext {
			return false
		}
	}
	return true
}

func firstReason(have, next string) string {
	if have != "" {
		return have
	}
	return next
}

func revealedChars(spans []Span) int {
	n := 0
	for _, sp := range spans {
		n += len(sp.Value)
	}
	return n
}

func dropValues(spans []Span) {
	for i := range spans {
		spans[i].Value = ""
	}
}

type row struct {
	line     int
	template string
}

// snippetRows: the numbered rows, or, for a snippet with no numbering (a
// skill that stores the cited line itself, e.g. a config secret), its rows
// mapped to lineStart onwards.
func snippetRows(snippet string, lineStart int) ([]row, bool) {
	if rows := numberedRows(snippet); len(rows) > 0 || lineStart < 1 {
		return rows, true
	}
	var out []row
	for i, ln := range strings.Split(strings.TrimRight(snippet, "\n"), "\n") {
		if i == maxRows {
			break
		}
		out = append(out, row{line: lineStart + i, template: strings.TrimSuffix(ln, "\r")})
	}
	return out, false
}

// numberedRows parses the snippet's "N: text" rows (at most maxRows).
func numberedRows(snippet string) []row {
	var out []row
	for _, ln := range strings.Split(snippet, "\n") {
		num, text, ok := strings.Cut(strings.TrimSuffix(ln, "\r"), ": ")
		n, err := strconv.Atoi(num)
		if !ok || err != nil || n < 1 {
			continue
		}
		out = append(out, row{line: n, template: text})
		if len(out) == maxRows {
			break
		}
	}
	return out
}

// relativePath maps the finding's path to a path under root. An absolute path
// must lie under the root itself or under a run-mode mount (/mnt/source, the
// git staging tree); anything else is outside.
func relativePath(p, root string) (string, bool) {
	p = filepath.ToSlash(strings.TrimSpace(p))
	if p == "" || !filepath.IsAbs(p) {
		return filepath.Clean(p), p != ""
	}
	if rel := pathutil.RelToRoot(p, filepath.ToSlash(root)); !filepath.IsAbs(rel) {
		return rel, true
	}
	rel, ok := pathutil.StripRunModePrefix(p)
	return rel, ok && rel != ""
}

// readLines reads rel under root through os.Root (kernel-confined).
func readLines(root, rel string) ([]string, string) {
	if !ownedRoot(root) {
		return nil, ReasonOutsideRoot
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, ReasonUnavailable
	}
	defer r.Close()
	// Stat first (root-confined: a link escaping the root fails here): a FIFO
	// or device is refused before any open, so a reader can never block the
	// request on a pipe.
	info, err := r.Stat(rel)
	if err != nil {
		return nil, openFailure(err)
	}
	if !info.Mode().IsRegular() {
		return nil, ReasonNotRegular
	}
	f, err := r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, openFailure(err)
	}
	defer f.Close()
	return readRegular(f)
}

func openFailure(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return ReasonUnavailable
	}
	return ReasonOutsideRoot
}

func readRegular(f *os.File) ([]string, string) {
	if reason := statRegular(f); reason != "" {
		return nil, reason
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, ReasonUnavailable
	}
	if strings.IndexByte(string(b), 0) >= 0 {
		return nil, ReasonBinary
	}
	return splitLines(string(b)), ""
}

func statRegular(f *os.File) string {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ReasonNotRegular
	}
	if info.Size() > maxFileBytes {
		return ReasonTooLarge
	}
	return ""
}

func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimSuffix(ln, "\r")
	}
	return lines
}

// alignRow matches one masked row against its file line.
func alignRow(r row, lines []string) ([]Span, string) {
	if r.line > len(lines) {
		return nil, ReasonChanged
	}
	raw := lines[r.line-1]
	segs := splitPlaceholders(r.template)
	if len(segs) == 1 {
		return nil, plainRow(r.template, raw)
	}
	if hasPlaceholder(raw) || adjacentPlaceholders(segs) {
		return nil, ReasonAmbiguous
	}
	return alignMasked(r, raw, segs)
}

// alignMasked extracts the row's values; a row with almost no literal text
// keeps them only when each has a recognised secret shape.
func alignMasked(r row, raw string, segs []string) ([]Span, string) {
	spans, reason := extractSpans(r, raw, segs, false)
	if reason != "" {
		// A window cut can end the row anywhere: match it as a prefix, where a
		// trailing placeholder has no knowable extent and yields no value.
		spans, reason = extractSpans(r, raw, segs, true)
	}
	if reason == "" && literalChars(segs) < minLiteralChars && hasShapeless(spans) {
		return nil, ReasonAmbiguous
	}
	return spans, reason
}

func literalChars(segs []string) int {
	n := 0
	for _, seg := range segs {
		n += len(strings.TrimSpace(seg))
	}
	return n
}

func hasShapeless(spans []Span) bool {
	for _, sp := range spans {
		if sp.Kind == "secret" {
			return true
		}
	}
	return false
}

func plainRow(template, raw string) string {
	// A window cut leaves a row that is a PREFIX of its line (the window
	// stage's own rule, window._row_matches), so a prefix matches.
	raw = raw[indentOf(template, raw):]
	if raw == template || (template != "" && strings.HasPrefix(raw, template)) {
		return ""
	}
	return ReasonChanged
}

// indentOf: the leading whitespace of raw that a template stored without it
// (a skill that keeps the trimmed line) leaves out; 0 when the template keeps it.
func indentOf(template, raw string) int {
	if strings.TrimLeft(template, " \t") != template {
		return 0
	}
	return len(raw) - len(strings.TrimLeft(raw, " \t"))
}

// extractSpans walks the literal segments: the first is a prefix, a middle one
// is found by strings.Index (no pattern is built from text), the last is the
// suffix — or, on a cut row, a prefix of the rest, whose trailing placeholder
// then has no knowable extent.
func extractSpans(r row, raw string, segs []string, cut bool) ([]Span, string) {
	indent := indentOf(r.template, raw)
	if !strings.HasPrefix(raw[indent:], segs[0]) {
		return nil, ReasonChanged
	}
	pos := indent + len(segs[0])
	var spans []Span
	for k := 1; k < len(segs); k++ {
		end, next, ok := valueEnd(raw, pos, segs[k], k == len(segs)-1, cut)
		if !ok {
			return nil, ReasonChanged
		}
		if end > pos {
			spans = append(spans, newSpan(r.line, k-1, raw, pos, end))
		}
		pos = next
	}
	return spans, ""
}

// valueEnd locates the value before seg starting at pos; it returns the
// value's end, the position after seg, and whether seg was found.
func valueEnd(raw string, pos int, seg string, last, cut bool) (int, int, bool) {
	switch {
	case last && !cut:
		return suffixEnd(raw, pos, seg)
	case last && seg == "":
		return pos, pos, true // a cut row ends in a placeholder: extent unknown
	}
	i := strings.Index(raw[pos:], seg)
	if i < 0 {
		return 0, 0, false
	}
	return pos + i, pos + i + len(seg), true
}

// suffixEnd: the row's last segment is the line's suffix.
func suffixEnd(raw string, pos int, seg string) (int, int, bool) {
	if !strings.HasSuffix(raw, seg) || len(raw)-len(seg) < pos {
		return 0, 0, false
	}
	return len(raw) - len(seg), len(raw), true
}

func newSpan(line, ordinal int, raw string, start, end int) Span {
	value := raw[start:end]
	kind := classify(value, raw[:start])
	s := Span{Line: line, Ordinal: ordinal, Column: utf8.RuneCountInString(raw[:start]) + 1, Kind: kind, Value: value}
	if !hidesLength[kind] {
		n := utf8.RuneCountInString(value)
		s.Length = &n
	}
	return s
}

func splitPlaceholders(t string) []string {
	segs := []string{t}
	for _, ph := range placeholders {
		var next []string
		for _, s := range segs {
			next = append(next, strings.Split(s, ph)...)
		}
		segs = next
	}
	return segs
}

func hasPlaceholder(s string) bool {
	for _, ph := range placeholders {
		if strings.Contains(s, ph) {
			return true
		}
	}
	return false
}

// adjacentPlaceholders: two placeholders with no literal text between them
// cannot be told apart in the file.
func adjacentPlaceholders(segs []string) bool {
	for _, s := range segs[1 : len(segs)-1] {
		if s == "" {
			return true
		}
	}
	return false
}
