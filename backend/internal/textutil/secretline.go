package textutil

import (
	"regexp"
	"strings"
	"unicode"
)

// A Go port of the agents' secret-line redactor
// (shared.audit_runner._redact_secret_line): mask secret VALUES in text while
// keeping its shape — variable names, keys, quotes. Pinned byte for byte to
// the agent by testdata/secret_line_cases_0074.json.

// RedactionPlaceholder replaces every masked value, as in the agent.
const RedactionPlaceholder = "***REDACTED***"

var (
	// quotedLiteral is one complete single- or double-quoted literal, escapes
	// honoured (RE2 has no backreference, so one alternative per quote).
	quotedLiteral = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`)
	// assignRHS is an unquoted assignment / key-value right-hand side.
	assignRHS = regexp.MustCompile(`^(\s*(?:export\s+|set\s+)?)([A-Za-z_][\w.\[\]'"-]*\s*[:=]\s*)(\S.*?)(\s*(?:#.*)?)$`)
	// commentBody is a trailing comment body (# or //).
	commentBody = regexp.MustCompile(`(#|//)(\s*\S.*)$`)
)

// RedactSecretText redacts each line of s independently.
func RedactSecretText(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = RedactSecretLine(l)
	}
	return strings.Join(lines, "\n")
}

// RedactSecretLine masks the secret values in one line: complete quoted
// literals (dict keys kept), else a dangling truncated literal, else an
// unquoted assignment value, else a trailing comment body.
func RedactSecretLine(line string) string {
	if quotedLiteral.MatchString(line) {
		return maskLiterals(line)
	}
	if i := danglingQuote(line); i != -1 {
		return line[:i+1] + RedactionPlaceholder
	}
	return maskAssignmentOrComment(line)
}

// maskLiterals masks every complete literal's body, then any literal whose
// closing quote was cut away.
func maskLiterals(line string) string {
	var b strings.Builder
	last := 0
	for _, loc := range quotedLiteral.FindAllStringIndex(line, -1) {
		b.WriteString(line[last:loc[0]])
		b.WriteString(maskLiteral(line, loc))
		last = loc[1]
	}
	b.WriteString(line[last:])
	masked := b.String()
	if i := danglingQuote(masked); i != -1 {
		masked = masked[:i+1] + RedactionPlaceholder
	}
	return masked
}

// maskLiteral keeps a literal in dict-key position (followed by ':') verbatim
// and masks any other literal's body, keeping its quotes.
func maskLiteral(line string, loc []int) string {
	lit := line[loc[0]:loc[1]]
	if strings.HasPrefix(strings.TrimLeftFunc(line[loc[1]:], unicode.IsSpace), ":") {
		return lit
	}
	q := lit[:1]
	return q + RedactionPlaceholder + q
}

// danglingQuote is the index of an opening quote never closed, or -1.
func danglingQuote(s string) int {
	for i := 0; i < len(s); {
		next, open := skipQuoted(s, i)
		if open {
			return i
		}
		i = next
	}
	return -1
}

// skipQuoted steps past s[i], or past the whole literal it opens; open
// reports a literal that never closes.
func skipQuoted(s string, i int) (next int, open bool) {
	c := s[i]
	if c != '\'' && c != '"' {
		return i + 1, false
	}
	j := strings.IndexByte(s[i+1:], c)
	if j == -1 {
		return 0, true
	}
	return i + j + 2, false
}

func maskAssignmentOrComment(line string) string {
	if m := assignRHS.FindStringSubmatch(line); m != nil {
		return m[1] + m[2] + RedactionPlaceholder + m[4]
	}
	if loc := commentBody.FindStringSubmatchIndex(line); loc != nil {
		return line[:loc[0]] + line[loc[2]:loc[3]] + " " + RedactionPlaceholder
	}
	return line
}
