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
	assignRHS = regexp.MustCompile(spelled(`^(\s*(?:export\s+|set\s+)?)([A-Za-z_][\w.\[\]'"-]*\s*[:=]\s*)(\S.*?)(\s*(?:#.*)?)$`))
	// commentBody is a trailing comment body (# or //).
	commentBody = regexp.MustCompile(spelled(`(#|//)(\s*\S.*)$`))

	// The prose pass (0074 T3). Both patterns open with an explicit boundary
	// group instead of \b, and use [ \t] instead of \s, because Python's \b
	// and \s are Unicode-aware and Go's are ASCII: the agent's copy must match
	// the same bytes. The keyword alternation spells i as [iİı]: Python's
	// case-insensitive i also matches U+0130 and U+0131 and Go's does not, and
	// the wider match is the one that masks. Pinned by prose_cases in the
	// shared fixture.
	//
	// proseNamedSecret is a secret-named key followed by ':' or '=' anywhere
	// in a sentence ("Found password: hunter2 in settings.py").
	proseNamedSecret = regexp.MustCompile(`(^|[^A-Za-z0-9_-])([A-Za-z0-9_-]*(?i:password|passwd|pwd|secret|token|ap[iİı][_-]?key|access[_-]?key|pr[iİı]vate[_-]?key)[ \t]*[:=][ \t]*)([^ \t'"]+)`)
	// proseKeyToken is a token whose shape alone marks it a credential.
	proseKeyToken = regexp.MustCompile(`(^|[^A-Za-z0-9_-])((?:sk|pk|rk)[-_](?:live|test|proj)[-_][A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,})`)
)

// The code-line patterns are written with \s, \S and \w for legibility
// and compiled with those spelled out, because RE2's are ASCII and Python's
// Unicode (0074 T3): whitespace is exactly unicode.IsSpace (\v and the
// Unicode spaces included, U+001C-U+001F and U+FEFF not), and a word
// character is [A-Za-z0-9_] or any non-ASCII rune that is not whitespace. The
// agent builds the same three classes (shared.audit_runner), pinned by the
// non-ASCII rows of the shared fixture.
const (
	nonASCIISpace = `\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}`
	spaceClass    = `[\t\n\x0B\f\r ` + nonASCIISpace + `]`
	nonSpaceClass = `[^\t\n\x0B\f\r ` + nonASCIISpace + `]`
	// wordChars is the word class's members WITHOUT brackets — \w only ever
	// appears inside a bracket expression: ASCII word characters and every
	// non-ASCII rune outside nonASCIISpace.
	wordChars = `A-Za-z0-9_\x{80}-\x{84}\x{86}-\x{9F}\x{A1}-\x{167F}\x{1681}-\x{1FFF}` +
		`\x{200B}-\x{2027}\x{202A}-\x{202E}\x{2030}-\x{205E}\x{2060}-\x{2FFF}\x{3001}-\x{10FFFF}`
)

// spelled rewrites \s, \S and \w in a code-line pattern to the shared
// classes.
var spelled = strings.NewReplacer(`\s`, spaceClass, `\S`, nonSpaceClass, `\w`, wordChars).Replace

// RedactSecretText redacts each line of s independently: the code-line
// redactor (RedactSecretLine), then the prose pass, so a secret written in a
// sentence is masked too.
func RedactSecretText(s string) string {
	return eachLine(s, func(l string) string { return redactProse(RedactSecretLine(l)) })
}

// RedactProseSecrets is the prose pass alone: a named secret's value and any
// key-shaped token are masked, and everything else — quoted identifiers,
// apostrophes — is kept. For text that is prose rather than a code line.
func RedactProseSecrets(s string) string {
	return eachLine(s, redactProse)
}

// eachLine applies fn to every line of s.
func eachLine(s string, fn func(string) string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = fn(l)
	}
	return strings.Join(lines, "\n")
}

// redactProse masks a named secret's value and any key-shaped token.
func redactProse(line string) string {
	line = proseNamedSecret.ReplaceAllString(line, "${1}${2}"+RedactionPlaceholder)
	return proseKeyToken.ReplaceAllString(line, "${1}"+RedactionPlaceholder)
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
