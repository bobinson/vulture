package server

import (
	"regexp"
	"strings"
)

// SensitiveFieldNames is the case-insensitive allow-list of field
// names whose VALUES must be redacted before logging. Lookup is
// O(1) on the lowercased name. See plan invariant S16 — field-name
// allow-list, NOT a value-pattern regex (a value pattern over-redacts
// commit SHAs and finding fingerprints while under-redacting
// non-Bearer credentials).
var SensitiveFieldNames = map[string]struct{}{
	"authorization":     {},
	"x-api-key":         {},
	"x-auth-token":      {},
	"cookie":            {},
	"set-cookie":        {},
	"openai_api_key":    {},
	"anthropic_api_key": {},
	"ollama_api_key":    {},
	"vulture_jwt_secret": {},
	"jwt_secret":        {},
	"secret":            {},
	"password":          {},
	"passwd":            {},
	"pwd":               {},
	"token":             {},
	"access_token":      {},
	"refresh_token":     {},
	"session":           {},
	"api_key":           {},
	"apikey":            {},
	"private_key":       {},
	"client_secret":     {},
}

// IsSensitiveFieldName returns true if name (case-insensitive) is on
// the allow-list and therefore its associated value should be masked.
func IsSensitiveFieldName(name string) bool {
	_, ok := SensitiveFieldNames[strings.ToLower(name)]
	return ok
}

// MaskSecret returns a debug-friendly redacted form of value. Short
// values get the literal "<redacted>"; long values keep the first 4
// and last 4 chars for log debuggability — `sk_l...abcd`.
func MaskSecret(value string) string {
	if len(value) < 10 {
		return "<redacted>"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// Line-level redactors for known string shapes that appear inside
// free-form log messages (where there is no structured field-name to
// dispatch on). These are intentionally conservative: each pattern
// targets a syntactic shape that is almost certainly a credential,
// not a content-pattern guess.
var (
	authHeaderRe = regexp.MustCompile(`(?i)\b(Authorization:\s*Bearer)\s+([A-Za-z0-9._\-]+)`)
	kvSecretRe   = regexp.MustCompile(
		`(?i)\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|VULTURE_JWT_SECRET|JWT_SECRET|api[_-]?key|password|secret|token)=` +
			`([^\s"']+)`)
)

// RedactLine returns line with known credential shapes masked. The
// goal is best-effort: structured logging (RedactField / MaskSecret)
// is the primary tool; this catches stragglers in free-form
// fmt.Printf-style output.
func RedactLine(line string) string {
	out := authHeaderRe.ReplaceAllStringFunc(line, func(match string) string {
		sm := authHeaderRe.FindStringSubmatch(match)
		if len(sm) != 3 {
			return match
		}
		return sm[1] + " " + MaskSecret(sm[2])
	})
	out = kvSecretRe.ReplaceAllStringFunc(out, func(match string) string {
		sm := kvSecretRe.FindStringSubmatch(match)
		if len(sm) != 3 {
			return match
		}
		return sm[1] + "=" + MaskSecret(sm[2])
	})
	return out
}

// RedactField is the structured-logging entry point. Callers wrap
// each field-name/value pair through this helper before emitting to
// the log sink.
func RedactField(name, value string) string {
	if IsSensitiveFieldName(name) {
		return MaskSecret(value)
	}
	return value
}
