package config

import (
	"os"
	"strings"
)

// EnvTruthy reports whether the environment variable name is set to a truthy
// value: "on", "true", "1", or "yes" (case-insensitive, surrounding whitespace
// ignored). Anything else — including unset, empty, "false", "0", "off", "no",
// or an unrecognized string — is false.
//
// This is the single source of truth for boolean env parsing across feature
// 0065's new variables so "on/true/1/yes" are honored consistently (§M6).
func EnvTruthy(name string) bool {
	return EnvFlag(name, false)
}

// EnvFlag reads name with the shared token list (ParseFlag): on/true/1/yes
// enable, off/false/0/no disable (case-insensitive, surrounding whitespace
// ignored), and unset, blank or any unrecognised value yields def. An
// unrecognised NON-BLANK value is also logged once per variable, naming it
// (re-audit #16), so an operator's typo is never silent.
func EnvFlag(name string, def bool) bool {
	raw := os.Getenv(name)
	v, ok := flagToken(raw)
	if !ok {
		warnIfNotBlank(name, raw)
		return def
	}
	return v
}

// ParseFlag is EnvFlag on a value already read, without the warning:
// on/true/1/yes are true, off/false/0/no are false (case-insensitive,
// surrounding whitespace ignored), and anything else yields def.
//
// The token list is pinned by testdata/flag_tokens_0074.json, which the
// Python agents' shared.env.env_flag / env_truthy are held to as well, and
// every agent reader of VULTURE_USE_LLM goes through that token list (T2), so
// the backend's view of a switch both runtimes read — VULTURE_USE_LLM above
// all — agrees with what the agents actually run. Backend-only,
// security-gating switches (VULTURE_LOCAL_MODE, VULTURE_READONLY,
// VULTURE_API_KEYS_ENABLED, VULTURE_REQUIRE_LLM, …) deliberately keep their
// strict `== "true"` reads: widening what turns them on would loosen a
// security boundary.
func ParseFlag(v string, def bool) bool {
	if b, ok := flagToken(v); ok {
		return b
	}
	return def
}

// flagToken maps v to its flag value; ok is false when v is not a token.
func flagToken(v string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return true, true
	case "off", "false", "0", "no":
		return false, true
	default:
		return false, false
	}
}

// warnIfNotBlank warns once about a non-blank value that is not a token.
func warnIfNotBlank(name, raw string) {
	if strings.TrimSpace(raw) != "" {
		warnUnrecognised(name, raw)
	}
}
