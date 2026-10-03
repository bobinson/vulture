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
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

// EnvFlag reads name with the Python agents' env_flag semantics
// (shared.env.env_flag), so a switch both runtimes read cannot disagree:
// on/true/1/yes enable, off/false/0/no disable (case-insensitive, surrounding
// whitespace ignored), and unset, blank or any unrecognised value yields def.
func EnvFlag(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "on", "true", "1", "yes":
		return true
	case "off", "false", "0", "no":
		return false
	default:
		return def
	}
}
