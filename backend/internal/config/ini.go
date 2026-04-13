package config

import "github.com/vulture/backend/pkg/iniutil"

// iniValues is a flat map of "section.key" -> value loaded from config.ini.
type iniValues map[string]string

// LoadINI parses a minimal INI file. Delegates to the shared iniutil package.
func LoadINI(path string) iniValues {
	return iniValues(iniutil.ParseINI(path))
}

// get returns the value for "section.key", or "" if absent.
func (v iniValues) get(section, key string) string {
	return v[section+"."+key]
}
