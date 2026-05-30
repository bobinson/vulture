// Package cwe is the read-only CWE normalisation layer introduced by
// feature 0050. It resolves a (AgentType, Category, CheckID) triple
// to a canonical CWE-NNN string using a deterministic 7-step order:
//
//  1. Plugin's rule_to_cwe[CheckID]              (per-plugin, exact)
//  2. Plugin's prefix_to_cwe (longest-prefix on CheckID)
//  3. Canonical short-circuit: Category matches ^CWE-\d{1,5}$
//  4. Composite canonical: Category is "CWE-A|CWE-B|..." → first
//  5. System check_id_prefix_to_cwe (longest-prefix on CheckID)
//  6. System category_to_cwe[Category]
//  7. ""  — no match
//
// All maps are read-only after construction; safe for concurrent use.
package cwe

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vulture/backend/pkg/pluginregistry"
)

// Layer resolves a finding to a canonical CWE string. Empty result
// means "no mapping known"; callers treat that as "don't match
// CWE-filtered prove plugins".
type Layer interface {
	Normalize(agentType, category, checkID string) string
}

// passthroughLayer returns "" for every input. Used by the stage
// router's legacy constructors so existing 0049 behaviour is
// bit-identical when no layer is wired.
type passthroughLayer struct{}

func (passthroughLayer) Normalize(agentType, category, checkID string) string {
	return ""
}

// Passthrough returns a Layer whose Normalize always returns "".
// Exposed so external callers (notably the stage router) can compose
// a no-op layer without re-declaring the type.
func Passthrough() Layer { return passthroughLayer{} }

// canonicalCWERE matches a single canonical CWE-NNN string. Lives in
// this package as well as pluginregistry because the cycle direction
// is cwe → pluginregistry; pluginregistry cannot depend on internal/cwe.
var canonicalCWERE = regexp.MustCompile(`^CWE-\d{1,5}$`)

// defaultLayer holds the per-plugin and system maps. Constructed by
// New / NewFromMaps; immutable thereafter.
type defaultLayer struct {
	perPluginRuleToCWE   map[string]map[string]string
	perPluginPrefixToCWE map[string]map[string]string
	systemCategoryToCWE  map[string]string
	systemCheckIDPrefix  map[string]string
}

// NewFromMaps builds a Layer from caller-supplied maps. Nil maps are
// treated as empty. Used by tests; also the construction primitive
// New itself uses internally.
func NewFromMaps(
	perPluginRuleToCWE map[string]map[string]string,
	perPluginPrefixToCWE map[string]map[string]string,
	systemCategoryToCWE map[string]string,
	systemCheckIDPrefixCWE map[string]string,
) Layer {
	return &defaultLayer{
		perPluginRuleToCWE:   perPluginRuleToCWE,
		perPluginPrefixToCWE: perPluginPrefixToCWE,
		systemCategoryToCWE:  systemCategoryToCWE,
		systemCheckIDPrefix:  systemCheckIDPrefixCWE,
	}
}

// New builds the default Layer from the embedded baseline plus
// per-plugin maps walked from the registry. A nil registry yields a
// system-only layer. VULTURE_CWE_SYSTEM_MAP_DIR overrides embedded
// keys when set and readable.
func New(reg pluginregistry.Registry) Layer {
	sysCat, sysPfx := loadEmbeddedSystemMaps()
	applyOperatorOverride(sysCat, sysPfx)
	ruleMap, prefixMap := collectPerPluginMaps(reg)
	return &defaultLayer{
		perPluginRuleToCWE:   ruleMap,
		perPluginPrefixToCWE: prefixMap,
		systemCategoryToCWE:  sysCat,
		systemCheckIDPrefix:  sysPfx,
	}
}

// applyOperatorOverride merges any override JSONs found in
// VULTURE_CWE_SYSTEM_MAP_DIR into the supplied baseline maps
// (last-write-wins). Missing files / unreadable dirs are silent
// fallbacks per the LLD.
func applyOperatorOverride(cat, pfx map[string]string) {
	dir := os.Getenv("VULTURE_CWE_SYSTEM_MAP_DIR")
	if dir == "" {
		return
	}
	mergeOverrideFile(filepath.Join(dir, "category_to_cwe.json"), cat)
	mergeOverrideFile(filepath.Join(dir, "check_id_prefix_to_cwe.json"), pfx)
}

func mergeOverrideFile(path string, target map[string]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	parsed, err := decodeStringMap(data)
	if err != nil {
		return
	}
	for k, v := range parsed {
		target[k] = v
	}
}

// collectPerPluginMaps walks the registry's enabled plugins and
// indexes each plugin's normalization block by plugin name. Inline
// entries from the manifest are copied first; any external
// mapping_file is then loaded (feature 0050 v1.1) and merged with
// inline-wins semantics.
func collectPerPluginMaps(reg pluginregistry.Registry) (rules, prefixes map[string]map[string]string) {
	rules = map[string]map[string]string{}
	prefixes = map[string]map[string]string{}
	if reg == nil {
		return rules, prefixes
	}
	for _, p := range reg.Enabled() {
		merged := mergePluginRuleMap(p)
		if len(merged) > 0 {
			rules[p.Name()] = merged
		}
		if len(p.Manifest.Normalization.PrefixToCWE) > 0 {
			prefixes[p.Name()] = p.Manifest.Normalization.PrefixToCWE
		}
	}
	return rules, prefixes
}

// mergePluginRuleMap copies the plugin's inline rule_to_cwe into a
// fresh map and overlays any entries loaded from the external
// mapping_file. Inline keys are authoritative (manifest wins on
// conflict — LLD §"Resolution path" / AC 2). External load errors
// are logged and treated as "no external entries"; inline entries
// still flow through.
func mergePluginRuleMap(p pluginregistry.Plugin) map[string]string {
	out := make(map[string]string, len(p.Manifest.Normalization.RuleToCWE))
	for k, v := range p.Manifest.Normalization.RuleToCWE {
		out[k] = v
	}
	external, err := loadMappingFile(p)
	if err != nil {
		log.Printf("[cwe] skip mapping_file for %s: %v", p.Name(), err)
		return out
	}
	for k, v := range external {
		if _, present := out[k]; present {
			continue // inline wins
		}
		out[k] = v
	}
	return out
}

// Normalize implements the resolution order documented at the package
// level. Each step delegates to a tiny helper so the dispatcher stays
// under the cyclomatic-complexity cap.
func (l *defaultLayer) Normalize(agentType, category, checkID string) string {
	if l == nil {
		return ""
	}
	if v := l.pluginRule(agentType, checkID); v != "" {
		return v
	}
	if v := l.pluginPrefix(agentType, checkID); v != "" {
		return v
	}
	if v := canonicalCategory(category); v != "" {
		return v
	}
	if v := compositeCanonical(category); v != "" {
		return v
	}
	if v := longestPrefixMatch(checkID, l.systemCheckIDPrefix); v != "" {
		return v
	}
	if v := l.systemCategoryToCWE[category]; v != "" {
		return v
	}
	return ""
}

func (l *defaultLayer) pluginRule(agentType, checkID string) string {
	if agentType == "" || checkID == "" {
		return ""
	}
	m := l.perPluginRuleToCWE[agentType]
	if m == nil {
		return ""
	}
	return m[checkID]
}

func (l *defaultLayer) pluginPrefix(agentType, checkID string) string {
	if agentType == "" || checkID == "" {
		return ""
	}
	return longestPrefixMatch(checkID, l.perPluginPrefixToCWE[agentType])
}

// canonicalCategory returns Category if it already matches the
// single-CWE form, else "".
func canonicalCategory(category string) string {
	if canonicalCWERE.MatchString(category) {
		return category
	}
	return ""
}

// compositeCanonical handles the legacy xss-agent pattern
// "CWE-79|CWE-113|CWE-644|CWE-1336" — return the first.
func compositeCanonical(category string) string {
	if !strings.Contains(category, "|") {
		return ""
	}
	first := category
	if idx := strings.Index(category, "|"); idx >= 0 {
		first = category[:idx]
	}
	if canonicalCWERE.MatchString(first) {
		return first
	}
	return ""
}

// longestPrefixMatch scans prefixes once, returning the value for the
// longest key that is a prefix of checkID. Deterministic regardless of
// map iteration order: ties are impossible because Go maps have unique
// keys, and we strictly compare length. Empty prefix keys are skipped
// to avoid the degenerate "matches everything" trap.
func longestPrefixMatch(checkID string, prefixes map[string]string) string {
	if checkID == "" || len(prefixes) == 0 {
		return ""
	}
	bestLen := -1
	bestVal := ""
	for prefix, val := range prefixes {
		if prefix == "" {
			continue
		}
		if len(prefix) <= bestLen {
			continue
		}
		if strings.HasPrefix(checkID, prefix) {
			bestLen = len(prefix)
			bestVal = val
		}
	}
	return bestVal
}
