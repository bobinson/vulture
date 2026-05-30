package pluginregistry

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/BurntSushi/toml"
)

// ManifestError wraps a manifest validation failure. The Path field
// is populated by the loader so log lines can identify the offending
// file.
type ManifestError struct {
	Path string
	Err  error
}

func (e *ManifestError) Error() string {
	if e.Path == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("manifest %s: %v", e.Path, e.Err)
}

func (e *ManifestError) Unwrap() error { return e.Err }

// ParseManifest reads `plugin.toml` from disk and validates it.
func ParseManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, &ManifestError{Path: path, Err: err}
	}
	return ParseManifestBytes(data, path)
}

// ParseManifestBytes parses TOML bytes (used by tests and the
// virtual-manifest fast path).
func ParseManifestBytes(data []byte, path string) (Manifest, error) {
	var m Manifest
	if _, err := toml.Decode(string(data), &m); err != nil {
		return Manifest{}, &ManifestError{Path: path, Err: fmt.Errorf("toml decode: %w", err)}
	}
	if err := ValidateManifest(&m); err != nil {
		return Manifest{}, &ManifestError{Path: path, Err: err}
	}
	return m, nil
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
var semverRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$`)
// CWERe is the canonical CWE-NNN regexp. Exported so external loaders
// (e.g. internal/cwe's mapping_file loader) can validate against the
// same single source of truth.
var CWERe = regexp.MustCompile(`^CWE-\d{1,5}$`)

// cosignRE matches the minimum-shape Sigstore subject. The {2,256}
// quantifier requires the path body (after the mandatory leading
// alphanumeric char) to be at least 2 more chars — so a fully-qualified
// subject like `cosign://a/bc` (14 chars total) is the shortest
// accepted URL. The character class deliberately excludes `:` (rejects
// nested URL schemes like `cosign://file://...`) and `?` (no query
// strings). Mirrors `manifest.schema.json` line 49.
var cosignRE = regexp.MustCompile(`^cosign://[A-Za-z0-9][A-Za-z0-9._~@/-]{2,256}$`)

// Schema-derived length caps. Mirrors `manifest.schema.json` `maxLength`
// declarations on each [plugin] subfield. Enforcing these at load time
// protects the registry from megabyte-sized strings being held in memory
// for every plugin entry.
const (
	maxDisplayNameLen = 100
	maxPublisherLen   = 100
	maxDescriptionLen = 500
	maxLicenseLen     = 50

	// MaxNormalisationEntries caps the cardinality of each per-plugin
	// normalization map (rule_to_cwe / prefix_to_cwe). Prevents a
	// hostile manifest from holding the registry hostage with
	// millions of entries. Feature 0050 BLOCKER #5. Exported so the
	// mapping_file loader in internal/cwe consumes the single source
	// of truth without duplicating the constant.
	MaxNormalisationEntries = 10000
)

// validTiers and validRuntimeTypes are the schema enums we enforce
// at load time. Mistakes here are operator errors, not crash bugs —
// the loader skips the manifest and logs a warning.
var validTiers = map[string]bool{
	TierInTree:          true,
	TierCommunitySigned: true,
	TierUserSupplied:    true,
}

var validRuntimeTypes = map[string]bool{
	RuntimeInTree:     true,
	RuntimeContainer:  true,
	RuntimeHostBinary: true,
}

var validPhases = map[string]bool{
	PhaseScan:     true,
	PhaseDiscover: true,
	PhaseProve:    true,
	PhaseValidate: true,
}

var validAcks = map[string]bool{
	"runs-real-exploits": true,
	"network-egress":     true,
	"host-network":       true,
	"host-fs-write":      true,
	"privileged":         true,
	"commercial-key":     true,
	"gpu-access":         true,
	"kernel-modules":     true,
}

// validNetworks mirrors `runtime.network` enum.
var validNetworks = map[string]bool{
	"none":     true,
	"internal": true,
	"host":     true,
}

// validEmits mirrors the `emits` enum at manifest.schema.json:166–179.
// Each value is a legal event name the plugin protocol can route.
var validEmits = map[string]bool{
	"run_started":       true,
	"run_finished":      true,
	"agent_start":       true,
	"agent_end":         true,
	"thinking":          true,
	"progress":          true,
	"finding":           true,
	"discover_result":   true,
	"proof_phase":       true,
	"proof_plan":        true,
	"proof_review":      true,
	"proof_attempt":     true,
	"proof_reflection":  true,
	"proof_result":      true,
	"proof_summary":     true,
	"validation_update": true,
	"dedup_stats":       true,
	"token_savings":     true,
	"result":            true,
}

// validLanguages mirrors the `languages` enum at manifest.schema.json:156–162.
// Plugins targeting languages outside this set should use "unknown".
var validLanguages = map[string]bool{
	"python": true, "javascript": true, "typescript": true, "go": true,
	"java": true, "kotlin": true, "rust": true, "ruby": true, "csharp": true,
	"php": true, "cpp": true, "c": true, "swift": true, "scala": true,
	"shell": true, "sql": true, "yaml": true, "json": true, "toml": true,
	"html": true, "css": true, "markdown": true, "dockerfile": true,
	"makefile": true, "groovy": true, "lua": true, "r": true, "dart": true,
	"perl": true, "unknown": true,
}

// requiredEmitForPhase encodes the schema's per-phase allOf rules.
// scan→finding, discover→discover_result, validate→validation_update.
// prove has no single required emit (it pairs proof_* events that the
// schema validates individually via the emits enum).
var requiredEmitForPhase = map[string]string{
	PhaseScan:     "finding",
	PhaseDiscover: "discover_result",
	PhaseValidate: "validation_update",
}

// ValidateManifest applies the schema rules that matter at load time.
// JSON Schema is the authority on shape; this is a hand-rolled subset
// covering the rules that would prevent the registry from functioning
// or cause downstream dispatch (feature 0049) to misbehave.
func ValidateManifest(m *Manifest) error {
	if err := validatePluginBlock(&m.Plugin); err != nil {
		return err
	}
	if err := validateTrustBlock(&m.Trust); err != nil {
		return err
	}
	if err := validateRuntimeBlock(&m.Runtime); err != nil {
		return err
	}
	if err := validateRuntimeAckConsistency(&m.Runtime, &m.Trust); err != nil {
		return err
	}
	if len(m.Capabilities) == 0 {
		return errors.New("[[capabilities]]: at least one entry required")
	}
	for i, c := range m.Capabilities {
		if err := validateCapability(&c); err != nil {
			return fmt.Errorf("[[capabilities]][%d]: %w", i, err)
		}
	}
	if err := validateNormalizationBlock(&m.Normalization); err != nil {
		return err
	}
	return nil
}

// validateNormalizationBlock enforces the cardinality cap on
// per-plugin normalisation maps (feature 0050 BLOCKER #5).
func validateNormalizationBlock(n *NormalizationBlock) error {
	if len(n.RuleToCWE) > MaxNormalisationEntries {
		return fmt.Errorf("[normalization].rule_to_cwe: exceeds %d entries (got %d)",
			MaxNormalisationEntries, len(n.RuleToCWE))
	}
	if len(n.PrefixToCWE) > MaxNormalisationEntries {
		return fmt.Errorf("[normalization].prefix_to_cwe: exceeds %d entries (got %d)",
			MaxNormalisationEntries, len(n.PrefixToCWE))
	}
	return nil
}

func validatePluginBlock(p *PluginBlock) error {
	if p.Name == "" {
		return errors.New("[plugin].name: required")
	}
	if !nameRE.MatchString(p.Name) {
		return fmt.Errorf("[plugin].name %q: must match %s", p.Name, nameRE)
	}
	if p.Version == "" {
		return errors.New("[plugin].version: required")
	}
	if !semverRE.MatchString(p.Version) {
		return fmt.Errorf("[plugin].version %q: must be semver", p.Version)
	}
	if p.APIVersion != APIVersionV1 {
		return fmt.Errorf("[plugin].api_version %q: only %q is supported", p.APIVersion, APIVersionV1)
	}
	if p.Publisher == "" {
		return errors.New("[plugin].publisher: required")
	}
	if p.Description == "" {
		return errors.New("[plugin].description: required")
	}
	if len(p.DisplayName) > maxDisplayNameLen {
		return fmt.Errorf("[plugin].display_name: exceeds %d chars", maxDisplayNameLen)
	}
	if len(p.Publisher) > maxPublisherLen {
		return fmt.Errorf("[plugin].publisher: exceeds %d chars", maxPublisherLen)
	}
	if len(p.Description) > maxDescriptionLen {
		return fmt.Errorf("[plugin].description: exceeds %d chars", maxDescriptionLen)
	}
	if len(p.License) > maxLicenseLen {
		return fmt.Errorf("[plugin].license: exceeds %d chars", maxLicenseLen)
	}
	return nil
}

func validateTrustBlock(t *TrustBlock) error {
	if !validTiers[t.Tier] {
		return fmt.Errorf("[trust].tier %q: must be one of in-tree, community-signed, user-supplied", t.Tier)
	}
	if t.Tier == TierCommunitySigned && t.Signature == "" {
		return errors.New("[trust].signature: required when tier=community-signed")
	}
	if t.Signature != "" && !cosignRE.MatchString(t.Signature) {
		return fmt.Errorf("[trust].signature %q: must match cosign://… pattern", t.Signature)
	}
	if t.Tier == TierUserSupplied && len(t.RequiredAck) == 0 {
		return errors.New("[trust].required_ack: must list at least one ack for tier=user-supplied")
	}
	seen := make(map[string]bool, len(t.RequiredAck))
	for _, ack := range t.RequiredAck {
		if !validAcks[ack] {
			return fmt.Errorf("[trust].required_ack: %q is not a recognised ack", ack)
		}
		if seen[ack] {
			return fmt.Errorf("[trust].required_ack: %q listed more than once", ack)
		}
		seen[ack] = true
	}
	return nil
}

func validateRuntimeBlock(r *RuntimeBlock) error {
	if !validRuntimeTypes[r.Type] {
		return fmt.Errorf("[runtime].type %q: must be one of in-tree, container, host-binary", r.Type)
	}
	switch r.Type {
	case RuntimeInTree:
		if r.ModulePath == "" {
			return errors.New("[runtime].module_path: required for type=in-tree")
		}
	case RuntimeContainer:
		if r.Image == "" {
			return errors.New("[runtime].image: required for type=container")
		}
		if r.Port < 1024 || r.Port > 65535 {
			return fmt.Errorf("[runtime].port %d: must be 1024-65535 for type=container", r.Port)
		}
	case RuntimeHostBinary:
		if r.Executable == "" {
			return errors.New("[runtime].executable: required for type=host-binary")
		}
		if r.Port != 0 && (r.Port < 1024 || r.Port > 65535) {
			return fmt.Errorf("[runtime].port %d: must be 1024-65535 when set", r.Port)
		}
	}
	if r.Network != "" && !validNetworks[r.Network] {
		return fmt.Errorf("[runtime].network %q: must be one of none, internal, host", r.Network)
	}
	return nil
}

// validateRuntimeAckConsistency enforces cross-block rules between
// `[runtime]` and `[trust].required_ack`. Mirrors the Python linter's
// `_check_network_host_requires_egress_ack`.
func validateRuntimeAckConsistency(r *RuntimeBlock, t *TrustBlock) error {
	if r.Network != "host" {
		return nil
	}
	hasEgress := false
	hasHostNet := false
	for _, ack := range t.RequiredAck {
		switch ack {
		case "network-egress":
			hasEgress = true
		case "host-network":
			hasHostNet = true
		}
	}
	if !hasEgress {
		return errors.New("[runtime].network=host requires [trust].required_ack to include \"network-egress\"")
	}
	if !hasHostNet {
		return errors.New("[runtime].network=host requires [trust].required_ack to include \"host-network\" (feature 0052 MAJOR #8)")
	}
	return nil
}

func validateCapability(c *Capability) error {
	if !validPhases[c.Phase] {
		return fmt.Errorf("phase %q: must be one of scan, discover, prove, validate", c.Phase)
	}
	if len(c.Emits) == 0 {
		return errors.New("emits: at least one event required")
	}
	seenEmit := make(map[string]bool, len(c.Emits))
	for _, e := range c.Emits {
		if !validEmits[e] {
			return fmt.Errorf("emits %q: not a recognised event name", e)
		}
		seenEmit[e] = true
	}
	if required, ok := requiredEmitForPhase[c.Phase]; ok {
		if !seenEmit[required] {
			return fmt.Errorf("emits: phase=%s requires %q in emits", c.Phase, required)
		}
	}
	for _, lang := range c.Languages {
		if !validLanguages[lang] {
			return fmt.Errorf("languages %q: not a recognised language", lang)
		}
	}
	for _, cwe := range c.MatchesCWE {
		if !CWERe.MatchString(cwe) {
			return fmt.Errorf("matches_cwe %q: must match CWE-\\d{1,5}", cwe)
		}
	}
	return nil
}
