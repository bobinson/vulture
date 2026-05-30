// Package pluginregistry is the runtime registry of installed Vulture
// plugins. Feature 0048 introduces it as the successor to the static
// `agentregistry.AllAgents` slice.
//
// A plugin is a unit shipped under the vulture-plugin/1.0 contract
// (see docs/spec/plugin-v1/contract.md). At runtime it may be:
//
//   - An in-tree agent — virtual manifest synthesised from
//     agentregistry.AllAgents (preserves today's behaviour exactly).
//   - A locally installed plugin under ~/.vulture/plugins/.
//   - A test/packaging override directory listed in VULTURE_PLUGIN_DIRS.
//
// In v1 (this feature) the registry is read-only after startup and
// the consumer surface is:
//
//	pluginregistry.Default()             // singleton, lazy-initialised
//	r.All()                              // every discovered plugin
//	r.Enabled()                          // only state.enabled=true
//	r.ByName("semgrep")                  // lookup
//
// Capability-based dispatch and stage routing land in feature 0049.
package pluginregistry

// Plugin is the in-memory representation of a parsed manifest plus its
// persisted state. Fields mirror the TOML schema at
// docs/spec/plugin-v1/manifest.schema.json.
type Plugin struct {
	// Manifest is the parsed TOML.
	Manifest Manifest

	// Source records where the manifest came from, for diagnostics.
	// One of: "in-tree", "local", "env:<path>".
	Source string

	// Path is the absolute path to the plugin.toml file. Empty for
	// virtual (in-tree) manifests.
	Path string

	// Enabled mirrors the operator's choice in state.toml. Defaults
	// to true on first discovery.
	Enabled bool
}

// Manifest is the parsed plugin.toml.
type Manifest struct {
	Plugin        PluginBlock        `toml:"plugin"`
	Trust         TrustBlock         `toml:"trust"`
	Runtime       RuntimeBlock       `toml:"runtime"`
	Capabilities  []Capability       `toml:"capabilities"`
	Normalization NormalizationBlock `toml:"normalization"`
}

// PluginBlock is the [plugin] section.
type PluginBlock struct {
	Name          string `toml:"name"`
	DisplayName   string `toml:"display_name"`
	Version       string `toml:"version"`
	APIVersion    string `toml:"api_version"`
	Publisher     string `toml:"publisher"`
	Description   string `toml:"description"`
	Homepage      string `toml:"homepage"`
	License       string `toml:"license"`
	Documentation string `toml:"documentation"`
}

// TrustBlock is the [trust] section.
type TrustBlock struct {
	Tier        string   `toml:"tier"`
	Signature   string   `toml:"signature"`
	RequiredAck []string `toml:"required_ack"`
}

// RuntimeBlock is the [runtime] section.
type RuntimeBlock struct {
	Type            string         `toml:"type"`
	Image           string         `toml:"image"`
	Executable      string         `toml:"executable"`
	ModulePath      string         `toml:"module_path"`
	Port            int            `toml:"port"`
	HealthEndpoint  string         `toml:"health_endpoint"`
	InfoEndpoint    string         `toml:"info_endpoint"`
	RunEndpoint     string         `toml:"run_endpoint"`
	Restart         string         `toml:"restart"`
	Network         string         `toml:"network"`
	Resources       map[string]any `toml:"resources"`
	FS              map[string]any `toml:"fs"`
	Env             map[string]any `toml:"env"`
}

// Capability is one entry in `[[capabilities]]`.
type Capability struct {
	Phase                string   `toml:"phase"`
	Languages            []string `toml:"languages"`
	Emits                []string `toml:"emits"`
	TimeoutS             int      `toml:"timeout_s"`
	MaxIterations        int      `toml:"max_iterations"`
	MatchesCWE           []string `toml:"matches_cwe"`
	MatchesCheckIDPrefix []string `toml:"matches_check_id_prefix"`
	TechStacks           []string `toml:"tech_stacks"`
	Selectors            map[string]any `toml:"selectors"`
}

// NormalizationBlock is the [normalization] section. Consumed by 0050.
type NormalizationBlock struct {
	RuleToCWE         map[string]string `toml:"rule_to_cwe"`
	PrefixToCWE       map[string]string `toml:"prefix_to_cwe"`
	MappingFile       string            `toml:"mapping_file"`
	FallbackCrossMap  string            `toml:"fallback_cross_map"`
}

// Name returns the plugin's slug.
func (p Plugin) Name() string { return p.Manifest.Plugin.Name }

// IsInTree reports whether this plugin is one of the legacy in-tree
// agents (tier=in-tree, runtime.type=in-tree).
func (p Plugin) IsInTree() bool {
	return p.Manifest.Trust.Tier == TierInTree &&
		p.Manifest.Runtime.Type == RuntimeInTree
}

// Trust tier values mirror the schema enum.
const (
	TierInTree          = "in-tree"
	TierCommunitySigned = "community-signed"
	TierUserSupplied    = "user-supplied"
)

// Runtime type values mirror the schema enum.
const (
	RuntimeInTree     = "in-tree"
	RuntimeContainer  = "container"
	RuntimeHostBinary = "host-binary"
)

// Phase values mirror the schema enum.
const (
	PhaseScan     = "scan"
	PhaseDiscover = "discover"
	PhaseProve    = "prove"
	PhaseValidate = "validate"
)

// APIVersionV1 is the only api_version this build understands.
const APIVersionV1 = "vulture-plugin/1.0"
