package agentregistry

import "strings"

// AgentRegistryEntry defines a single agent type in the central registry.
type AgentRegistryEntry struct {
	Type        string // e.g. "chaos"
	Name        string // e.g. "Chaos Engineering"
	DefaultPort string // e.g. "28001"
	DirName     string // agents/ subdirectory, e.g. "chaos_engineering"
	Module      string // uvicorn module, e.g. "chaos_agent.main:app"
	INIKey      string // config.ini [ports] key, e.g. "agent_chaos"

	// Optional agents are excluded from ScanAgentTypes(), the default
	// scan set used when the operator doesn't pass --types. They still
	// appear in AllScanAgentTypes() and on /api/agents so users can
	// discover them and opt-in via the CLI flag or the frontend
	// selector. Use this flag for niche / domain-specific scanners
	// (e.g. avionics-only DO-178C) where running by default would add
	// noise for users outside that domain.
	Optional bool
}

// AllAgents is the central registry of all agent types.
// Adding a new agent requires only appending one entry here.
var AllAgents = []AgentRegistryEntry{
	{Type: "chaos", Name: "Chaos Engineering", DefaultPort: "28001", DirName: "chaos_engineering", Module: "chaos_agent.main:app", INIKey: "agent_chaos"},
	{Type: "owasp", Name: "OWASP", DefaultPort: "28002", DirName: "owasp", Module: "owasp_agent.main:app", INIKey: "agent_owasp"},
	{Type: "soc2", Name: "SOC2", DefaultPort: "28003", DirName: "soc2", Module: "soc2_agent.main:app", INIKey: "agent_soc2"},
	{Type: "cwe", Name: "CWE", DefaultPort: "28004", DirName: "cwe", Module: "cwe_agent.main:app", INIKey: "agent_cwe"},
	{Type: "prove", Name: "Prove", DefaultPort: "28005", DirName: "prove", Module: "prove_agent.main:app", INIKey: "agent_prove"},
	{Type: "xss", Name: "XSS Scanner", DefaultPort: "28006", DirName: "xss", Module: "xss_agent.main:app", INIKey: "agent_xss"},
	{Type: "ssdf", Name: "NIST SSDF v1.1", DefaultPort: "28007", DirName: "ssdf", Module: "ssdf_agent.main:app", INIKey: "agent_ssdf"},
	{Type: "discover", Name: "Endpoint Discover", DefaultPort: "28008", DirName: "discover", Module: "discover_agent.main:app", INIKey: "agent_discover"},
	// Avionics-only — opt-in via --types do178c (CLI) or the frontend selector.
	{Type: "do178c", Name: "DO-178C Compliance Auditor", DefaultPort: "28009", DirName: "do178c", Module: "do178c_agent.main:app", INIKey: "agent_do178c", Optional: true},
	{Type: "asvs", Name: "ASVS Compliance Auditor", DefaultPort: "28010", DirName: "asvs", Module: "asvs_agent.main:app", INIKey: "agent_asvs"},
}

// ScanAgentTypes returns the default scan agent set: every registry
// entry that isn't a pipeline stage (prove/discover) and isn't
// flagged Optional. This is what runs when the user invokes a scan
// without an explicit --types list.
//
// Optional agents (e.g. do178c) are intentionally excluded from this
// set so the default flow doesn't dispatch domain-specific scanners
// outside their target audience. Use AllScanAgentTypes() for the
// "everything available" view.
func ScanAgentTypes() []string {
	types := make([]string, 0, len(AllAgents))
	for _, a := range AllAgents {
		if a.Type == "prove" || a.Type == "discover" {
			continue
		}
		if a.Optional {
			continue
		}
		types = append(types, a.Type)
	}
	return types
}

// AllScanAgentTypes returns every scan-capable agent including those
// flagged Optional. Pipeline stages (prove/discover) are still
// excluded — they aren't scanners. Used by the CLI --types help text
// and the frontend agent selector to advertise opt-in agents.
func AllScanAgentTypes() []string {
	types := make([]string, 0, len(AllAgents))
	for _, a := range AllAgents {
		if a.Type == "prove" || a.Type == "discover" {
			continue
		}
		types = append(types, a.Type)
	}
	return types
}

// EnvPortKey returns the env var name for the agent's port, e.g. "VULTURE_AGENT_CHAOS_PORT".
func (e AgentRegistryEntry) EnvPortKey() string {
	return "VULTURE_AGENT_" + strings.ToUpper(e.Type) + "_PORT"
}

// EnvURLKey returns the env var name for the agent's URL, e.g. "VULTURE_AGENT_CHAOS_URL".
func (e AgentRegistryEntry) EnvURLKey() string {
	return "VULTURE_AGENT_" + strings.ToUpper(e.Type) + "_URL"
}

// DefaultHost returns the docker-compose service hostname, e.g. "agent-chaos".
func (e AgentRegistryEntry) DefaultHost() string {
	return "agent-" + e.Type
}
