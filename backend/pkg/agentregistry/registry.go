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
}

// AllAgents is the central registry of all agent types.
// Adding a new agent requires only appending one entry here.
var AllAgents = []AgentRegistryEntry{
	{"chaos", "Chaos Engineering", "28001", "chaos_engineering", "chaos_agent.main:app", "agent_chaos"},
	{"owasp", "OWASP", "28002", "owasp", "owasp_agent.main:app", "agent_owasp"},
	{"soc2", "SOC2", "28003", "soc2", "soc2_agent.main:app", "agent_soc2"},
	{"cwe", "CWE", "28004", "cwe", "cwe_agent.main:app", "agent_cwe"},
	{"prove", "Prove", "28005", "prove", "prove_agent.main:app", "agent_prove"},
	{"xss", "XSS Scanner", "28006", "xss", "xss_agent.main:app", "agent_xss"},
	{"ssdf", "NIST SSDF v1.1", "28007", "ssdf", "ssdf_agent.main:app", "agent_ssdf"},
	{"discover", "Endpoint Discover", "28008", "discover", "discover_agent.main:app", "agent_discover"},
}

// ScanAgentTypes returns the agent types used for scanning (excludes "prove" and "discover").
func ScanAgentTypes() []string {
	types := make([]string, 0, len(AllAgents))
	for _, a := range AllAgents {
		if a.Type != "prove" && a.Type != "discover" {
			types = append(types, a.Type)
		}
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
