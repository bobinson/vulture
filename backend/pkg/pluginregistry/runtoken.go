package pluginregistry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/vulture/backend/pkg/agentregistry"
)

// AgentTokenEnv names the environment variable that holds an agent's /run
// token: the shared token for the in-tree agents, and the plugin's own derived
// token inside a plugin container.
const AgentTokenEnv = "VULTURE_AGENT_TOKEN"

// AgentTokenHeader is the request header the backend presents that token in
// on every /run call.
const AgentTokenHeader = "X-Vulture-Agent-Token"

// runTokenContext domain-separates the per-plugin derivation. It is versioned
// so that a future scheme can never reproduce a token handed out under this one.
const runTokenContext = "vulture-plugin-run-token/v1:"

// PluginRunToken derives a plugin's own /run token from the run key:
// hex(HMAC-SHA256(key, "vulture-plugin-run-token/v1:"+name)). A plugin that
// holds it can open its own /run and nothing else, and cannot recover the key.
// An empty key gives no token.
func PluginRunToken(key, name string) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(runTokenContext + name))
	return hex.EncodeToString(mac.Sum(nil))
}

// RunTokens is the backend's one view of the /run credentials, built once at
// startup and shared by the agent proxy and the plugin supervisor so the two
// can never disagree. Neither reads the environment per request.
//
// The zero value yields "" for every name (no token is sent or injected).
type RunTokens struct {
	// Shared is the operator's VULTURE_AGENT_TOKEN, sent to in-tree agents only.
	Shared string
	// PluginKey keys every plugin's derived token. It is Shared when one is
	// configured, so an operator can derive a hand-run plugin's token, and a
	// per-process random key otherwise: a plugin under the supervisor always
	// gets a token.
	PluginKey string
	inTree    func(string) bool
}

// NewRunTokens builds the run tokens from the configured shared token and the
// plugin registry, which decides what counts as an in-tree agent. reg may be
// nil: a backend without a registry has no plugins, so the agent registry's
// names decide.
func NewRunTokens(shared string, reg Registry) RunTokens {
	key := shared
	if key == "" {
		key = rand.Text()
	}
	return RunTokens{Shared: shared, PluginKey: key, inTree: inTreePredicate(reg)}
}

// For returns the token the agent proxy presents to agentType: the shared
// token for an in-tree agent, that agent type's derived token otherwise.
func (t RunTokens) For(agentType string) string {
	if t.inTree != nil && t.inTree(agentType) {
		return t.Shared
	}
	return t.ForPlugin(agentType)
}

// ForPlugin returns the token the supervisor injects into the container plugin
// name. It never asks whether name is in-tree, so a container that carries an
// in-tree agent's name still gets its own derived token, never the shared one.
func (t RunTokens) ForPlugin(name string) string {
	return PluginRunToken(t.PluginKey, name)
}

// inTreePredicate decides "in-tree" from the registry, not from the name: a
// plugin from VULTURE_PLUGIN_DIRS may override an in-tree agent's name, and a
// manifest may claim the in-tree tier and runtime. Only the virtual entry the
// registry synthesises counts. A name the registry does not hold, or every
// name without a registry, falls back to the agent registry; no plugin of that
// name exists to receive the token then.
func inTreePredicate(reg Registry) func(string) bool {
	if reg == nil {
		return agentregistry.IsInTree
	}
	return func(name string) bool {
		p, ok := reg.ByName(name)
		if !ok {
			return agentregistry.IsInTree(name)
		}
		return isVirtualInTree(p)
	}
}

// isVirtualInTree reports whether p is the registry's synthesised entry for an
// in-tree agent. IsInTree alone is not enough: a manifest file can declare
// both in-tree fields, but it cannot set the virtual Source.
func isVirtualInTree(p Plugin) bool {
	return p.Source == SourceVirtual && p.IsInTree()
}
