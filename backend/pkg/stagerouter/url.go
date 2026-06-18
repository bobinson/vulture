package stagerouter

import (
	"fmt"
	"os"
	"strings"

	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// URLResolver maps a discovered plugin to the HTTP endpoint the proxy
// should dial. The interface lets feature 0051 swap in a health-aware
// implementation without touching the router.
type URLResolver interface {
	Resolve(p pluginregistry.Plugin) string
}

// defaultResolver applies the standard precedence:
//
//  1. VULTURE_AGENT_<NAME>_URL env override — runtime operator
//     intent, wins over baked-in config (twelve-factor: env beats
//     file).
//  2. cfg.Agents[plugin.Name] — config.ini value.
//  3. Manifest-derived `http://agent-<name>:<port>` for container
//     runtimes inside docker-compose.
//
// Returns "" when no URL is resolvable; the router skips such
// plugins with a log line in the calling service.
//
// Security (SH1): manifest values cannot inject into the env or
// config paths — they're only consulted as the final fallback.
//
// Performance (review MAJOR #8): env vars are snapshotted at New()
// time, so Resolve() does only map lookups. Operators must restart
// the backend to pick up VULTURE_AGENT_*_URL changes — consistent
// with how the rest of the config is reloaded.
type defaultResolver struct {
	envURLs   map[string]string
	agents    map[string]config.AgentConfig
	localMode bool
}

// NewURLResolver constructs the default resolver. The env snapshot
// captures every VULTURE_AGENT_*_URL value present at process start,
// keyed by lowercased plugin name (matching plugin.Name slugs).
func NewURLResolver(agents map[string]config.AgentConfig) URLResolver {
	return &defaultResolver{
		envURLs:   snapshotEnvURLs(),
		agents:    agents,
		localMode: os.Getenv("VULTURE_LOCAL_MODE") == "true",
	}
}

func (d *defaultResolver) Resolve(p pluginregistry.Plugin) string {
	name := p.Name()
	if url, ok := d.envURLs[name]; ok && url != "" {
		return url
	}
	if a, ok := d.agents[name]; ok && a.URL != "" {
		return a.URL
	}
	if p.Manifest.Runtime.Type == pluginregistry.RuntimeContainer && p.Manifest.Runtime.Port > 0 {
		// Feature 0052 BLOCKER #1: alias and URL must agree on the
		// DNS-sanitised slug — both go through pluginregistry so they
		// cannot drift. In LocalMode (native launcher) the compose alias
		// doesn't resolve on the host, so a host-network plugin is dialed
		// at localhost:<port> instead (Feature 0055).
		host := pluginregistry.PluginContainerHost(d.localMode, name)
		return fmt.Sprintf("http://%s:%d", host, p.Manifest.Runtime.Port)
	}
	return ""
}

// snapshotEnvURLs walks os.Environ once at startup and extracts every
// VULTURE_AGENT_<NAME>_URL pair, decoding NAME back to the lowercased
// plugin slug.
func snapshotEnvURLs() map[string]string {
	const prefix = "VULTURE_AGENT_"
	const suffix = "_URL"
	out := map[string]string{}
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := kv[:eq]
		val := kv[eq+1:]
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
			continue
		}
		middle := key[len(prefix) : len(key)-len(suffix)]
		// Reverse the encoding from envURLKey (uppercase + dash→
		// underscore). We can't perfectly recover the original slug
		// when both `foo-bar` and `foo_bar` map to FOO_BAR, but
		// plugin names are constrained by the schema regex to use
		// only lowercase + `_` + `-`, so we lowercase + leave _
		// alone — collisions are caller's choice.
		slug := strings.ToLower(middle)
		out[slug] = val
		// Also store with dashes for the dash-named slug variant.
		if strings.Contains(slug, "_") {
			out[strings.ReplaceAll(slug, "_", "-")] = val
		}
	}
	return out
}
