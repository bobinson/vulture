package handler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulture/backend/pkg/agentregistry"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// validateAuditTypes rejects any requested audit type that does not name a real
// agent.
//
// Dispatch resolves a type by case-sensitive map lookup and skips a miss:
//
//	[stream-svc] skipping agent="CWE" (not configured)
//	[dispatch] run complete findings=0 proveResults=0 scores=map[]
//
// so before this, an audit naming a mistyped or miscased agent completed in
// ~30ms with no findings, no scores and status=completed — indistinguishable,
// through the API and the UI, from a clean scan of a clean codebase. A tool
// that reports assurance it never gathered is worse than one that errors, so
// the type list is a contract checked at the door.
//
// Names must match EXACTLY. A miscased name is rejected rather than normalised
// because `types` is also a cache key (0083) and part of how a run is grouped
// for lineage: admitting two spellings of one agent forks both. The error
// carries the canonical spelling, so the caller learns it once.
//
// The valid set is the agent REGISTRY plus this deployment's enabled plugins —
// not its configured agent URLs. Whether an endpoint is wired is a deployment
// question that dispatch already reports on its own; a missing URL does not
// make the type name wrong, and conflating the two would turn a deployment
// problem into a "you typed it wrong" error.
func validateAuditTypes(requested []string, reg pluginregistry.Registry) error {
	// An empty list is not an invalid list: stagerouter.Route reads
	// `len(RequestedTypes) == 0` as "no filter", i.e. the default agent set.
	if len(requested) == 0 {
		return nil
	}
	valid := knownAuditTypes(reg)
	problems := collectTypeProblems(requested, valid, disabledPluginNames(reg))
	if len(problems) == 0 {
		return nil
	}
	return invalidTypesError(problems, valid)
}

// collectTypeProblems returns one phrase per offending type, in the order the
// caller listed them. Every offender is reported, so a caller who passed two
// bad names does not fix one and rediscover the next.
func collectTypeProblems(requested []string, valid map[string]bool, disabled map[string]bool) []string {
	// Suggestions key on the trimmed, lowercased form so a miscased or
	// padded name is pointed at its canonical spelling instead of merely
	// being called unknown.
	canonical := make(map[string]string, len(valid))
	for name := range valid {
		canonical[strings.ToLower(name)] = name
	}
	problems := make([]string, 0, len(requested))
	for _, t := range requested {
		if p := classifyAuditType(t, valid, canonical, disabled); p != "" {
			problems = append(problems, p)
		}
	}
	return problems
}

func invalidTypesError(problems []string, valid map[string]bool) error {
	noun := "type"
	if len(problems) > 1 {
		noun = "types"
	}
	return fmt.Errorf("unknown audit %s: %s; valid types are: %s",
		noun, strings.Join(problems, ", "), strings.Join(sortedKeys(valid), ", "))
}

// classifyAuditType returns "" when the type is dispatchable, else the phrase
// describing what is wrong with it.
func classifyAuditType(t string, valid map[string]bool, canonical map[string]string, disabled map[string]bool) string {
	if valid[t] {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(t))
	if c, ok := canonical[key]; ok {
		return fmt.Sprintf("%q (did you mean %q?)", t, c)
	}
	// An installed-but-disabled plugin would reach dispatch and produce
	// exactly the silent empty run this function exists to prevent, because
	// stagerouter.Route iterates Enabled() only. Naming the real reason
	// beats calling a plugin the operator installed "unknown".
	if disabled[key] {
		return fmt.Sprintf("%q (plugin is installed but not enabled)", t)
	}
	return fmt.Sprintf("%q", t)
}

// knownAuditTypes is every name that addresses a real agent: the in-tree
// registry plus the plugins this deployment has enabled. This is the same set
// GET /api/agents lists, which is where a client discovers it.
func knownAuditTypes(reg pluginregistry.Registry) map[string]bool {
	known := make(map[string]bool, len(agentregistry.AllAgents)+4)
	for _, a := range agentregistry.AllAgents {
		known[a.Type] = true
	}
	if reg == nil {
		return known
	}
	for _, p := range reg.Enabled() {
		if n := p.Name(); n != "" {
			known[n] = true
		}
	}
	return known
}

// disabledPluginNames are installed but switched off, keyed lowercased so the
// lookup matches classifyAuditType's normalised probe.
func disabledPluginNames(reg pluginregistry.Registry) map[string]bool {
	out := map[string]bool{}
	if reg == nil {
		return out
	}
	for _, p := range reg.All() {
		if p.Enabled {
			continue
		}
		if n := p.Name(); n != "" {
			out[strings.ToLower(n)] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
