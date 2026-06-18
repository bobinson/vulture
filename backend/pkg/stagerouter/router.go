// Package stagerouter decides, per pipeline stage, which plugins
// from pluginregistry should be invoked for a given audit context.
//
// Feature 0049 introduces this package. It replaces the
// `audit.Types`-based dispatch in service/stream_service.go with
// capability-driven routing.
//
// The router is pure logic: it reads plugin manifests + the supplied
// RouteRequest and produces a slice of DispatchTargets. Actual network
// dispatch remains in the proxy / stream service.
package stagerouter

import (
	"github.com/vulture/backend/internal/config"
	"github.com/vulture/backend/internal/cwe"
	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/pkg/pluginregistry"
)

// Stage names mirror pluginregistry.PhaseXxx but are duplicated here
// to give callers a stage-typed string instead of a phase-typed one.
type Stage string

const (
	StageScan     Stage = "scan"
	StageDiscover Stage = "discover"
	StageProve    Stage = "prove"
	StageValidate Stage = "validate"
)

// RouteRequest is the input to Route: the stage being executed plus
// whatever runtime context the router needs to apply per-stage
// filters.
type RouteRequest struct {
	Stage Stage

	// RequestedTypes is the legacy AuditRequest.Types allow-list.
	// Empty means "no filter — every matching plugin is dispatched".
	// Non-empty means "only plugins whose name appears here".
	RequestedTypes []string

	// Languages observed in the source tree, populated by the caller.
	// Used to filter scan capabilities that declare a `languages` set.
	Languages []string

	// TechStacks observed by an earlier discover stage. Used to
	// filter discover capabilities that declare `tech_stacks`.
	TechStacks []string

	// PriorFindings supplied to the prove stage for CWE /
	// check_id_prefix matching. The router uses the lightweight
	// PriorFinding view (not model.Finding) so callers can populate
	// it from cache without paying for the full audit-finding marshal.
	PriorFindings []model.PriorFinding

	// ValidateEnabled gates the validate stage. When false (the
	// default), Route returns zero validate targets even if validate
	// plugins are installed. Set by the caller from audit config —
	// e.g., when VULTURE_DISABLE_VALIDATE=false and the L1-L5
	// cascade (feature 0046) is allowed to run.
	ValidateEnabled bool
}

// DispatchTarget is one routing decision: a plugin to invoke at this
// stage, the URL the proxy should call, plus the matched capability
// so downstream code can attach phase-specific metadata.
type DispatchTarget struct {
	PluginName string
	URL        string
	Phase      string
	// RuntimeType mirrors the plugin's runtime.type ("container",
	// "in-tree", …). The stream service uses it to decide whether a
	// dispatched source_path must be remapped to the container's
	// audit-inputs mount in LocalMode (Feature 0055).
	RuntimeType string
	Capability  pluginregistry.Capability

	// MatchedFindings is populated only for prove targets: it is the
	// subset of PriorFindings whose CWE / check_id matched this
	// plugin's filters. The proxy passes only these findings to the
	// plugin — data minimisation per the security model in 0049.
	MatchedFindings []model.PriorFinding
}

// Router is the public interface. Implementations route a request to
// the registry's plugins.
type Router interface {
	Route(req RouteRequest) ([]DispatchTarget, error)
}

// New constructs the default router with the standard URL resolver.
// `agents` is the legacy URL map from config.ini (cfg.Agents); env
// vars and manifest-derived URLs fall in behind it via NewURLResolver.
// The layer defaults to cwe.Passthrough() — bit-identical to 0049.
func New(registry pluginregistry.Registry, agents map[string]config.AgentConfig) Router {
	return NewWithResolver(registry, NewURLResolver(agents))
}

// NewWithResolver constructs a router with a caller-supplied
// URLResolver. Used by tests to inject deterministic URLs and by
// future features (0051 health-aware resolver) to swap implementations.
// The layer defaults to cwe.Passthrough().
func NewWithResolver(registry pluginregistry.Registry, resolver URLResolver) Router {
	return &router{registry: registry, resolver: resolver, layer: cwe.Passthrough()}
}

// NewWithLayer composes the default URL resolver with a caller-supplied
// CWE normalisation layer. Feature 0050: lets the stream service pin
// a registry-aware layer without changing the router's other
// constructors.
func NewWithLayer(registry pluginregistry.Registry, agents map[string]config.AgentConfig, layer cwe.Layer) Router {
	if layer == nil {
		layer = cwe.Passthrough()
	}
	return &router{
		registry: registry,
		resolver: NewURLResolver(agents),
		layer:    layer,
	}
}

type router struct {
	registry pluginregistry.Registry
	resolver URLResolver
	layer    cwe.Layer
}

// Route walks the registry and returns DispatchTargets that satisfy
// the request. Disabled plugins (state.toml: enabled=false) are
// never returned. The result preserves registry order so the stream
// service emits agent-start events in a stable order.
//
// A plugin with multiple capabilities for the same stage produces
// one DispatchTarget per matched capability. Callers that need a
// single dispatch per plugin should dedupe by PluginName before
// launching agent goroutines.
func (r *router) Route(req RouteRequest) ([]DispatchTarget, error) {
	var targets []DispatchTarget
	for _, p := range r.registry.Enabled() {
		if len(req.RequestedTypes) > 0 && !contains(req.RequestedTypes, p.Name()) {
			continue
		}
		for _, c := range p.Manifest.Capabilities {
			if Stage(c.Phase) != req.Stage {
				continue
			}
			matched, ok := matchCapability(&req, &p, &c, r.layer)
			if !ok {
				continue
			}
			url := r.resolver.Resolve(p)
			if url == "" {
				continue
			}
			targets = append(targets, DispatchTarget{
				PluginName:      p.Name(),
				URL:             url,
				Phase:           c.Phase,
				RuntimeType:     p.Manifest.Runtime.Type,
				Capability:      c,
				MatchedFindings: matched,
			})
		}
	}
	return targets, nil
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
