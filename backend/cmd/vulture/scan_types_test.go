package main

import (
	"testing"

	"github.com/vulture/backend/pkg/agentregistry"
)

// The release CLI must not ask for an agent that cannot run in the scan stage.
//
// It used to derive its type list as "every configured agent except prove",
// which swept in `discover` — a PIPELINE STAGE with no scan-stage capability.
// The stage router correctly produced no target for it, so it never reported,
// and every release-smoke audit silently shipped one requested-but-absent
// agent. Once a missing agent began failing the audit (a requested detector
// that never ran is not a clean scan), that latent mismatch surfaced as:
//
//	[stream-svc] agent="discover" was requested but the router produced
//	             no scan target for it
//	[persist] marked FAILED (incomplete coverage): requested agents did not
//	          run: discover
//
// The audit was right and the request was wrong. `prove` was already excluded
// by hand; `discover` is the same kind of thing and was missed, which is the
// argument for asking the registry instead of maintaining a second list here.
func TestScanAuditTypesExcludePipelineStages(t *testing.T) {
	got := scanAuditTypes()
	if len(got) == 0 {
		t.Fatal("the scan requests no agents at all")
	}
	for _, pipeline := range []string{"prove", "discover"} {
		for _, typ := range got {
			if typ == pipeline {
				t.Errorf("scan requests %q, a pipeline stage with no scan-stage "+
					"capability: the router yields no target and the audit fails "+
					"for an agent that was never able to run", pipeline)
			}
		}
	}
}

// Non-vacuity, and the reason this is not just a hand-written deny list: the
// set must still carry the real scanners, Optional ones included. Narrowing to
// ScanAgentTypes() would silently drop do178c and owasp from every release
// smoke run.
func TestScanAuditTypesKeepTheRealScanners(t *testing.T) {
	got := scanAuditTypes()
	have := make(map[string]bool, len(got))
	for _, t := range got {
		have[t] = true
	}
	for _, want := range []string{"cwe", "chaos", "soc2", "xss", "ssdf", "asvs", "owasp", "do178c"} {
		if !have[want] {
			t.Errorf("scan no longer requests %q", want)
		}
	}
}

// Every requested type must name a real registry entry, so a typo here cannot
// become an audit that fails for an agent that does not exist.
func TestScanAuditTypesAreAllRealAgents(t *testing.T) {
	known := make(map[string]bool, len(agentregistry.AllAgents))
	for _, a := range agentregistry.AllAgents {
		known[a.Type] = true
	}
	for _, typ := range scanAuditTypes() {
		if !known[typ] {
			t.Errorf("scan requests %q, which is not in the agent registry", typ)
		}
	}
}
