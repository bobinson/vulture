//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// An audit type that addresses no dispatchable agent must be REJECTED at
// creation, not accepted and then silently skipped at dispatch.
//
// The behaviour this replaces: the registry keys are lowercase and dispatch is
// a case-sensitive map lookup, so `types: ["CWE"]` produced
//
//	[stream-svc] skipping agent="CWE" (not configured)
//	[dispatch] run complete findings=0 proveResults=0 scores=map[]
//
// in ~30ms — a run indistinguishable, in the UI and in the API, from a clean
// scan of a clean codebase. For a security tool that is the worst available
// failure mode: it reports assurance it never gathered.
func TestAuditCreateRejectsMiscasedType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"CWE"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for miscased type, got %d", resp.StatusCode)
	}

	var body map[string]string
	readJSON(t, resp, &body)
	msg := body["error"]
	if !strings.Contains(msg, `"CWE"`) {
		t.Errorf("error must quote the offending type; got %q", msg)
	}
	// The whole point of rejecting rather than normalising is that the caller
	// learns the canonical spelling once instead of guessing forever.
	if !strings.Contains(msg, `"cwe"`) {
		t.Errorf("error must suggest the exact spelling %q; got %q", "cwe", msg)
	}
}

func TestAuditCreateRejectsUnknownType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"nosuchagent"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for unknown type, got %d", resp.StatusCode)
	}

	var body map[string]string
	readJSON(t, resp, &body)
	msg := body["error"]
	if !strings.Contains(msg, `"nosuchagent"`) {
		t.Errorf("error must quote the offending type; got %q", msg)
	}
	// An unknown name has no canonical spelling to suggest, so the caller needs
	// the valid set enumerated instead.
	for _, want := range []string{"cwe", "chaos", "soc2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must enumerate valid types (missing %q); got %q", want, msg)
		}
	}
}

// One request, one error: a caller who passed two bad types should not have to
// fix one, re-submit, and discover the next.
func TestAuditCreateReportsEveryInvalidType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"CWE", "cwe", "OWASP"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	readJSON(t, resp, &body)
	msg := body["error"]
	if !strings.Contains(msg, `"CWE"`) || !strings.Contains(msg, `"OWASP"`) {
		t.Errorf("error must name BOTH invalid types; got %q", msg)
	}
}

// Padding is not a spelling: ` cwe` addresses no agent and must not be
// silently trimmed into one.
func TestAuditCreateRejectsWhitespacePaddedType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{" cwe"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for whitespace-padded type, got %d", resp.StatusCode)
	}
}

// NON-VACUITY. Without this the three tests above would pass against a handler
// that rejected every audit.
func TestAuditCreateAcceptsExactTypes(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{"cwe", "owasp", "chaos"},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 for exact registry types, got %d", resp.StatusCode)
	}
}

// An empty list is not an invalid list: the stage router reads
// `len(RequestedTypes) == 0` as "no filter", i.e. the default agent set.
// Rejecting it here would break every caller that omits the field.
func TestAuditCreateAcceptsEmptyTypes(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
		"source_id": sourceID,
		"types":     []string{},
	})
	if err != nil {
		t.Fatalf("POST /api/audits: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 for empty types, got %d", resp.StatusCode)
	}
}

// Pipeline-stage agents (prove, discover) and Optional agents (do178c) are in
// the registry and therefore addressable, even though ScanAgentTypes() omits
// them from the DEFAULT scan set. Validating against the narrower helper would
// break `vulture prove` and `--types do178c`.
func TestAuditCreateAcceptsStageAndOptionalTypes(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	for _, typ := range []string{"prove", "discover", "do178c"} {
		resp, err := httpPost(addr, "/api/audits", map[string]interface{}{
			"source_id": sourceID,
			"types":     []string{typ},
		})
		if err != nil {
			t.Fatalf("POST /api/audits (%s): %v", typ, err)
		}
		if resp.StatusCode != 201 {
			t.Errorf("type %q: expected 201, got %d", typ, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func createSourceForTypeTest(t *testing.T, addr string) string {
	t.Helper()
	resp, err := httpPost(addr, "/api/sources", map[string]string{
		"type": "local",
		"path": createTestSourceDir(t),
	})
	if err != nil {
		t.Fatalf("POST /api/sources: %v", err)
	}
	var src map[string]interface{}
	readJSON(t, resp, &src)
	id, _ := src["id"].(string)
	if id == "" {
		t.Fatal("source create returned no id")
	}
	return id
}

// The cache probe is the FIRST thing the CLI does with a --types list, and it
// short-circuits the scan when it hits. Left unvalidated it re-serves the very
// audits this feature exists to prevent: a repeat of `--types CWE` matched the
// empty `{CWE}` row already in the database, printed "Cached results found /
// Findings: 0", and returned success without ever reaching POST /api/audits.
// An invalid type has to be invalid on every endpoint that accepts one.
func TestCachedAuditRejectsInvalidType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpGet(addr, "/api/audits/cache?source_id="+sourceID+"&types=CWE")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for miscased type on the cache probe, got %d", resp.StatusCode)
	}
	var body map[string]string
	readJSON(t, resp, &body)
	if !strings.Contains(body["error"], `"cwe"`) {
		t.Errorf("cache probe error must suggest the exact spelling; got %q", body["error"])
	}
}

// NON-VACUITY for the case above.
func TestCachedAuditAcceptsValidType(t *testing.T) {
	cfg := testConfig(t)
	addr, cleanup := startTestServer(t, cfg)
	defer cleanup()

	sourceID := createSourceForTypeTest(t, addr)

	resp, err := httpGet(addr, "/api/audits/cache?source_id="+sourceID+"&types=cwe,owasp")
	if err != nil {
		t.Fatalf("GET /api/audits/cache: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for exact types on the cache probe, got %d", resp.StatusCode)
	}
}
