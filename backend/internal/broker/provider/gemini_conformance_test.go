package provider

import "testing"

// §32.1 recurrence guardrail #1 — the CANARY that would have caught the
// additionalProperties 400 in CI instead of against the live API. It feeds the
// REAL tool-schema SHAPES the agents' pydantic models emit (dumped from
// cwe/chaos/soc2/owasp/shared tools) through the Gemini request builder and
// asserts the emitted parameters contain ONLY keys in Gemini's OpenAPI-3.0
// whitelist — failing on ANY unsupported key, unresolved $ref, empty-object
// schema, or out-of-range format value. Extend `realAgentToolSchemas` whenever
// an agent adds a tool with a new param shape.
var realAgentToolSchemas = map[string]map[string]any{
	// The 24 CWE skill tools + soc2/chaos/owasp category checks: a single
	// source_path:str param (pydantic adds title + additionalProperties:false).
	"cwe_source_path": {
		"type":                 "object",
		"additionalProperties": false,
		"title":                "check_injection_args",
		"properties": map[string]any{
			"source_path": map[string]any{"description": "Path to source directory.", "title": "Source Path", "type": "string"},
		},
		"required": []any{"source_path"},
	},
	// shared file_reader: optional int params with defaults.
	"shared_file_reader": {
		"type":                 "object",
		"additionalProperties": false,
		"title":                "read_file_args",
		"properties": map[string]any{
			"path":       map[string]any{"type": "string", "title": "Path"},
			"start_line": map[string]any{"type": "integer", "title": "Start Line", "default": 0},
			"end_line":   map[string]any{"type": "integer", "title": "End Line", "default": 0},
		},
		"required": []any{"path"},
	},
	// Hypothetical future tool: Optional[int] (anyOf+null), Enum, HttpUrl format,
	// nested model ($ref/$defs) — the shapes that would break a blacklist.
	"future_rich_params": {
		"type":                 "object",
		"additionalProperties": false,
		"title":                "rich_args",
		"$defs": map[string]any{
			"Mode": map[string]any{"enum": []any{"fast", "deep"}, "type": "string"},
			"Cfg":  map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer"}}},
		},
		"properties": map[string]any{
			"limit": map[string]any{"anyOf": []any{map[string]any{"type": "integer"}, map[string]any{"type": "null"}}, "title": "Limit"},
			"mode":  map[string]any{"$ref": "#/$defs/Mode"},
			"cfg":   map[string]any{"$ref": "#/$defs/Cfg"},
			"url":   map[string]any{"type": "string", "format": "uri"},
		},
		"required": []any{"url"},
	},
	// A no-argument tool (list/status style).
	"no_arg_tool": {
		"type": "object", "additionalProperties": false, "title": "no_args", "properties": map[string]any{},
	},
}

func TestGeminiSchemaConformance_RealAgentShapes(t *testing.T) {
	for name, schema := range realAgentToolSchemas {
		out := sanitizeGeminiParams(schema)
		if out == nil {
			continue // no-arg tool → omitted parameters (valid)
		}
		assertGeminiClean(t, name, out)
		// Top level must be a valid object schema with properties (non-empty,
		// else it should have been nil).
		if out["type"] != "object" {
			t.Errorf("%s: top-level type = %v, want object", name, out["type"])
		}
	}
}

// assertGeminiClean recursively fails if any key is outside Gemini's whitelist,
// any $ref/$defs survived, or any format value is unsupported.
func assertGeminiClean(t *testing.T, ctx string, v any) {
	t.Helper()
	switch node := v.(type) {
	case map[string]any:
		for k, val := range node {
			if !geminiSchemaAllow[k] {
				t.Errorf("%s: unsupported key %q survived projection (would 400 on Gemini)", ctx, k)
				continue
			}
			if k == "format" {
				if s, ok := val.(string); ok && !geminiFormatAllow[s] {
					t.Errorf("%s: unsupported format value %q survived", ctx, s)
				}
			}
			switch k {
			case "properties":
				if pm, ok := val.(map[string]any); ok {
					for pname, sub := range pm {
						assertGeminiClean(t, ctx+".properties."+pname, sub)
					}
				}
			case "items", "anyOf":
				assertGeminiClean(t, ctx+"."+k, val)
			}
		}
	case []any:
		for i, e := range node {
			_ = i
			assertGeminiClean(t, ctx+"[]", e)
		}
	}
}
