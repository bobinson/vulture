package provider

import "testing"

// §32.1 (Bug A robustness + #12/#13/#14): the Gemini tool-schema normalizer is a
// WHITELIST of Gemini's OpenAPI-3.0 subset — not a blacklist — so ANY key
// Gemini doesn't support (present or future, from any agent's pydantic schema)
// is dropped, refs are resolved, unsupported format values are dropped, and a
// no-arg tool yields nil (no empty-object 400).
func TestSanitizeGeminiParams_Whitelist(t *testing.T) {
	in := map[string]any{
		"type":                 "object",
		"additionalProperties": false,      // must drop
		"title":                "Args",     // must drop
		"$schema":              "http://x", // must drop
		"unknownFutureKey":     "x",        // must drop (whitelist!)
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "title": "P", "default": "x"},
			"url":  map[string]any{"type": "string", "format": "uri"},       // format:uri unsupported → drop format, keep string
			"when": map[string]any{"type": "string", "format": "date-time"}, // supported → keep
		},
		"required": []any{"path"},
	}
	out := sanitizeGeminiParams(in)
	for _, k := range []string{"additionalProperties", "title", "$schema", "unknownFutureKey"} {
		if _, bad := out[k]; bad {
			t.Errorf("whitelist did not drop %q", k)
		}
	}
	if out["type"] != "object" {
		t.Fatalf("type must survive: %+v", out)
	}
	props, _ := out["properties"].(map[string]any)
	url, _ := props["url"].(map[string]any)
	if url["type"] != "string" {
		t.Errorf("url type must survive: %+v", url)
	}
	if _, bad := url["format"]; bad {
		t.Errorf("unsupported format:uri must be dropped: %+v", url)
	}
	when, _ := props["when"].(map[string]any)
	if when["format"] != "date-time" {
		t.Errorf("supported format:date-time must survive: %+v", when)
	}
	if p, _ := props["path"].(map[string]any); p["title"] != nil || p["default"] != nil {
		t.Errorf("nested title/default must be dropped: %+v", p)
	}
}

// #12: $ref to a local $defs entry must be RESOLVED (inlined), not left as a
// typeless {} that Gemini rejects.
func TestSanitizeGeminiParams_ResolvesRef(t *testing.T) {
	in := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"cfg": map[string]any{"$ref": "#/$defs/Cfg"},
		},
		"$defs": map[string]any{
			"Cfg": map[string]any{
				"type":       "object",
				"properties": map[string]any{"n": map[string]any{"type": "integer"}},
			},
		},
	}
	out := sanitizeGeminiParams(in)
	if _, bad := out["$defs"]; bad {
		t.Error("$defs must be stripped from the emitted schema")
	}
	props, _ := out["properties"].(map[string]any)
	cfg, _ := props["cfg"].(map[string]any)
	if cfg["type"] != "object" {
		t.Fatalf("$ref not resolved (cfg should be the inlined object): %+v", cfg)
	}
	if _, ref := cfg["$ref"]; ref {
		t.Errorf("$ref key must be gone after resolution: %+v", cfg)
	}
	cp, _ := cfg["properties"].(map[string]any)
	if n, _ := cp["n"].(map[string]any); n["type"] != "integer" {
		t.Errorf("inlined nested property lost: %+v", cfg)
	}
}

// #12 (Optional/Union): pydantic emits anyOf:[{type:X},{type:null}] for
// Optional[X]; Gemini uses nullable, not a null branch. Collapse it.
func TestSanitizeGeminiParams_CollapsesNullableAnyOf(t *testing.T) {
	in := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{
				"anyOf": []any{
					map[string]any{"type": "integer"},
					map[string]any{"type": "null"},
				},
				"title": "Limit",
			},
		},
	}
	out := sanitizeGeminiParams(in)
	props, _ := out["properties"].(map[string]any)
	limit, _ := props["limit"].(map[string]any)
	if limit["type"] != "integer" {
		t.Errorf("Optional[int] must collapse to type:integer: %+v", limit)
	}
	if limit["nullable"] != true {
		t.Errorf("Optional must set nullable:true: %+v", limit)
	}
	if _, bad := limit["anyOf"]; bad {
		t.Errorf("anyOf must be gone after collapse: %+v", limit)
	}
}

// #13: a no-arg tool (empty object schema) must sanitize to nil so the adapter
// omits `parameters` entirely — Gemini 400s on {"type":"object","properties":{}}.
func TestSanitizeGeminiParams_NoArgToolYieldsNil(t *testing.T) {
	for _, in := range []map[string]any{
		{"type": "object", "properties": map[string]any{}, "additionalProperties": false, "title": "NoArgs"},
		{"type": "object", "title": "NoArgs"},
	} {
		if out := sanitizeGeminiParams(in); out != nil {
			t.Errorf("no-arg schema must yield nil, got %+v", out)
		}
	}
	if sanitizeGeminiParams(nil) != nil {
		t.Error("nil stays nil")
	}
}
