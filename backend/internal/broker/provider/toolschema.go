package provider

import "strings"

// Tool-schema normalization (§32.1). Agent tool schemas are pydantic-generated
// (via the OpenAI Agents SDK) and carry JSON-Schema/OpenAI keys that some
// providers' function-declaration dialects REJECT. Gemini's dialect is the
// strictest (an OpenAPI-3.0 subset that 400s on any unknown key — confirmed live
// on `additionalProperties`), so it gets a WHITELIST projection here rather than
// a fragile per-key blacklist: any key Gemini does not support — present or
// future, from any agent — is dropped, `$ref` is resolved, unsupported `format`
// values are dropped, and Optional/Union `anyOf` is collapsed to `nullable`.

// geminiSchemaAllow is the set of schema keys Gemini's functionDeclarations
// OpenAPI-3.0 subset accepts. Everything else is projected out.
var geminiSchemaAllow = map[string]bool{
	"type": true, "format": true, "description": true, "nullable": true,
	"enum": true, "items": true, "properties": true, "required": true,
	"minItems": true, "maxItems": true, "minimum": true, "maximum": true,
	"pattern": true, "propertyOrdering": true, "anyOf": true,
}

// geminiFormatAllow is the set of `format` VALUES Gemini honors (§32.1 #14).
// A pydantic HttpUrl/EmailStr/UUID emits uri/email/uuid, which Gemini 400s on;
// those values are dropped (the field stays, just untyped-format).
var geminiFormatAllow = map[string]bool{
	"enum": true, "date-time": true,
	"float": true, "double": true,
	"int32": true, "int64": true, "uint32": true, "uint64": true,
}

const maxRefDepth = 32 // cycle guard for $ref resolution

// sanitizeGeminiParams projects a tool parameters schema onto Gemini's
// supported subset. Returns nil for a nil schema OR a no-argument tool (an
// empty-property object), so the adapter omits `parameters` entirely — Gemini
// 400s on {"type":"object","properties":{}} (§32.1 #13).
func sanitizeGeminiParams(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	defs := collectDefs(schema)
	projected := geminiProject(resolveRefs(schema, defs, 0))
	m, _ := projected.(map[string]any)
	if isEmptyObjectSchema(m) {
		return nil
	}
	return m
}

// collectDefs gathers the local $defs/definitions blocks for $ref resolution.
func collectDefs(schema map[string]any) map[string]any {
	defs := map[string]any{}
	for _, k := range []string{"$defs", "definitions"} {
		if d, ok := schema[k].(map[string]any); ok {
			for name, v := range d {
				defs[name] = v
			}
		}
	}
	return defs
}

// resolveRefs deep-copies v, inlining local "#/$defs/Name" (or definitions)
// references and dropping the $defs/definitions blocks. Cycles are bounded by
// maxRefDepth (a self-referential schema collapses to {} rather than looping).
func resolveRefs(v any, defs map[string]any, depth int) any {
	if depth > maxRefDepth {
		return map[string]any{}
	}
	switch t := v.(type) {
	case map[string]any:
		if ref, ok := t["$ref"].(string); ok {
			if target := lookupDef(ref, defs); target != nil {
				return resolveRefs(target, defs, depth+1)
			}
			return map[string]any{} // unresolvable ref → empty (projection drops it)
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			if k == "$defs" || k == "definitions" {
				continue
			}
			out[k] = resolveRefs(val, defs, depth)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = resolveRefs(t[i], defs, depth)
		}
		return out
	default:
		return v
	}
}

// lookupDef resolves the trailing name of a local $ref against defs.
func lookupDef(ref string, defs map[string]any) any {
	i := strings.LastIndex(ref, "/")
	if i < 0 {
		return defs[ref]
	}
	return defs[ref[i+1:]]
}

// geminiProject projects a resolved schema onto Gemini's supported subset. It
// is STRUCTURE-AWARE: `properties` is an object whose KEYS are arbitrary
// property names (kept) and whose VALUES are schemas (recursed); `items`/`anyOf`
// are nested schema(s) (recursed); `required`/`enum`/`propertyOrdering` are
// value arrays (copied verbatim). Every other allowed key is a scalar. Keys not
// in geminiSchemaAllow are dropped; unsupported `format` values are dropped.
func geminiProject(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		if list, isList := v.([]any); isList {
			out := make([]any, len(list))
			for i := range list {
				out[i] = geminiProject(list[i])
			}
			return out
		}
		return v
	}
	if collapsed := collapseNullableAnyOf(m); collapsed != nil {
		m = collapsed
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		if !geminiSchemaAllow[k] {
			continue
		}
		switch k {
		case "properties":
			if pm, ok := val.(map[string]any); ok {
				np := make(map[string]any, len(pm))
				for name, sub := range pm {
					np[name] = geminiProject(sub) // values are schemas; names are kept
				}
				out[k] = np
			}
		case "items", "anyOf":
			out[k] = geminiProject(val) // nested schema(s)
		case "format":
			if s, ok := val.(string); !ok || geminiFormatAllow[s] {
				out[k] = val // keep only supported format values (§32.1 #14)
			}
		default:
			out[k] = val // type/description/nullable/required/enum/min*/max*/pattern
		}
	}
	return out
}

// collapseNullableAnyOf turns pydantic's Optional/Union shape
// {"anyOf":[{...X...},{"type":"null"}]} into the sibling schema merged with X
// plus nullable:true (§32.1 #12). Returns nil when the node is not that shape.
func collapseNullableAnyOf(m map[string]any) map[string]any {
	raw, ok := m["anyOf"].([]any)
	if !ok {
		return nil
	}
	var nonNull map[string]any
	hasNull, nonNullCount := false, 0
	for _, b := range raw {
		bm, ok := b.(map[string]any)
		if !ok {
			return nil
		}
		if tp, _ := bm["type"].(string); tp == "null" {
			hasNull = true
			continue
		}
		nonNull = bm
		nonNullCount++
	}
	if !hasNull || nonNullCount != 1 || nonNull == nil {
		return nil // genuine multi-branch union — leave anyOf for Gemini to handle
	}
	merged := make(map[string]any, len(m)+len(nonNull))
	for k, v := range m {
		if k != "anyOf" {
			merged[k] = v
		}
	}
	for k, v := range nonNull {
		merged[k] = v
	}
	merged["nullable"] = true
	return merged
}

// isEmptyObjectSchema reports whether m is an object schema with no properties —
// a no-arg tool. Gemini rejects such a parameters block, so the adapter omits it.
func isEmptyObjectSchema(m map[string]any) bool {
	if m == nil {
		return true
	}
	if tp, _ := m["type"].(string); tp != "object" {
		return false
	}
	props, ok := m["properties"].(map[string]any)
	return !ok || len(props) == 0
}
