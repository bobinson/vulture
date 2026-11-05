package agui

import (
	"bytes"
	"encoding/json"
	"log"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/textutil"
)

// maskUnmarkedMergedLLM masks the token shapes in the merged_llm descriptions
// of a result snapshot that does not declare `merged_llm_masked: true`, i.e.
// one from an agent that predates masking them (0074 verification item 1).
// The snapshot is forwarded to live SSE clients and the broadcast replay and
// then parsed for persistence, so this is the one point both read. A masking
// agent's snapshot, or one without merged_llm, is returned byte for byte.
func maskUnmarkedMergedLLM(agentType string, data json.RawMessage) json.RawMessage {
	env, ok := unmarkedEnvelope(data)
	if !ok {
		return data
	}
	var findings []map[string]json.RawMessage
	if json.Unmarshal(env["findings"], &findings) != nil || !maskFindingsMergedLLM(findings) {
		return data
	}
	env["findings"], _ = json.Marshal(findings)
	out, err := json.Marshal(env)
	if err != nil {
		return data
	}
	log.Printf("[translate] merged_llm descriptions masked agent=%s: the agent does not declare merged_llm_masked", agentType)
	return out
}

// unmarkedEnvelope decodes a snapshot that carries merged_llm without the
// agent's masking declaration; ok is false for any other snapshot.
func unmarkedEnvelope(data json.RawMessage) (map[string]json.RawMessage, bool) {
	if !bytes.Contains(data, []byte(`"merged_llm"`)) {
		return nil, false
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(data, &env) != nil || isTrue(env["merged_llm_masked"]) {
		return nil, false
	}
	return env, true
}

// maskFindingsMergedLLM masks each finding's merged_llm descriptions in place;
// it reports whether any text changed. An unreadable merged_llm is dropped.
func maskFindingsMergedLLM(findings []map[string]json.RawMessage) bool {
	changed := false
	for _, f := range findings {
		raw, ok := f["merged_llm"]
		if !ok {
			continue
		}
		var rows []model.MergedLLMRow
		if json.Unmarshal(raw, &rows) != nil {
			delete(f, "merged_llm")
			changed = true
			continue
		}
		if maskRows(rows) {
			f["merged_llm"], _ = json.Marshal(rows)
			changed = true
		}
	}
	return changed
}

func maskRows(rows []model.MergedLLMRow) bool {
	changed := false
	for i := range rows {
		if masked := textutil.MaskTokenShapes(textutil.RedactSecretText(rows[i].Description)); masked != rows[i].Description {
			rows[i].Description = masked
			changed = true
		}
	}
	return changed
}

func isTrue(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("true"))
}
