package agui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/textutil"
	"github.com/vulture/backend/pkg/agentregistry"
)

type AgentEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type translatorFunc func(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error)

var translators = map[string]translatorFunc{
	"agent_start":   func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateAgentStart(at, d) },
	"thinking":      func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateThinking(d) },
	"tool_call":     func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateToolCall(d) },
	"tool_result":   func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateToolResult(d) },
	"finding":       func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateFinding(at, d) },
	"progress":      func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateProgress(d) },
	"result":        func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateResult(at, d) },
	"token_savings": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateTokenSavings(d) },
	"dedup_stats":   func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateDedupStats(d) },
	"agent_end":     func(at string, _ json.RawMessage) ([]*model.AgUIEvent, error) { return translateAgentEnd(at) },
	"proof_phase": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_phase", d)
	},
	"proof_plan": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_plan", d)
	},
	"proof_review": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_review", d)
	},
	"proof_attempt": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_attempt", d)
	},
	"proof_reflection": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_reflection", d)
	},
	"proof_result": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_result", d)
	},
	"proof_summary": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateProofEvent("proof_summary", d)
	},
	"discover_result": func(_ string, d json.RawMessage) ([]*model.AgUIEvent, error) { return translateDiscoverResult(d) },
	// feature 0046: L5 verdict streaming. One agent-side event becomes
	// N StateDelta replace ops keyed on finding id, so the frontend
	// updates the existing rows' validation_status in place.
	"validation_update": func(at string, d json.RawMessage) ([]*model.AgUIEvent, error) {
		return translateValidationUpdate(at, d)
	},
}

func Translate(agentType string, event string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	fn, ok := translators[event]
	if !ok {
		return nil, nil
	}
	return fn(agentType, data)
}

// agentDisplayName returns the registry display name for an agent type,
// falling back to uppercase for short acronym-like types (e.g. "ssdf" → "SSDF").
func AgentDisplayName(agentType string) string {
	for _, a := range agentregistry.AllAgents {
		if a.Type == agentType {
			return a.Name
		}
	}
	if len(agentType) <= 6 {
		return strings.ToUpper(agentType)
	}
	return strings.ToUpper(agentType[:1]) + agentType[1:]
}

func translateAgentStart(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStepStarted, StepName: AgentDisplayName(agentType), StepID: "step-" + agentType,
			LLMWindow: allowListedLLMWindow(data)},
	}, nil
}

// allowListedLLMWindow returns the agent_start payload's llm_window (0074
// §5.1(e), AC7) — the ONE allow-listed key of that payload; every other key
// stays behind. The object reaches every SSE client, so only its five
// documented fields pass, each validated and re-marshalled (review #36):
// unknown keys and oversized values never pass through. The wire shape is
// kept (re-audit R9): a null value stays null, an absent key stays absent, and
// {} stays {}. A malformed payload, a non-object, or any mistyped or
// implausible field yields nil, never an error: a garbled start frame must not
// drop the agent's step.
func allowListedLLMWindow(data json.RawMessage) json.RawMessage {
	in, ok := llmWindowObject(data)
	if !ok {
		return nil
	}
	out, ok := cleanLLMWindow(in)
	if !ok {
		return nil
	}
	b, _ := json.Marshal(out)
	return b
}

// llmWindowObject decodes the payload's llm_window when it is a JSON object.
func llmWindowObject(data json.RawMessage) (map[string]json.RawMessage, bool) {
	var d struct {
		LLMWindow json.RawMessage `json:"llm_window"`
	}
	if json.Unmarshal(data, &d) != nil || !bytes.HasPrefix(d.LLMWindow, []byte("{")) {
		return nil, false
	}
	var in map[string]json.RawMessage
	return in, json.Unmarshal(d.LLMWindow, &in) == nil
}

// llmWindowVocabMax bounds provenance/source (short vocabulary words);
// llmWindowModelMax bounds a model id. llmWindowMaxTokens bounds a window: no
// model comes within an order of magnitude of it, so anything above is a
// garbled value, not a window.
const (
	llmWindowVocabMax  = 32
	llmWindowModelMax  = 256
	llmWindowMaxTokens = 100_000_000
)

// llmWindowFields are the five published fields, each with its validator.
var llmWindowFields = map[string]func(json.RawMessage) (json.RawMessage, bool){
	"resolved":   windowTokens,
	"effective":  windowTokens,
	"provenance": cappedString(llmWindowVocabMax),
	"source":     cappedString(llmWindowVocabMax),
	"model":      cappedString(llmWindowModelMax),
}

// cleanLLMWindow keeps each present documented field once it validates; one
// invalid field rejects the object.
func cleanLLMWindow(in map[string]json.RawMessage) (map[string]json.RawMessage, bool) {
	out := make(map[string]json.RawMessage, len(llmWindowFields))
	for key, clean := range llmWindowFields {
		raw, present := in[key]
		if !present {
			continue
		}
		v, ok := clean(raw)
		if !ok {
			return nil, false
		}
		out[key] = v
	}
	return out, true
}

var jsonNull = json.RawMessage("null")

// windowTokens accepts null or an integer token count in [0, llmWindowMaxTokens].
func windowTokens(raw json.RawMessage) (json.RawMessage, bool) {
	if bytes.Equal(raw, jsonNull) {
		return jsonNull, true
	}
	var n int64
	if json.Unmarshal(raw, &n) != nil {
		return nil, false
	}
	out, _ := json.Marshal(n)
	return out, n >= 0 && n <= llmWindowMaxTokens
}

// cappedString accepts null or a string, cut on a rune boundary at maxBytes.
func cappedString(maxBytes int) func(json.RawMessage) (json.RawMessage, bool) {
	return func(raw json.RawMessage) (json.RawMessage, bool) {
		if bytes.Equal(raw, jsonNull) {
			return jsonNull, true
		}
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return nil, false
		}
		out, _ := json.Marshal(textutil.CutAtRune(v, maxBytes))
		return out, true
	}
}

func translateThinking(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal thinking: %w", err)
	}
	delta, _ := json.Marshal(d.Content)
	return []*model.AgUIEvent{
		{Type: model.EventTextMessageContent, MessageID: "msg-thinking", Delta: delta},
	}, nil
}

func translateToolCall(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Tool string          `json:"tool"`
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal tool_call: %w", err)
	}
	return []*model.AgUIEvent{
		{Type: model.EventToolCallStart, ToolName: d.Tool, ToolID: "tc-" + d.Tool},
		{Type: model.EventToolCallArgs, ToolID: "tc-" + d.Tool, ToolArgs: d.Args},
	}, nil
}

func translateToolResult(data json.RawMessage) ([]*model.AgUIEvent, error) {
	var d struct {
		Tool string `json:"tool"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("unmarshal tool_result: %w", err)
	}
	return []*model.AgUIEvent{
		{Type: model.EventToolCallEnd, ToolID: "tc-" + d.Tool},
	}, nil
}

func translateFinding(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	patch, _ := json.Marshal([]map[string]interface{}{
		{"op": "add", "path": "/findings/-", "value": json.RawMessage(data)},
	})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: patch, AgentType: agentType},
	}, nil
}

func translateProgress(data json.RawMessage) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: data},
	}, nil
}

func translateResult(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	log.Printf("[translate] result agent=%s dataLen=%d data=%.200s", agentType, len(data), string(data))
	events := make([]*model.AgUIEvent, 0, 2)
	// A result payload carrying a non-empty `error` (e.g. a plugin whose scan
	// process failed — bad flag, timeout, unparseable output) must SURFACE as
	// an audit error, not be silently dropped as a clean 0-findings snapshot.
	// parseSnapshot only reads {findings, score}, so without this an errored
	// scan is indistinguishable from a genuinely clean one (0058 review, HIGH;
	// this is exactly the --project-root failure mode). Emit an "ERROR: …"
	// text event first so collectErrorText marks DrainResult.AgentError.
	if msg := resultErrorText(data); msg != "" {
		delta, _ := json.Marshal("ERROR: " + msg)
		events = append(events, &model.AgUIEvent{
			Type: model.EventTextMessageContent, Delta: delta, AgentType: agentType,
		})
	}
	events = append(events, &model.AgUIEvent{
		Type: model.EventStateSnapshot, Snapshot: data, AgentType: agentType,
	})
	return events, nil
}

// resultErrorText returns the trimmed `error` field of a result payload, or
// "" when absent/unparseable.
func resultErrorText(data json.RawMessage) string {
	var r struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return ""
	}
	return strings.TrimSpace(r.Error)
}

func translateTokenSavings(data json.RawMessage) ([]*model.AgUIEvent, error) {
	// Wrap token savings data so the frontend can distinguish it from other state deltas
	wrapped, _ := json.Marshal(map[string]json.RawMessage{"token_savings": data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateDedupStats(data json.RawMessage) ([]*model.AgUIEvent, error) {
	wrapped, _ := json.Marshal(map[string]json.RawMessage{"dedup_stats": data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateProofEvent(eventName string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	wrapped, _ := json.Marshal(map[string]json.RawMessage{eventName: data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateDiscoverResult(data json.RawMessage) ([]*model.AgUIEvent, error) {
	wrapped, _ := json.Marshal(map[string]json.RawMessage{"discover_result": data})
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: wrapped},
	}, nil
}

func translateAgentEnd(agentType string) ([]*model.AgUIEvent, error) {
	return []*model.AgUIEvent{
		{Type: model.EventStepFinished, StepName: AgentDisplayName(agentType), StepID: "step-" + agentType},
	}, nil
}

// translateValidationUpdate converts a Python-side `validation_update`
// event into per-finding StateDelta `replace` ops. The aggregator's
// `extractDeltaFindings` keys on finding id, so these patches update
// existing rows in place rather than appending duplicates.
//
// Feature 0046 D19: one event per L5 batch, multiple findings per
// event. Each finding's `validation_status` / `validation_confidence`
// / `validation` blob get individual replace ops.
func translateValidationUpdate(agentType string, data json.RawMessage) ([]*model.AgUIEvent, error) {
	var payload struct {
		Phase   string `json:"phase"`
		Updates []struct {
			ID                   string          `json:"id"`
			ValidationStatus     string          `json:"validation_status"`
			ValidationConfidence float64         `json:"validation_confidence"`
			Validation           json.RawMessage `json:"validation"`
		} `json:"updates"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("validation_update: %w", err)
	}
	if len(payload.Updates) == 0 {
		return nil, nil
	}
	patches := make([]map[string]interface{}, 0, len(payload.Updates)*3)
	for _, u := range payload.Updates {
		if u.ID == "" {
			continue
		}
		base := "/findings/" + u.ID
		patches = append(patches,
			map[string]interface{}{"op": "replace", "path": base + "/validation_status", "value": u.ValidationStatus},
			map[string]interface{}{"op": "replace", "path": base + "/validation_confidence", "value": u.ValidationConfidence},
		)
		if len(u.Validation) > 0 && string(u.Validation) != "null" {
			patches = append(patches, map[string]interface{}{
				"op": "replace", "path": base + "/validation", "value": json.RawMessage(u.Validation),
			})
		}
	}
	delta, err := json.Marshal(patches)
	if err != nil {
		return nil, fmt.Errorf("marshal validation_update delta: %w", err)
	}
	return []*model.AgUIEvent{
		{Type: model.EventStateDelta, Delta: delta, AgentType: agentType},
	}, nil
}
