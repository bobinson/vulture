package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// anthropic_live: an env-gated LIVE check against Anthropic's real Messages
// API, through the adapter's own Complete — the call the broker makes for a
// `vulture.sh dev anthropic` run. It replays what the L5 judge sends: a system
// prompt, its three read-only tools, tool_choice auto, temperature 0.1 and
// max_tokens 16000; then a tool loop whose history carries NO thinking blocks
// (the broker never hands them to the agent, so the agent never sends them
// back), with two parallel tool calls answered by separate tool messages, the
// OpenAI wire shape the agent SDK replays.
//
// Skips unless ANTHROPIC_LIVE_KEY is set (CI never calls a live model).
// ANTHROPIC_LIVE_MODELS overrides the models (comma list). Run:
//
//	ANTHROPIC_LIVE_KEY=$ANTHROPIC_API_KEY go test ./internal/broker/provider/ -run TestAnthropicLive -count=1 -v

const anthropicLiveDefaultModels = "claude-sonnet-5-5,claude-haiku-5-5,claude-opus-5-5"

func anthropicLiveSetup(t *testing.T) (string, []string) {
	t.Helper()
	key := os.Getenv("ANTHROPIC_LIVE_KEY")
	if key == "" {
		t.Skip("set ANTHROPIC_LIVE_KEY to run the live Anthropic check")
	}
	models := os.Getenv("ANTHROPIC_LIVE_MODELS")
	if models == "" {
		models = anthropicLiveDefaultModels
	}
	return key, strings.Split(models, ",")
}

// judgeTools are the L5 judge's tools, as the agent declares them.
func judgeTools() []ToolDef {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return []ToolDef{
		{Type: "function", Name: "read_file", Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":       str("File path, relative to the audited tree"),
				"start_line": map[string]any{"type": "integer", "description": "First line (1-based); 0 = start"},
				"end_line":   map[string]any{"type": "integer", "description": "Last line (1-based); 0 = start_line + 119"},
			},
			"required": []any{"path"},
		}},
		{Type: "function", Name: "search_pattern", Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern": str("Regular expression"),
				"subdir":  str("Optional subdirectory to search under"),
			},
			"required": []any{"pattern"},
		}},
		{Type: "function", Name: "parse_ast", Parameters: map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": str("File path, relative to the audited tree")},
			"required":   []any{"path"},
		}},
	}
}

const judgeSystem = `You review automated static-analysis findings in the user's own repository.
For each finding, estimate the probability (0.0 to 1.0) that it is a real defect
as written. You may call read_file, search_pattern and parse_ast to see more code.
Your FINAL message must be strict JSON only:
{"verdicts":[{"id":"<finding_id>","exploitable":<float>,"window_sufficient":<bool>,"evidence_line":<int or null>,"reasoning":"<up to 60 words>"}]}`

const judgeFinding = `Findings to review (1 in this batch):
[1] id=f1  rule=cwe.error_handling.unchecked_return  severity=low
    file=internal/repository/repo.go  lines=175-175  language=go
    description: Error explicitly discarded by assignment to the blank identifier at line 175
    code:
L173: 	audit.Config = json.RawMessage(cfgStr)
L174: 	audit.Scores = map[string]int{}
L175: 	_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)
L176: 	if owaspCovStr != "" {`

func judgeRequest(model string, msgs []Message) CompletionRequest {
	return CompletionRequest{
		Model:          model,
		Messages:       msgs,
		Tools:          judgeTools(),
		ToolChoice:     "auto",
		MaxTokens:      16000,
		Temperature:    0.1,
		HasTemperature: true,
		RequestID:      "live-" + model,
	}
}

func liveComplete(t *testing.T, key string, req CompletionRequest) *CompletionResponse {
	t.Helper()
	a := NewAnthropicAdapter(&http.Client{Timeout: 180 * time.Second})
	creds := Credentials{Provider: "anthropic", APIKey: key, BaseURL: CanonicalBaseURL("anthropic")}
	resp, err := a.Complete(context.Background(), creds, req)
	if err != nil {
		t.Fatalf("%s: Anthropic rejected the request: %v", req.Model, err)
	}
	if resp.FinishReason == "refusal" {
		t.Fatalf("%s: Claude declined (stop_reason refusal); the judge would get an empty verdict", req.Model)
	}
	if resp.Usage.InputTokens <= 0 || resp.Usage.OutputTokens <= 0 {
		t.Fatalf("%s: no usage reported: %+v", req.Model, resp.Usage)
	}
	if resp.Content == "" && len(resp.ToolCalls) == 0 {
		t.Fatalf("%s: empty answer (finish=%s)", req.Model, resp.FinishReason)
	}
	t.Logf("%s: finish=%s tool_calls=%d in=%d out=%d cost=$%.4f", req.Model, resp.FinishReason,
		len(resp.ToolCalls), resp.Usage.InputTokens, resp.Usage.OutputTokens, resp.Usage.CostUSD)
	return resp
}

func TestAnthropicLive_JudgeRequestAccepted(t *testing.T) {
	key, models := anthropicLiveSetup(t)
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			liveComplete(t, key, judgeRequest(model, []Message{
				{Role: "system", Content: judgeSystem},
				{Role: "user", Content: judgeFinding},
			}))
		})
	}
}

// The tool loop as the agent replays it: the assistant turn carries only the
// tool calls (no thinking blocks), and each result is its own tool message.
// Uses the model's own turn-1 calls when it makes them, so the replayed calls
// are ones Claude produced alongside thinking it never gets back.
func TestAnthropicLive_ToolLoopWithoutThinkingBlocksAccepted(t *testing.T) {
	key, models := anthropicLiveSetup(t)
	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			history := []Message{
				{Role: "system", Content: judgeSystem},
				{Role: "user", Content: judgeFinding + "\n\nRead lines 160-190 of the file with read_file and search for scoresStr with search_pattern before answering."},
			}
			first := liveComplete(t, key, judgeRequest(model, history))
			calls := first.ToolCalls
			if len(calls) == 0 {
				t.Logf("%s made no tool call in turn 1; replaying two synthetic parallel calls instead", model)
				calls = []ToolCall{
					{ID: "call_live_1", Type: "function", Name: "read_file", Arguments: `{"path":"internal/repository/repo.go","start_line":160,"end_line":190}`},
					{ID: "call_live_2", Type: "function", Name: "search_pattern", Arguments: `{"pattern":"scoresStr"}`},
				}
			}
			history = append(history, Message{Role: "assistant", ToolCalls: calls})
			for _, c := range calls {
				history = append(history, Message{Role: "tool", ToolCallID: c.ID, Content: toolResultFor(c.Name)})
			}
			second := liveComplete(t, key, judgeRequest(model, history))
			if len(second.ToolCalls) == 0 && !json.Valid([]byte(strings.TrimSpace(stripFence(second.Content)))) {
				t.Logf("%s: turn-2 answer is not bare JSON (judge would retry): %.200q", model, second.Content)
			}
		})
	}
}

func toolResultFor(name string) string {
	if name == "read_file" {
		return "173: \taudit.Config = json.RawMessage(cfgStr)\n174: \taudit.Scores = map[string]int{}\n175: \t_ = json.Unmarshal([]byte(scoresStr), &audit.Scores)\n"
	}
	return fmt.Sprintf("%s: internal/repository/repo.go:164: var cfgStr, scoresStr, owaspCovStr string", name)
}

func stripFence(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	return strings.TrimSuffix(s, "```")
}
