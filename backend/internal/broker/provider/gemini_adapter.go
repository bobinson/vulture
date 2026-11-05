package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// geminiAdapter speaks Google's native Gemini generateContent wire (feature
// 0064 §30). It translates the normalized OpenAI-shaped CompletionRequest to
// Gemini's contents/systemInstruction/tools/generationConfig, and normalizes
// candidates + usageMetadata back — so the broker fronts Gemini natively
// (native tools + responseSchema JSON), not via an OpenAI-compat shim.
type geminiAdapter struct {
	name          string
	http          *http.Client
	defaultURL    string
	pinnedClients sync.Map
}

const geminiDefaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// NewGeminiAdapter builds the native Gemini adapter.
func NewGeminiAdapter(httpClient *http.Client) Adapter {
	return &geminiAdapter{name: "gemini", http: clientOrDefault(httpClient), defaultURL: geminiDefaultBaseURL}
}

func (a *geminiAdapter) Name() string { return a.name }

// --- wire shapes ---

type gemPart struct {
	Text             string               `json:"text,omitempty"`
	FunctionCall     *gemFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *gemFunctionResponse `json:"functionResponse,omitempty"`
}

// ID pairs a functionCall with its functionResponse. Gemini may supply it on a
// call; the broker echoes whatever id the agent holds on both parts.
type gemFunctionCall struct {
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}
type gemFunctionResponse struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}
type gemContent struct {
	Role  string    `json:"role,omitempty"`
	Parts []gemPart `json:"parts"`
}
type gemFuncDecl struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}
type gemTool struct {
	FunctionDeclarations []gemFuncDecl `json:"functionDeclarations"`
}
type gemGenConfig struct {
	MaxOutputTokens  int            `json:"maxOutputTokens,omitempty"`
	Temperature      *float64       `json:"temperature,omitempty"`
	ResponseMimeType string         `json:"responseMimeType,omitempty"`
	ResponseSchema   map[string]any `json:"responseSchema,omitempty"`
}
type gemRequest struct {
	Contents          []gemContent  `json:"contents"`
	SystemInstruction *gemContent   `json:"systemInstruction,omitempty"`
	Tools             []gemTool     `json:"tools,omitempty"`
	GenerationConfig  *gemGenConfig `json:"generationConfig,omitempty"`
}

type gemResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text         string `json:"text"`
				FunctionCall *struct {
					ID   string          `json:"id"`
					Name string          `json:"name"`
					Args json.RawMessage `json:"args"`
				} `json:"functionCall"`
			} `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata *struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

// geminiToolCallID returns Gemini's own id when it sent one, else a fresh
// random id. The agent SDK rejects an id that ANY earlier turn of the run
// completed, and each turn is a separate broker request (possibly on another
// broker process), so an index or counter is not unique enough.
func geminiToolCallID(supplied string) string {
	if supplied != "" {
		return supplied
	}
	return "call_" + rand.Text()
}

// Complete performs a synchronous generateContent call.
func (a *geminiAdapter) Complete(ctx context.Context, creds Credentials, req CompletionRequest) (*CompletionResponse, error) {
	endpoint, err := a.endpoint(creds, req.Model)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(buildGeminiRequest(req))
	if err != nil {
		return nil, fmt.Errorf("marshal gemini request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if creds.APIKey != "" {
		httpReq.Header.Set("x-goog-api-key", creds.APIKey)
	}
	resp, err := pinnedClient(a.http, &a.pinnedClients, creds.PinnedIP).Do(httpReq)
	if err != nil {
		return nil, transportError(ctx, err) // §32.1 #3
	}
	defer resp.Body.Close()
	if statusError(resp.StatusCode) != nil {
		// N6: the body is logged here and, for the allowlisted class only,
		// carried into the typed error (see upstream_detail.go).
		return nil, errorFromResponse(a.name, resp.StatusCode, body, resp.Body)
	}
	var wire gemResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode gemini response: %w", err)
	}
	return a.toResponse(&wire, req.Model, req.RequestID)
}

// endpoint builds {base}/models/{model}:generateContent.
func (a *geminiAdapter) endpoint(creds Credentials, model string) (string, error) {
	base := strings.TrimRight(creds.BaseURL, "/")
	if base == "" {
		base = strings.TrimRight(a.defaultURL, "/")
	}
	if base == "" {
		return "", fmt.Errorf("broker/provider: missing base URL for gemini")
	}
	m := strings.TrimPrefix(model, "models/")
	return base + "/models/" + m + ":generateContent", nil
}

// buildGeminiRequest translates the normalized request to Gemini wire.
func buildGeminiRequest(req CompletionRequest) gemRequest {
	b := gemContentsBuilder{toolNameByID: map[string]string{}}
	for _, m := range req.Messages {
		b.add(m)
	}
	out := gemRequest{Contents: b.contents}
	if len(b.sys) > 0 {
		out.SystemInstruction = &gemContent{Parts: []gemPart{{Text: strings.Join(b.sys, "\n")}}}
	}
	out.Tools = geminiTools(req.Tools)
	out.GenerationConfig = geminiGenConfig(req, len(out.Tools) > 0)
	return out
}

// gemContentsBuilder walks the messages in order into Gemini contents.
type gemContentsBuilder struct {
	contents []gemContent
	sys      []string
	// §32.1 #9: OpenAI tool-result messages carry tool_call_id, not the tool
	// name — but Gemini requires functionResponse.name to match the prior
	// functionCall.name. The map is filled as assistant turns are walked, so a
	// result resolves against the latest turn that issued its id, even where an
	// older history repeats an id across turns.
	toolNameByID map[string]string
}

func (b *gemContentsBuilder) add(m Message) {
	switch m.Role {
	case "system":
		b.addSystem(m)
	case "tool":
		b.addToolResult(m)
	case "assistant":
		b.addAssistant(m)
	default: // user (and any other) → user turn
		b.contents = append(b.contents, gemContent{Role: "user", Parts: []gemPart{{Text: m.Content}}})
	}
}

func (b *gemContentsBuilder) addSystem(m Message) {
	if m.Content != "" {
		b.sys = append(b.sys, m.Content)
	}
}

// addToolResult emits a functionResponse part (role "user" per Gemini). #9:
// resolve the name from the assistant turn's tool_calls (fall back to m.Name).
// #10: coalesce consecutive tool results into ONE user turn so parallel tool
// calls don't emit non-alternating same-role turns.
func (b *gemContentsBuilder) addToolResult(m Message) {
	name := b.toolNameByID[m.ToolCallID]
	if name == "" {
		name = m.Name
	}
	part := gemPart{FunctionResponse: &gemFunctionResponse{ID: m.ToolCallID, Name: name, Response: map[string]any{"content": m.Content}}}
	b.contents = appendToolResult(b.contents, part)
}

func (b *gemContentsBuilder) addAssistant(m Message) {
	parts := []gemPart{}
	if m.Content != "" {
		parts = append(parts, gemPart{Text: m.Content})
	}
	for _, tc := range m.ToolCalls {
		if tc.ID != "" { // a blank id is no key; its result keeps m.Name
			b.toolNameByID[tc.ID] = tc.Name
		}
		parts = append(parts, gemPart{FunctionCall: &gemFunctionCall{ID: tc.ID, Name: tc.Name, Args: json.RawMessage(orJSONNull(tc.Arguments))}})
	}
	b.contents = append(b.contents, gemContent{Role: "model", Parts: parts})
}

func geminiTools(tools []ToolDef) []gemTool {
	if len(tools) == 0 {
		return nil
	}
	decls := make([]gemFuncDecl, 0, len(tools))
	for _, t := range tools {
		decls = append(decls, gemFuncDecl{Name: t.Name, Parameters: sanitizeGeminiParams(t.Parameters)})
	}
	return []gemTool{{FunctionDeclarations: decls}}
}

// geminiGenConfig builds generationConfig. §32.1 #4: send temperature only when
// explicitly set (Gemini accepts the full range, so no model gating — just
// presence).
func geminiGenConfig(req CompletionRequest, hasTools bool) *gemGenConfig {
	gc := &gemGenConfig{MaxOutputTokens: req.MaxTokens}
	if req.HasTemperature {
		temp := req.Temperature
		gc.Temperature = &temp
	}
	// §32.1: application/json response mime is MUTUALLY EXCLUSIVE with function
	// calling on Gemini ("Function calling with a response mime type:
	// 'application/json' is unsupported"). Only request JSON when no tools are
	// attached — otherwise the tools' functionCall output carries structure.
	if wantsJSON(req.ResponseFormat) && !hasTools {
		gc.ResponseMimeType = "application/json"
	}
	return gc
}

func wantsJSON(format string) bool { return format != "" && format != "text" }

func orJSONNull(s string) string {
	if t := strings.TrimSpace(s); t == "" || t == "null" {
		return "{}" // §32.1 #11: empty/null args → a valid empty JSON object
	}
	return s
}

// appendToolResult appends a functionResponse part, COALESCING it into the
// previous content when that is already a tool-result user turn (§32.1 #10) so
// parallel tool results form ONE alternation-valid user turn.
func appendToolResult(contents []gemContent, part gemPart) []gemContent {
	if n := len(contents); n > 0 {
		prev := &contents[n-1]
		if prev.Role == "user" && len(prev.Parts) > 0 && prev.Parts[0].FunctionResponse != nil {
			prev.Parts = append(prev.Parts, part)
			return contents
		}
	}
	return append(contents, gemContent{Role: "user", Parts: []gemPart{part}})
}

// toResponse normalizes candidates + usageMetadata, enforcing the usage floor.
func (a *geminiAdapter) toResponse(wire *gemResponse, model, requestID string) (*CompletionResponse, error) {
	if wire.UsageMetadata == nil || wire.UsageMetadata.PromptTokenCount+wire.UsageMetadata.CandidatesTokenCount <= 0 {
		return nil, ErrUsageMissing
	}
	in, outTok := wire.UsageMetadata.PromptTokenCount, wire.UsageMetadata.CandidatesTokenCount
	out := &CompletionResponse{
		Model:     model,
		Provider:  a.name,
		RequestID: requestID,
		Usage:     Usage{InputTokens: in, OutputTokens: outTok, CostUSD: ActualUSD(model, in, outTok)},
	}
	if len(wire.Candidates) > 0 {
		out.FinishReason = mapGeminiFinish(wire.Candidates[0].FinishReason)
		fillGeminiCandidate(out, wire)
	}
	return out, nil
}

// fillGeminiCandidate copies the first candidate's text and tool calls.
func fillGeminiCandidate(out *CompletionResponse, wire *gemResponse) {
	var text strings.Builder
	for _, p := range wire.Candidates[0].Content.Parts {
		text.WriteString(p.Text)
		if p.FunctionCall != nil {
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				ID: geminiToolCallID(p.FunctionCall.ID), Type: "function",
				// §32.1 #11: normalize empty/null args to a valid JSON object so
				// the agent SDK's json.loads gets a dict, not "" / None.
				Name: p.FunctionCall.Name, Arguments: orJSONNull(string(p.FunctionCall.Args)),
			})
		}
	}
	out.Content = text.String()
	if len(out.ToolCalls) > 0 {
		out.FinishReason = "tool_calls" // OpenAI-wire convention so the agent runs tools
	}
}

func mapGeminiFinish(r string) string {
	switch strings.ToUpper(r) {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT":
		return "content_filter"
	case "":
		return ""
	default:
		return strings.ToLower(r)
	}
}

// Stream is deferred (F2); the DTO layer rejects stream:true before egress.
func (a *geminiAdapter) Stream(context.Context, Credentials, CompletionRequest) (<-chan StreamChunk, error) {
	return nil, ErrNotImplemented
}

// Embed via Gemini is a follow-up (audit embeddings use the backend client).
func (a *geminiAdapter) Embed(context.Context, Credentials, EmbeddingRequest) (*EmbeddingResponse, error) {
	return nil, ErrNotImplemented
}

var _ Adapter = (*geminiAdapter)(nil)
