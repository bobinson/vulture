package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captured Gemini generateContent request body (subset we assert on).
type geminiReqCapture struct {
	Contents []struct {
		Role  string `json:"role"`
		Parts []struct {
			Text         string          `json:"text"`
			FunctionCall json.RawMessage `json:"functionCall"`
		} `json:"parts"`
	} `json:"contents"`
	SystemInstruction *struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"systemInstruction"`
	Tools []struct {
		FunctionDeclarations []struct {
			Name string `json:"name"`
		} `json:"functionDeclarations"`
	} `json:"tools"`
	GenerationConfig struct {
		MaxOutputTokens  int     `json:"maxOutputTokens"`
		Temperature      float64 `json:"temperature"`
		ResponseMimeType string  `json:"responseMimeType"`
	} `json:"generationConfig"`
}

func geminiServer(t *testing.T, status int, respBody string, capture *geminiReqCapture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, ":generateContent") {
			t.Errorf("path = %q, want …:generateContent", r.URL.Path)
		}
		if capture != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, capture)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
}

func TestGemini_Complete_TranslatesAndParses(t *testing.T) {
	var cap geminiReqCapture
	srv := geminiServer(t, 200, `{
		"candidates":[{"content":{"role":"model","parts":[{"text":"hello back"}]},"finishReason":"STOP"}],
		"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":20}
	}`, &cap)
	defer srv.Close()

	a := NewGeminiAdapter(srv.Client())
	resp, err := a.Complete(context.Background(), Credentials{Provider: "gemini", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model:       "gemini-2.5-flash",
		Messages:    []Message{{Role: "system", Content: "be terse"}, {Role: "user", Content: "hi"}},
		MaxTokens:   256,
		Temperature: 0.0,
		RequestID:   "req-1",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// request translation
	if cap.SystemInstruction == nil || len(cap.SystemInstruction.Parts) == 0 || cap.SystemInstruction.Parts[0].Text != "be terse" {
		t.Errorf("systemInstruction not translated: %+v", cap.SystemInstruction)
	}
	if len(cap.Contents) != 1 || cap.Contents[0].Role != "user" || cap.Contents[0].Parts[0].Text != "hi" {
		t.Errorf("contents not translated: %+v", cap.Contents)
	}
	if cap.GenerationConfig.MaxOutputTokens != 256 {
		t.Errorf("maxOutputTokens = %d, want 256", cap.GenerationConfig.MaxOutputTokens)
	}
	// response + usage
	if resp.Content != "hello back" || resp.Provider != "gemini" {
		t.Errorf("resp content/provider = %q/%q", resp.Content, resp.Provider)
	}
	if resp.Usage.InputTokens != 100 || resp.Usage.OutputTokens != 20 {
		t.Errorf("usage = %d/%d, want 100/20", resp.Usage.InputTokens, resp.Usage.OutputTokens)
	}
	if resp.Usage.CostUSD <= 0 {
		t.Error("cost must be > 0 (ActualUSD)")
	}
}

func TestGemini_Complete_ToolsAndFunctionCall(t *testing.T) {
	var cap geminiReqCapture
	srv := geminiServer(t, 200, `{
		"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_file","args":{"path":"x.go"}}}]},"finishReason":"STOP"}],
		"usageMetadata":{"promptTokenCount":50,"candidatesTokenCount":10}
	}`, &cap)
	defer srv.Close()

	a := NewGeminiAdapter(srv.Client())
	resp, err := a.Complete(context.Background(), Credentials{Provider: "gemini", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model:    "gemini-2.5-flash",
		Messages: []Message{{Role: "user", Content: "read it"}},
		Tools:    []ToolDef{{Type: "function", Name: "read_file", Parameters: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(cap.Tools) == 0 || len(cap.Tools[0].FunctionDeclarations) == 0 || cap.Tools[0].FunctionDeclarations[0].Name != "read_file" {
		t.Errorf("tools→functionDeclarations not translated: %+v", cap.Tools)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "read_file" {
		t.Fatalf("functionCall not parsed to ToolCall: %+v", resp.ToolCalls)
	}
	if !strings.Contains(resp.ToolCalls[0].Arguments, "x.go") {
		t.Errorf("tool args = %q, want JSON containing x.go", resp.ToolCalls[0].Arguments)
	}
}

func TestGemini_Complete_JSONResponseFormat(t *testing.T) {
	var cap geminiReqCapture
	srv := geminiServer(t, 200, `{"candidates":[{"content":{"parts":[{"text":"{}"}]}}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2}}`, &cap)
	defer srv.Close()
	a := NewGeminiAdapter(srv.Client())
	_, err := a.Complete(context.Background(), Credentials{Provider: "gemini", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "gemini-2.5-flash", Messages: []Message{{Role: "user", Content: "j"}}, ResponseFormat: "json_object",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if cap.GenerationConfig.ResponseMimeType != "application/json" {
		t.Errorf("responseMimeType = %q, want application/json", cap.GenerationConfig.ResponseMimeType)
	}
}

func TestGemini_Complete_UsageMissing(t *testing.T) {
	srv := geminiServer(t, 200, `{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`, nil)
	defer srv.Close()
	a := NewGeminiAdapter(srv.Client())
	_, err := a.Complete(context.Background(), Credentials{Provider: "gemini", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "gemini-2.5-flash", Messages: []Message{{Role: "user", Content: "x"}},
	})
	if !errors.Is(err, ErrUsageMissing) {
		t.Fatalf("missing usageMetadata must be ErrUsageMissing, got %v", err)
	}
}

func TestGemini_Complete_RateLimited(t *testing.T) {
	srv := geminiServer(t, http.StatusTooManyRequests, `{"error":{"message":"quota"}}`, nil)
	defer srv.Close()
	a := NewGeminiAdapter(srv.Client())
	_, err := a.Complete(context.Background(), Credentials{Provider: "gemini", APIKey: "k", BaseURL: srv.URL}, CompletionRequest{
		Model: "gemini-2.5-flash", Messages: []Message{{Role: "user", Content: "x"}},
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("429 must map to ErrRateLimited, got %v", err)
	}
}

func TestSanitizeGeminiParams_StripsUnsupportedKeys(t *testing.T) {
	// §32.1: an OpenAI/pydantic tool schema — Gemini 400s on additionalProperties
	// et al. Sanitizer drops them recursively, keeps the real schema.
	in := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"title":                "ReadFileArgs",
		"$defs":                map[string]any{"X": map[string]any{}},
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "title": "Path", "default": "x"},
		},
		"required": []any{"path"},
	}
	out := sanitizeGeminiParams(in)
	for _, k := range []string{"additionalProperties", "title", "$defs"} {
		if _, bad := out[k]; bad {
			t.Errorf("top-level %q not stripped", k)
		}
	}
	if out["type"] != "object" {
		t.Error("type must be preserved")
	}
	props, _ := out["properties"].(map[string]any)
	pathSchema, _ := props["path"].(map[string]any)
	if pathSchema == nil || pathSchema["type"] != "string" {
		t.Fatalf("nested property schema mangled: %+v", props)
	}
	for _, k := range []string{"title", "default"} {
		if _, bad := pathSchema[k]; bad {
			t.Errorf("nested %q not stripped", k)
		}
	}
	if req, _ := out["required"].([]any); len(req) != 1 {
		t.Errorf("required must be preserved, got %v", out["required"])
	}
	if sanitizeGeminiParams(nil) != nil {
		t.Error("nil schema must stay nil")
	}
}

func TestGemini_Name(t *testing.T) {
	if NewGeminiAdapter(nil).Name() != "gemini" {
		t.Error("Name must be gemini")
	}
}
