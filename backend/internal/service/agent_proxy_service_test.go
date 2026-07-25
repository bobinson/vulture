package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func TestAgentProxyService_RunAgent_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/run" {
			t.Errorf("expected path /run, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprintf(w, "event: agent_start\n")
		fmt.Fprintf(w, "data: {}\n\n")
		fmt.Fprintf(w, "event: agent_end\n")
		fmt.Fprintf(w, "data: {}\n\n")
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	go func() {
		err := proxy.RunAgent(context.Background(), server.URL, "chaos", "run-1", "/src", json.RawMessage("{}"), eventCh)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		close(eventCh)
	}()

	var events []*model.AgUIEvent
	for evt := range eventCh {
		events = append(events, evt)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestAgentProxyService_RunAgentWithContext_PriorFindings(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	priorFindings := []model.PriorFinding{
		{Title: "XSS", Severity: "high"},
	}
	err := proxy.RunAgentWithContext(context.Background(), server.URL, "owasp", "run-2", "/src", json.RawMessage("{}"), priorFindings, eventCh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(receivedBody, "prior_findings") {
		t.Error("expected prior_findings in request body")
	}
	if !strings.Contains(receivedBody, "XSS") {
		t.Error("expected XSS in request body")
	}
}

func TestAgentProxyService_RunAgentWithContext_NoPriorFindings(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	err := proxy.RunAgentWithContext(context.Background(), server.URL, "owasp", "run-3", "/src", json.RawMessage("{}"), nil, eventCh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(receivedBody, "prior_findings") {
		t.Error("should not include prior_findings when nil")
	}
}

func TestAgentProxyService_RunAgent_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintf(w, "internal error")
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	err := proxy.RunAgentWithContext(context.Background(), server.URL, "chaos", "run-4", "/src", json.RawMessage("{}"), nil, eventCh)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected status 500 in error, got %v", err)
	}
}

func TestAgentProxyService_RunAgent_ConnectionError(t *testing.T) {
	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	err := proxy.RunAgentWithContext(context.Background(), "http://localhost:1", "chaos", "run-5", "/src", json.RawMessage("{}"), nil, eventCh)
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

func TestAgentProxyService_RunAgent_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until context is done
		<-r.Context().Done()
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := proxy.RunAgentWithContext(ctx, server.URL, "chaos", "run-6", "/src", json.RawMessage("{}"), nil, eventCh)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestAgentProxyService_SSEStream_SkipsUnknownEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// Unknown event should be skipped
		fmt.Fprintf(w, "event: unknown_event_type\n")
		fmt.Fprintf(w, "data: {\"foo\":\"bar\"}\n\n")
		// Known event
		fmt.Fprintf(w, "event: agent_start\n")
		fmt.Fprintf(w, "data: {}\n\n")
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	go func() {
		_ = proxy.RunAgent(context.Background(), server.URL, "chaos", "run-7", "/src", json.RawMessage("{}"), eventCh)
		close(eventCh)
	}()

	var events []*model.AgUIEvent
	for evt := range eventCh {
		events = append(events, evt)
	}
	// Only agent_start should produce events (unknown is skipped via Translate returning nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event (agent_start), got %d", len(events))
	}
}

func TestAgentProxyService_SSEStream_MalformedData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// Malformed data for thinking event
		fmt.Fprintf(w, "event: thinking\n")
		fmt.Fprintf(w, "data: not-json\n\n")
		// Valid event after
		fmt.Fprintf(w, "event: agent_end\n")
		fmt.Fprintf(w, "data: {}\n\n")
	}))
	defer server.Close()

	proxy := NewAgentProxyService()
	eventCh := make(chan *model.AgUIEvent, 100)

	go func() {
		_ = proxy.RunAgent(context.Background(), server.URL, "chaos", "run-8", "/src", json.RawMessage("{}"), eventCh)
		close(eventCh)
	}()

	var events []*model.AgUIEvent
	for evt := range eventCh {
		events = append(events, evt)
	}
	// Malformed data should be skipped, only agent_end processed
	if len(events) != 1 {
		t.Fatalf("expected 1 event (agent_end), got %d", len(events))
	}
}

func TestNewAgentProxyService(t *testing.T) {
	proxy := NewAgentProxyService()
	if proxy == nil {
		t.Fatal("expected non-nil proxy")
	}
}
