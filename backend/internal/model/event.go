package model

import "encoding/json"

type AgUIEventType string

const (
	EventRunStarted         AgUIEventType = "RunStarted"
	EventRunFinished        AgUIEventType = "RunFinished"
	EventRunError           AgUIEventType = "RunError"
	EventStepStarted        AgUIEventType = "StepStarted"
	EventStepFinished       AgUIEventType = "StepFinished"
	EventTextMessageStart   AgUIEventType = "TextMessageStart"
	EventTextMessageContent AgUIEventType = "TextMessageContent"
	EventTextMessageEnd     AgUIEventType = "TextMessageEnd"
	EventToolCallStart      AgUIEventType = "ToolCallStart"
	EventToolCallArgs       AgUIEventType = "ToolCallArgs"
	EventToolCallEnd        AgUIEventType = "ToolCallEnd"
	EventStateDelta         AgUIEventType = "StateDelta"
	EventStateSnapshot      AgUIEventType = "StateSnapshot"

	// Prove agent event types (agent SSE names, not AgUI types).
	EventProofPhase      = "proof_phase"
	EventProofPlan       = "proof_plan"
	EventProofReview     = "proof_review"
	EventProofAttempt    = "proof_attempt"
	EventProofReflection = "proof_reflection"
	EventProofResult     = "proof_result"
	EventProofSummary    = "proof_summary"
)

type AgUIEvent struct {
	Type      AgUIEventType   `json:"type"`
	RunID     string          `json:"runId,omitempty"`
	ThreadID  string          `json:"threadId,omitempty"`
	StepName  string          `json:"stepName,omitempty"`
	StepID    string          `json:"stepId,omitempty"`
	MessageID string          `json:"messageId,omitempty"`
	Delta     json.RawMessage `json:"delta,omitempty"`
	Snapshot  json.RawMessage `json:"snapshot,omitempty"`
	ToolName  string          `json:"toolName,omitempty"`
	ToolArgs  json.RawMessage `json:"toolArgs,omitempty"`
	ToolID    string          `json:"toolCallId,omitempty"`
	Error     string          `json:"error,omitempty"`
	AgentType string          `json:"agentType,omitempty"`
	// LLMWindow is the agent's published llm_window object (feature 0074
	// §5.1(e): resolved, effective, provenance, source, model), passed through
	// on the agent's StepStarted event. Absent when the agent sent none.
	LLMWindow json.RawMessage `json:"llmWindow,omitempty"`
}
