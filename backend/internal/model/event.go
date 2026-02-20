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
}
