package model

type AgentInfo struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Status       string      `json:"status,omitempty"`
	Description  string      `json:"description,omitempty"`
	ConfigSchema interface{} `json:"config_schema,omitempty"`
	Skills       []string    `json:"skills,omitempty"`
	// Optional reports whether the agent is excluded from the default
	// scan set. Optional agents only run when the operator explicitly
	// requests them (CLI --types, frontend selector). The frontend
	// uses this to badge opt-in agents distinctly from defaults.
	Optional bool `json:"optional,omitempty"`
}
