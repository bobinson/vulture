package model

type AgentInfo struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Description  string      `json:"description,omitempty"`
	ConfigSchema interface{} `json:"config_schema,omitempty"`
	Skills       []string    `json:"skills,omitempty"`
}
