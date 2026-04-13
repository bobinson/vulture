package model

import "time"

// DiscoverResult stores the structured output of a discover audit.
type DiscoverResult struct {
	ID           string    `json:"id"`
	AuditID      string    `json:"audit_id"`
	TargetURL    string    `json:"target_url"`
	SiteMapJSON  string    `json:"site_map_json"`
	URLCount     int       `json:"url_count"`
	APICount     int       `json:"api_count"`
	FormCount    int       `json:"form_count"`
	Technologies []string  `json:"technologies"`
	CreatedAt    time.Time `json:"created_at"`
}
