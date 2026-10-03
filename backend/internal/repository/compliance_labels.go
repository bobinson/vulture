package repository

import (
	"encoding/json"

	"github.com/vulture/backend/internal/model"
)

// Feature 0096 (migration 030): the column codec for `compliance_labels`,
// shared by both dialects so "no labels" has exactly one stored form (NULL)
// and one read form (nil, omitted on the wire). Postgres stores JSONB and
// SQLite TEXT; both bind and read the same JSON text.
//
// Every string is passed through dbSafeText first. A NUL survives json.Marshal
// as `\u0000`, which SQLite accepts and Postgres jsonb rejects — and a finding
// is written in a multi-row INSERT, so one such label would drop its whole
// chunk on Postgres alone.

// findingLabelsColumn returns the bind value for a finding's labels.
func findingLabelsColumn(labels []model.ComplianceLabel) interface{} {
	if len(labels) == 0 {
		return nil
	}
	out := make([]model.ComplianceLabel, len(labels))
	for i, l := range labels {
		out[i] = model.ComplianceLabel{
			Framework:    dbSafeText(l.Framework),
			Edition:      dbSafeText(l.Edition),
			CategoryID:   dbSafeText(l.CategoryID),
			CategoryName: dbSafeText(l.CategoryName),
			CWE:          dbSafeText(l.CWE),
		}
	}
	return marshalColumn(out)
}

// lineageLabelsColumn returns the bind value for a lineage row's per-edition
// labels. A nil category list is written as `[]`, never `null`: the upsert
// merges by key (Postgres `||`, SQLite json_patch), and json_patch reads a
// null member as "delete this key", which would turn "this edition maps the
// CWE to nothing" into "forget this edition".
func lineageLabelsColumn(labels map[string][]string) interface{} {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string][]string, len(labels))
	for key, cats := range labels {
		safe := make([]string, len(cats))
		for i, c := range cats {
			safe[i] = dbSafeText(c)
		}
		out[dbSafeText(key)] = safe
	}
	return marshalColumn(out)
}

func marshalColumn(v interface{}) interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

// decodeLabelsColumn fills dst from a column read through COALESCE to the
// empty string. An empty or unparseable value leaves dst nil, matching how the
// other JSON columns (refs, validation) degrade.
func decodeLabelsColumn(raw string, dst interface{}) {
	if raw == "" {
		return
	}
	_ = json.Unmarshal([]byte(raw), dst)
}
