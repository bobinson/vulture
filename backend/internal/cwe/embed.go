package cwe

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed data/category_to_cwe.json
var embeddedCategoryToCWE []byte

//go:embed data/check_id_prefix_to_cwe.json
var embeddedCheckIDPrefixToCWE []byte

// decodeStringMap decodes a JSON object whose values are strings.
// Shared by both the embedded-path load and the operator-override
// load so the two paths can't drift apart.
func decodeStringMap(data []byte) (map[string]string, error) {
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode string map: %w", err)
	}
	return out, nil
}

// loadEmbeddedSystemMaps returns the two embedded baseline maps. Any
// decode error means the build shipped corrupt JSON; panic so it's
// caught in CI rather than at runtime.
func loadEmbeddedSystemMaps() (categoryToCWE, checkIDPrefixToCWE map[string]string) {
	cat, err := decodeStringMap(embeddedCategoryToCWE)
	if err != nil {
		panic(fmt.Sprintf("cwe: embedded category_to_cwe.json invalid: %v", err))
	}
	pfx, err := decodeStringMap(embeddedCheckIDPrefixToCWE)
	if err != nil {
		panic(fmt.Sprintf("cwe: embedded check_id_prefix_to_cwe.json invalid: %v", err))
	}
	return cat, pfx
}
