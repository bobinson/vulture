package handler

// 0074 verification item 1: an agent that predates masking its merged_llm
// descriptions (or a cross-agent loser's description) must not get a raw token
// persisted in validation.merged_descriptions. Go masks the distinctive token
// shapes (textutil.MaskTokenShapes) on every merge description. Synthetic values.

import (
	"strings"
	"testing"

	"github.com/vulture/backend/internal/model"
)

const maskingJWT0074 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

func TestMergedDescriptions_MaskTokenShapes_0074(t *testing.T) {
	for _, category := range []string{"CWE-89", "CWE-798"} {
		t.Run(category, func(t *testing.T) {
			skill := withMergedLLM(deterministicRow("mm-skill", model.SeverityHigh),
				model.MergedLLMRow{Provenance: "llm", Description: "token " + maskingJWT0074 +
					" and postgres://admin:S3cr3tPassw0rdX9@db.internal/app"})
			skill.Category = category
			got := mergeOne(t, skill)
			s := mustJSON(t, got.Validation["merged_descriptions"])
			for _, raw := range []string{maskingJWT0074, "S3cr3tPassw0rdX9"} {
				if strings.Contains(s, raw) {
					t.Errorf("raw %q persisted in merged_descriptions: %s", raw, s)
				}
			}
			// A secret-bearing category's line redactor already masks the whole
			// URL; elsewhere only the credential goes.
			if category == "CWE-89" && !strings.Contains(s, "db.internal/app") {
				t.Errorf("the readable part of the description was lost: %s", s)
			}
		})
	}
}
