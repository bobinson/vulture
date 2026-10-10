package textutil

import "regexp"

// MaskTokenShapes replaces credential values whose SHAPE identifies them —
// provider tokens, JWTs, URL userinfo, private-key bodies — with
// RedactionPlaceholder, keeping the rest of the text readable.
//
// The agent's mask_secret_values (shared/llm/errors.py) is the authoritative
// masker and covers more (Bearer/Basic values, credential-named hex, camel-case
// judgement), using lookaround that RE2 does not have. This is the defence in
// depth for text the backend receives from an agent that predates masking it
// (0074 verification item 1). Both runtimes are pinned to mask at least the
// shapes in testdata/token_shapes_0074.json. RE2 matching is linear, so a
// minified megabyte line cannot stall it.
func MaskTokenShapes(s string) string {
	s = pemRegion.ReplaceAllString(s, "${head}"+RedactionPlaceholder+"${tail}")
	return tokenShape.ReplaceAllString(s, RedactionPlaceholder)
}

var (
	// A private-key block: the body between the BEGIN and END lines (or the
	// end of the text) is masked; both header lines stay.
	pemRegion = regexp.MustCompile(`(?s)(?P<head>-----BEGIN[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----\r?\n?)` +
		`[A-Za-z0-9+/=\r\n \t]+?(?P<tail>\r?\n?-----END[ A-Z]{0,40}PRIVATE KEY(?: BLOCK)?-----|\z)`)
	tokenShape = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@:]*:[^\s/@]+@` + // URL userinfo
		`|\bAIza[0-9A-Za-z_\-]{10,}` + // Google API key
		`|\beyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z._\-]{8,}` + // JWT
		`|\bgh[pousr]_[0-9A-Za-z]{16,}` + // GitHub
		`|\bgithub_pat_[0-9A-Za-z_]{40,}` +
		`|\bxox[baprse]-[0-9A-Za-z\-]{10,}` + // Slack
		`|\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA)[0-9A-Z]{12,}` + // AWS key id
		`|\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}` + // Stripe
		`|\bnpm_[0-9A-Za-z]{36}\b` +
		`|\bglpat-[0-9A-Za-z_\-]{20,}` + // GitLab
		`|\bSG\.[\w\-]{16,}\.[\w\-]{16,}` + // SendGrid
		`|\bhf_[A-Za-z]{30,}`) // Hugging Face
)
