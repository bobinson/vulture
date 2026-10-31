package reveal

import "strings"

// hidesLength: kinds whose length would tell a reader without the source how
// long a password is. Fixed-format tokens keep theirs (it is public anyway).
var hidesLength = map[string]bool{
	"secret": true, "basic": true, "connection_secret": true, "url_userinfo": true,
}

// prefixKinds label a value by its leading characters; first match wins.
var prefixKinds = []struct{ prefix, kind string }{
	{"eyJ", "jwt"}, {"AIza", "google_api_key"}, {"github_pat_", "github_token"},
	{"ghp_", "github_token"}, {"gho_", "github_token"}, {"ghu_", "github_token"},
	{"ghs_", "github_token"}, {"ghr_", "github_token"}, {"xox", "slack_token"},
	{"AKIA", "aws_key_id"}, {"ASIA", "aws_key_id"}, {"sk_live_", "stripe_key"},
	{"sk_test_", "stripe_key"}, {"rk_live_", "stripe_key"}, {"rk_test_", "stripe_key"},
	{"npm_", "npm_token"}, {"glpat-", "gitlab_token"}, {"SG.", "sendgrid_key"},
	{"hf_", "huggingface_token"}, {"sk-", "openai_style_key"},
	{"-----BEGIN", "private_key"},
}

// classify labels a masked value. Only a label: never an authority.
func classify(value, before string) string {
	for _, p := range prefixKinds {
		if strings.HasPrefix(value, p.prefix) {
			return p.kind
		}
	}
	return contextKind(value, strings.ToLower(before))
}

// contextRules label a value by what surrounds it; first match wins.
var contextRules = []struct {
	kind  string
	match func(value, before string) bool
}{
	{"url_userinfo", func(v, _ string) bool { return strings.Contains(v, "://") && strings.HasSuffix(v, "@") }},
	{"bearer", func(_, b string) bool { return strings.HasSuffix(strings.TrimRight(b, " \t"), "bearer") }},
	{"basic", func(_, b string) bool { return strings.HasSuffix(strings.TrimRight(b, " \t"), "basic") }},
	{"connection_secret", func(_, b string) bool { return hasAnySuffix(b, connectionKeys) }},
	{"hex_credential", func(v, _ string) bool { return isHex(v) && len(v) >= 32 }},
	{"private_key", func(v, b string) bool { return isBase64Body(v) && strings.TrimSpace(b) == "" }},
}

var connectionKeys = []string{"password=", "accountkey=", "pwd=", "sharedaccesskey="}

func contextKind(value, before string) string {
	for _, r := range contextRules {
		if r.match(value, before) {
			return r.kind
		}
	}
	return "secret"
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	return strings.Trim(s, "0123456789abcdefABCDEF") == ""
}

func isBase64Body(s string) bool {
	return len(s) >= 16 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == ""
}
