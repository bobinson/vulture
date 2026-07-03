package validators

import "regexp"

// CWE-1333: overlapping wildcard alternation compiled at init — ReDoS.
var slugRe = regexp.MustCompile("(.*)*-slug")

func IsSlug(s string) bool {
	return slugRe.MatchString(s)
}
