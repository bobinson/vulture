package validators

import "regexp"

// Safe: a single, non-nested wildcard with an anchored bounded suffix.
var slugRe = regexp.MustCompile("^[a-z0-9-]{1,40}-slug$")

func IsSlug(s string) bool {
	return slugRe.MatchString(s)
}
