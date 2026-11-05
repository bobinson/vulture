// Pins: an early-return host guard `if !isTrustedHost(target) { return }` on the same name before http.Get(target).
package app

func pullPage(r *http.Request) (*http.Response, error) {
	target := r.FormValue("u")
	if !isTrustedHost(target) {
		return nil, errBlockedHost
	}
	return http.Get(target)
}
