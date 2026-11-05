// Pins: http.Get(target) where target := r.FormValue("u") from an *http.Request param; get is a sink with no browser gate outside JS/TS.
package app

func pullPage(r *http.Request) (*http.Response, error) {
	target := r.FormValue("u")
	return http.Get(target)
}
