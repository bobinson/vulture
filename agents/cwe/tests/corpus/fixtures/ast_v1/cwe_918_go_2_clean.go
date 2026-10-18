// Pins: an early-return host guard on req.URL.Hostname() between http.NewRequest and http.DefaultClient.Do(req); the query read itself is a source, not a sink.
package app

func relay(r *http.Request) (*http.Response, error) {
	target := r.URL.Query().Get("u")
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	if !isTrustedHost(req.URL.Hostname()) {
		return nil, errBlockedHost
	}
	return http.DefaultClient.Do(req)
}
