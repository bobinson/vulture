// Pins: http.DefaultClient.Do(req) where req := http.NewRequest("GET", target, nil) and target := r.URL.Query().Get("u"); Do on a client carrier.
package app

func relay(r *http.Request) (*http.Response, error) {
	target := r.URL.Query().Get("u")
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
