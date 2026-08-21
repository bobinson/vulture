package gateway

func forward(w http.ResponseWriter, r *http.Request) {
	outbound, _ := http.NewRequest("GET", upstreamURL, nil)
	outbound.Header = r.Header
	resp, err := client.Do(outbound)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
