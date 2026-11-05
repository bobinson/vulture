func h(w http.ResponseWriter, r *http.Request) {
	if err := run(); err != nil {
		// EXPECT-NEXT: finding check=cwe.info_exposure.server_error_message  server error helper is CWE-550
		http.Error(w, err.Error(), 500)
	}
}
