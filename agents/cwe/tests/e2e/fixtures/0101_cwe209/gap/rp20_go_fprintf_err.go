func h(w http.ResponseWriter, r *http.Request) {
	if err := run(); err != nil {
		// EXPECT-NEXT: clean  known-gap go Fprintf err
		fmt.Fprintf(w, "failed: %v", err)
	}
}
