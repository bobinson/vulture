func h(w http.ResponseWriter, r *http.Request) {
	// EXPECT-NEXT: clean  go raw string
	w.Write([]byte(`{"error":"disabled"}`))
}
