func recoverMW(w http.ResponseWriter) {
	if r := recover(); r != nil {
		w.WriteHeader(500)
		// EXPECT-NEXT: clean  known-gap go debug stack
		w.Write(debug.Stack())
	}
}
