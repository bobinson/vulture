package x
func h(w http.ResponseWriter) {
	if err := svc.Load(); err != nil {
		// EXPECT-NEXT: finding  Go Sprintf
		w.Write([]byte(fmt.Sprintf("failed: %v", err)))
	}
}
