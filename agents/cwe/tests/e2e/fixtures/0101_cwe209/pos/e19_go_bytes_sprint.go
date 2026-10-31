func h(w http.ResponseWriter, r *http.Request) {
	if err := run(); err != nil {
		// EXPECT-NEXT: finding  go bytes sprint
		w.Write([]byte(fmt.Sprint(err)))
	}
}
