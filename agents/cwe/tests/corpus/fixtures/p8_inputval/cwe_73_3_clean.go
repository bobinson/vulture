package handlers

func ShowDocument(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(docRoot, filepath.Base(r.URL.Query().Get("name")))
	deliver(w, p)
}
