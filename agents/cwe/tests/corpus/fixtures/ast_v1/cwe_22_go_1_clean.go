// Pins: filepath.Base on the r.URL.Query().Get("f") value before Join and os.ReadFile; the base sanitizer survives the Join builder.
package app

const rootDir = "/srv/docs"

func showDoc(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(filepath.Join(rootDir, filepath.Base(r.URL.Query().Get("f"))))
	fmt.Fprintf(w, "%s", data)
}
