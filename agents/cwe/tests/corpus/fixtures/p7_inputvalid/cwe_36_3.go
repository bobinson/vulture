package handler

func serveDoc(name string) ([]byte, error) {
	cleaned := strings.ReplaceAll(name, "..", "")
	return ioutil.ReadFile(cleaned)
}
