package handler

func serveDoc(name string) ([]byte, error) {
	rel, err := filepath.Rel(root, filepath.Join(root, name))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(rel)
}
