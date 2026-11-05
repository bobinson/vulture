func main() {
	if err := run(); err != nil {
		// EXPECT-NEXT: clean  stderr is not a peer
		io.WriteString(os.Stderr, err.Error()+"\n")
	}
}
