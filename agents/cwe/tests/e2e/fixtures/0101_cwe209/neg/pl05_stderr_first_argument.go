func main() {
	if err := run(); err != nil {
		// EXPECT-NEXT: clean  stderr first argument
		io.WriteString(os.Stderr, err.Error())
	}
}
