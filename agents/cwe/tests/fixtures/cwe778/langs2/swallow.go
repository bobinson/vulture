package app

func a() int {
	if err := run(); err != nil {
		return 1
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	if err := run(); err != nil {
		fatalf("run: %v", err)
	}
	if err := run(); err != nil {
		return nil, errInvalidRequest
	}
	if err := run(); err != nil {
		lastErr = derr
		continue
	}
	if err := run(); err != nil {
		failed = append(failed, err.Error())
	}
	if err := run(); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if err := run(); err != nil {
		log.Printf("run: %v", err)
	}
	return 0
}

func inlineForms() int {
	if err := run(); err != nil { }
	if err := run(); err != nil {}
	if err := run(); err != nil { count++ }
	if err := run(); err != nil { log.Print(err) }
	if err := run(); err != nil { return fmt.Errorf("x: %w", err) }
	return 0
}
