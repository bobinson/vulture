func join(errs []error) string {
	var sb strings.Builder
	for _, err := range errs {
		// EXPECT-NEXT: clean  go strings builder
		sb.WriteString(err.Error())
	}
	return sb.String()
}
