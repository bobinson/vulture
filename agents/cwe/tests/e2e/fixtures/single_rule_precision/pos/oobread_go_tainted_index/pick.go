package pick

// pick indexes rows with a caller-supplied value.
func pick(rows []string, param int) string {
	// EXPECT-NEXT: finding
	return rows[param]
}
