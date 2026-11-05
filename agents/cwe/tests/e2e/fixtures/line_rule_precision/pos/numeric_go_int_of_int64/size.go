package size

// Count narrows a 64-bit count to the platform int.
func Count(n int64) int {
	return int(n) // EXPECT: finding
}
