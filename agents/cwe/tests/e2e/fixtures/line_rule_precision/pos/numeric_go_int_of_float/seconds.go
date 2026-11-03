package seconds

// Whole truncates a decoded JSON number.
func Whole(v interface{}) int {
	secs, _ := v.(float64)
	whole := int(secs) // EXPECT: finding
	return whole
}
