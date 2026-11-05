package narrow

// Narrow truncates a size to 32 bits.
func Narrow(size int64) int32 {
	n := int32(size) // EXPECT: finding
	return n
}
