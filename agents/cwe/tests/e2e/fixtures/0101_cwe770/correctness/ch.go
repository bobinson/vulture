package x

func drain(ch chan []byte) [][]byte {
	var out [][]byte
	for msg := range ch {
		// EXPECT-NEXT: finding channel range
		out = append(out, msg)
	}
	return out
}
