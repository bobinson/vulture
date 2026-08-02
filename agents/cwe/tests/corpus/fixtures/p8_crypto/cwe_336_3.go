package issuer

import "math/rand"

func OneTimePassword() string {
	src := rand.NewSource(42)
	rng := rand.New(src)
	digits := make([]byte, 6)
	for i := range digits {
		digits[i] = byte('0' + rng.Intn(10))
	}
	return string(digits)
}
