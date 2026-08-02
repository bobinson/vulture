package issuer

import (
	"crypto/rand"
	"math/big"
)

func OneTimePassword() string {
	digits := make([]byte, 6)
	for i := range digits {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		digits[i] = byte('0' + n.Int64())
	}
	return string(digits)
}
