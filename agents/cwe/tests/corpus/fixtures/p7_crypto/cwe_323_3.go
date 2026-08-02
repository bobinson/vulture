package store

func sealPayload(aesgcm cipher.AEAD, plaintext []byte) []byte {
	ct := aesgcm.Seal(nil, make([]byte, 12), plaintext, nil)
	return ct
}
