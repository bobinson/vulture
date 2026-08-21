package store

func sealPayload(aesgcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}
