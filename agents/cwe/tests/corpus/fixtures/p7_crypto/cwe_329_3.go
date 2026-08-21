package store

func encryptRecord(block cipher.Block, plaintext []byte) []byte {
	out := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	mode.CryptBlocks(out, plaintext)
	return out
}
