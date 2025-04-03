package set1

import (
	"crypto/aes"
	"encoding/base64"
	"io"
	"os"
)

func AesInEcbMode(filePath, key string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b64buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	encrypted, err := base64.StdEncoding.DecodeString(string(b64buf))
	if err != nil {
		return nil, err
	}

	blockSize := 16
	blocks := len(encrypted) / blockSize

	decrypted := make([]byte, 0)
	for i := 0; i < blocks; i++ {
		c, err := aes.NewCipher([]byte(key))
		if err != nil {
			return nil, err
		}

		decryptedBlock := make([]byte, blockSize)
		c.Decrypt(decryptedBlock, encrypted[blockSize*i:blockSize*i+blockSize])

		decrypted = append(decrypted, decryptedBlock...)
	}

	return decrypted, nil
}
