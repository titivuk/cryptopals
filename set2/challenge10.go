package set2

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"os"
)

func CbcMode(filePath string, key []byte) ([]byte, error) {
	b64, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	encrypted, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, err
	}

	return AesInCbcMode(encrypted, key, nil)
}

func AesInCbcMode(encrypted, key []byte, iv []byte) ([]byte, error) {
	if iv != nil && len(key) != len(iv) {
		return nil, errors.New("key and IV vector must be the same size")
	}

	c, err := aes.NewCipher(key)
	blockSize := len(key)
	decrypted := make([]byte, 0)
	if iv == nil {
		iv = make([]byte, blockSize)
	}
	for i := 0; i < len(encrypted); i += blockSize {
		if err != nil {
			return nil, err
		}

		end := i + blockSize
		if end > len(encrypted) {
			end = len(encrypted) - 1
		}
		encryptedBlock := encrypted[i:end]
		// decrypt block
		decryptedBlock := make([]byte, blockSize)
		c.Decrypt(decryptedBlock, encryptedBlock)
		// XOR decrypted block with initialization vector to get original plaintext value
		plainBlock := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			plainBlock[j] = decryptedBlock[j] ^ iv[j]
		}

		// next block initialization vector (IV) is the previous encrypted block
		iv = encryptedBlock

		decrypted = append(decrypted, plainBlock...)
	}

	return decrypted, nil
}
