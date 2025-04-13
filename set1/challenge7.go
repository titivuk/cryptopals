package set1

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func Chal7() {
	f, err := os.Open("./set1/challenge7.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	b64buf, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(string(b64buf))
	if err != nil {
		panic(err)
	}

	decrypted, err := AesInEcbMode(encrypted, []byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}

	fmt.Println("s1ch7 decrypted", string(decrypted))
}

func AesInEcbMode(encrypted, key []byte) ([]byte, error) {
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
