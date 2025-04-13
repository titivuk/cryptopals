package set2

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"slices"

	"github.com/titivuk/cryptopals/set1"
)

func EcbcbcDetector() {
	// ECB is deterministic and always ecnrypt the same data into the same encrypted data
	// randomEncryptor appends from 5 to 11 byte -> worst case first block can consume 11 byte of the input
	// so we insert eleven "A" in the beginning and in the end
	// in the middle put 2 identical 16-byte blocks
	// in result
	// AAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAA
	//			  |                                |
	// 			   results of those 2 blocks
	// 			   are compared after encryption
	encrypted, err := randomEncryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		panic(err)
	}

	secondBlock := encrypted[16:32]
	thirdBlock := encrypted[32:48]
	if slices.Equal(secondBlock, thirdBlock) {
		fmt.Println("Two equal blocks are encrypted into the same block -> ECB encryption is used")
	} else {
		fmt.Println("Two equal blocks are encrypted into different blocks  -> CBC encryption is used")
	}
}

func randomEncryptor(input []byte) ([]byte, error) {
	key := genKey(16)
	extInput := appendRandomBytes(input)

	if len(extInput)%16 != 0 {
		paddedInput, err := Pad(extInput, len(extInput)+(16-len(extInput)%16))

		if err != nil {
			return nil, err
		}

		extInput = paddedInput
	}

	// from 0 to 1
	n := mrand.IntN(2)

	switch n {
	case 0:
		return set1.AesInEcbMode(extInput, key)
	case 1:
		iv := make([]byte, 16)
		_, err := crand.Read(iv)
		if err != nil {
			return nil, err
		}
		return AesInCbcMode(extInput, key, iv)
	default:
		return nil, errors.New("unknown encryption method")
	}
}

func genKey(n int) []byte {
	key := make([]byte, n)
	_, err := crand.Read(key)
	if err != nil {
		panic(err)
	}

	return key
}

func appendRandomBytes(input []byte) []byte {
	n := mrand.IntN(10-5) + 5

	before := make([]byte, n)
	after := make([]byte, n)
	_, err := crand.Read(before)
	if err != nil {
		panic(err)
	}
	_, err = crand.Read(after)
	if err != nil {
		panic(err)
	}

	result := make([]byte, 0, len(input)+n*2)
	result = append(result, before...)
	result = append(result, input...)
	result = append(result, after...)

	return result
}
