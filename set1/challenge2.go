package set1

import "errors"

func FixedXOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("buffers must be equal length")
	}

	result := make([]byte, len(a))
	for i := 0; i < len(result); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}
