package set1

import (
	"errors"
)

func repeatingKeyIter(seq string) (func() byte, error) {
	l := len(seq)

	if l == 0 {
		return nil, errors.New("empty sequence is not allowed")
	}

	i := 0
	return func() byte {
		key := seq[i]
		i++
		i = i % l
		return key
	}, nil

}

func RepeatingKeyXOR(input []byte, key string) ([]byte, error) {
	seqIter, err := repeatingKeyIter(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		key := seqIter()
		result[i] = input[i] ^ key
	}

	return result, nil
}
