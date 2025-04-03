package set1

import "github.com/titivuk/cryptopals/utils"

var base64grammar = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func HexToBase64(input string) (string, error) {
	decoded, err := utils.HexToBytes(input)
	if err != nil {
		return "", err
	}
	decodedLen := len(decoded)

	// every 3 bytes is written into 4 bytes, so the length has to be 4/3 of initial len
	b64 := make([]byte, decodedLen/3*4)
	i := 0
	j := 0
	for i < decodedLen-2 {
		// concat 3 bytes together
		// we use uint32 since it's the smallest integer that can fit 24 bits
		// example
		// data = [73, 39, 109]
		// bin  = [01001001, 00100111, 01101101]
		// result val = 00000000 01001001 00100111 01101101
		// 			    unused   73       39       109
		val := uint32(decoded[i])<<16 | uint32(decoded[i+1])<<8 | uint32(decoded[i+2])

		// now we need to convert those bits into base64
		// every base64 value occupies 6 bits (64 possible values = 2^6)
		// since we have 24 bits we care about, we split these bits into 6 bits chunks
		// additionally, to use only lefmost 6 bits we care about we apply bitwise AND with 00111111 = 0x3f
		// for example
		// 1st 6 bit chunk is 00000000 (010010)01 00100111 01101101
		// 		shift bits to discard 18 rightmost bits - val >> 18. result is 0...(010010)
		// 		all bits we do not care about are 0s so we don't need to apply bitwise AND to discard them
		// 		010010 (insignifact leftmost 0 bits are omited) = 18 in decimal
		// 		18 is 'S' in base 64 grammar
		// 2st 6 bit chunk is 00000000 010010(01 0010)0111 01101101
		// 		to get the second chunk shift 12 rightmost bits - val >> 12
		// 		however there are bits on the left that are not 0s but we don't care about them so we do bitwise AND and make them 0
		// 		00000000 010010(01 0010) & 00111111 = 0...(010010)
		// 		010010 (insignifact leftmost 0 bits are omited) = 18 in decimal
		// ...
		b64[j] = base64grammar[val>>18&0x3f]
		b64[j+1] = base64grammar[val>>12&0x3f]
		b64[j+2] = base64grammar[val>>6&0x3f]
		b64[j+3] = base64grammar[val&0x3f]

		i += 3
		j += 4
	}

	return string(b64), nil
}
