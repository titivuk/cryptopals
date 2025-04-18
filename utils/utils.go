package utils

import "fmt"

// mapping between hex and ascii
// stole the idea from go std hex package
// byte pos int the string - ascii charcode
// value int the string - corresponding hex value
var reverseHexTable = "" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [0,15]
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [16, 31]
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [32, 47]
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff" + // [48, 63]
	"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [64, 79]
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [80, 95]
	"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // [96, 111]
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" + // ...
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

func HexToBytes(input string) ([]byte, error) {
	if len(input)%2 == 1 {
		return nil, fmt.Errorf("invalid input length: %d", len(input))
	}

	// hex value is 4 bit
	// so we need (len(input) / 2) bytes to store len(intput) hex
	dataLen := len(input) / 2
	data := make([]byte, dataLen)

	inputIdx, byteIdx := 0, 0
	for inputIdx < len(input)-1 {
		b1 := input[inputIdx]
		b2 := input[inputIdx+1]
		left := reverseHexTable[b1]
		right := reverseHexTable[b2]

		// expect hex string to have only valid characters
		if left > 0x0f {
			return nil, fmt.Errorf("invalid byte %#U", rune(b1))
		}
		if right > 0x0f {
			return nil, fmt.Errorf("invalid byte %#U", rune(b2))
		}

		data[byteIdx] = left<<4 | right

		inputIdx += 2
		byteIdx += 1
	}

	return data, nil
}
