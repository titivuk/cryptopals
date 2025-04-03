package main

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/titivuk/cryptopals/set1"
	"github.com/titivuk/cryptopals/utils"
)

func main() {
	str, err := set1.HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		panic(err)
	}

	if str != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic(errors.New("invalid hex -> base64 conversion"))
	}

	s1ch2a, err := utils.HexToBytes("1c0111001f010100061a024b53535009181c")
	if err != nil {
		panic(err)
	}
	s1ch2b, err := utils.HexToBytes("686974207468652062756c6c277320657965")
	if err != nil {
		panic(err)
	}
	s1ch2, err := set1.FixedXOR(s1ch2a, s1ch2b)
	if err != nil {
		panic(err)
	}
	fmt.Printf("s1ch2 result: %s\n", hex.EncodeToString(s1ch2))

	s1ch3input, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		panic(err)
	}
	s1ch3, err := set1.SingleByteCipher(s1ch3input)
	if err != nil {
		panic(err)
	}
	fmt.Printf("s1ch3 result: %s\n", string(s1ch3.Data))
	if string(s1ch3.Data) != "Cooking MC's like a pound of bacon" {
		panic(fmt.Sprintf("s1ch3: invalid result string %s", string(s1ch3.Data)))
	}

	s1ch4, err := set1.DetectSingleCharacterXOR()
	if err != nil {
		panic(err)
	}
	fmt.Printf("s1ch4 result: %s\n", s1ch4)

	s1ch5, err := set1.RepeatingKeyXOR([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), "ICE")
	if err != nil {
		panic(err)
	}
	fmt.Printf("s1ch5 result: %s\n", hex.EncodeToString(s1ch5))
	if hex.EncodeToString(s1ch5) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		panic(fmt.Sprintf("s1ch5: invalid result string %s", s1ch5))
	}

	s1ch6, err := set1.BreakRepeatingKeyXOR("./set1/challenge6.txt")
	if err != nil {
		panic(err)
	}
	if s1ch6.Key != "Terminator X: Bring the noise" {
		panic(fmt.Sprintf("s1ch6: invalid key %s\n", s1ch6.Key))
	}

	_, err = set1.AesInEcbMode("./set1/challenge7.txt", "YELLOW SUBMARINE")
	if err != nil {
		panic(err)
	}
}
