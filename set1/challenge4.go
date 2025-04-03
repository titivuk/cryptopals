package set1

import (
	"io"
	"os"
	"strings"

	"github.com/titivuk/cryptopals/utils"
)

func DetectSingleCharacterXOR() (string, error) {
	f, err := os.Open("./set1/challenge4.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	fileBuf, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	inputs := strings.Split(string(fileBuf), "\n")

	var maxScore float64
	var result []byte
	for _, input := range inputs {
		b, err := utils.HexToBytes(input)
		if err != nil {
			return "", err
		}

		for i := 0; i < 256; i++ {
			tmp := make([]byte, len(b))
			var score float64

			for j := 0; j < len(b); j++ {
				decoded := b[j] ^ byte(i)
				tmp[j] = decoded
				score += charFreq[decoded]
			}

			if score > maxScore {
				maxScore = score
				result = tmp
			}
		}
	}

	return string(result), nil
}
