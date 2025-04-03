package set1

import (
	"encoding/hex"
	"os"
	"strings"
)

func DetectAesInEcbMode(filePath string) (string, error) {
	fb, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(fb), "\n")
	blockSize := 16
	maxFreq := 0
	line := ""
	for i := 0; i < len(lines); i++ {
		b, err := hex.DecodeString(lines[i])
		if err != nil {
			return "", err
		}

		// assume data is equally split into 16 byte chunks
		if len(b)%16 != 0 {
			continue
		}

		// assume data is at least single 16-byte block
		if len(b) < 16 {
			continue
		}

		// Remember that the problem with ECB is that it is stateless and deterministic;
		// the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
		// Based on that comment we assume that some blocks repeat and find the line with the most repeated block
		maxLocalFreq := 0
		chunkFreq := make(map[string]int)
		for c := 0; c < len(b); c += blockSize {
			chunk := b[c : c+blockSize]
			chunkKey := string(chunk)
			chunkFreq[chunkKey] += 1
			if chunkFreq[chunkKey] > maxLocalFreq {
				maxLocalFreq = chunkFreq[chunkKey]
			}
		}

		if maxLocalFreq > maxFreq {
			maxFreq = maxLocalFreq
			line = lines[i]
		}
	}

	return line, nil
}
