package set1

import (
	"cmp"
	"encoding/base64"
	"io"
	"os"
	"slices"
)

type BreakRepeatingKeyXORResult struct {
	Key  string
	Data []byte
}

func BreakRepeatingKeyXOR(filePath string) (BreakRepeatingKeyXORResult, error) {
	var result BreakRepeatingKeyXORResult

	f, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer f.Close()

	b64buf, err := io.ReadAll(f)
	if err != nil {
		return result, err
	}

	b, err := base64.StdEncoding.DecodeString(string(b64buf))
	if err != nil {
		return result, err
	}

	type Dist struct {
		keySize  int
		distance float64
	}

	// find distances
	distances := make([]Dist, 0)
	for ks := 2; ks <= 40; ks++ {
		d := calculatePairDistance(b, ks)
		distances = append(distances, Dist{
			keySize:  ks,
			distance: d,
		})
	}
	// sort by distance ASC
	slices.SortFunc(distances, func(a, b Dist) int {
		return cmp.Compare(a.distance, b.distance)
	})

	minDistance := distances[0]
	transposedLen := len(b) / minDistance.keySize
	transposedLen += len(b) % minDistance.keySize

	kb := make([]byte, 0)
	for i := 0; i < minDistance.keySize; i++ {
		block := make([]byte, transposedLen)
		bi := 0
		for j := i; j < len(b); j += minDistance.keySize {
			block[bi] = b[j]
			bi++
		}

		sb, err := SingleByteCipher(block)
		if err != nil {
			panic(err)
		}

		kb = append(kb, sb.Key)
	}
	result.Key = string(kb)

	br, err := RepeatingKeyXOR(b, string(kb))
	if err != nil {
		return result, err
	}
	result.Data = br

	return result, nil
}

func calculatePairDistance(input []byte, pairSize int) float64 {
	pairCount := 0
	var dist float64
	for i := 0; i+2*pairSize < len(input); i++ {
		a, b := input[i:i+pairSize], input[i+pairSize:i+2*pairSize]
		dist += float64(hammingDistance(a, b))
		pairCount += 1
	}

	// normalize
	dist /= float64(pairSize)
	// avg
	dist /= float64(pairCount)

	return dist
}

func hammingDistance(a, b []byte) int {
	// must be the same length
	if len(a) != len(b) {
		return -1
	}

	l := len(a)

	count := 0
	for i := 0; i < l; i++ {
		// XOR sets 1 if bits aren't equal
		x := a[i] ^ b[i]

		// count number of "1" in a given byte
		for j := 0; j < 8; j++ {
			// start from 1 << 0 = 00000001
			// 		 then 1 << 1 = 00000010
			//       ....
			//       then 1 << 7 = 10000000
			// check if bit at j-th position is "1" using bitwise AND "&"
			if isOne := x & (1 << j); isOne > 0 {
				count += 1
			}
		}
	}

	return count
}
