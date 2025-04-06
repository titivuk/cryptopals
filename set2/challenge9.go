package set2

import (
	"fmt"
)

func Pad(block []byte, targetLen int) ([]byte, error) {
	if len(block) > targetLen {
		return nil, fmt.Errorf("block len %d is greater than target block size %d", len(block), targetLen)
	}

	if len(block) == targetLen {
		return block, nil
	}

	for len(block) < targetLen {
		block = append(block, 0x04)
	}

	return block, nil
}
