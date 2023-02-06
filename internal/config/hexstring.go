package config

import (
	"encoding/hex"
	"math/big"
	"strings"
)

type HexString string

func (h HexString) ToBigInt() (*big.Int, bool) {
	s := clean(h)
	return big.NewInt(0).SetString(s, 16)
}

func (h HexString) ToBytes() ([]byte, bool) {
	s := clean(h)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func clean(h HexString) string {
	s := strings.TrimSpace(string(h))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
