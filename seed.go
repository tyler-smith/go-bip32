package bip32

import (
	"crypto/rand"
	"encoding/hex"
)

type Seed []byte

func NewSeed() (*Seed, error) {
	s := make(Seed, 256)
	_, err := rand.Read([]byte(s))
	return &s, err
}

func NewSeedFromHex(hexString string) (*Seed, error) {
	decodedSeed, err := hex.DecodeString(hexString)
	seed := Seed(decodedSeed)
	return &seed, err
}
