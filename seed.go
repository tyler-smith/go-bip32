package bip32

import (
  "crypto/rand"
)

type Seed []byte

func NewSeed() (*Seed, error) {
  s := make(Seed, 256)
  _, err := rand.Read([]byte(s))
  return &s, err
}
