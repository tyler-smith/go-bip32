package bip32

import (
  // "fmt"
  "crypto/rand"
  "crypto/hmac"
  "crypto/sha512"
  "encoding/binary"
  "bytes"
  "encoding/hex"
)


var Private, _ = hex.DecodeString("0488ADE4")
var Public, _ = hex.DecodeString("0488B21E")
var MaxKey, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

type Seed []byte
type Key struct {
  Version []byte
  Depth byte
  FingerPrint []byte
  ChildNumber []byte
  ChainCode []byte
  Key []byte
}

func NewKey(seed *Seed) (*Key) {
  validPair := false

  var key []byte
  var chainCode []byte

  for !validPair {
    // Generate intermediary
    hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
    hmac.Write([]byte(*seed))
    intermediary := hmac.Sum(nil)

    // Split it into our key intermediary and chain code
    key = intermediary[:32]
    chainCode = intermediary[32:]

  // Validate key
    keyInt, err := binary.ReadVarint(bytes.NewBuffer(key))
    if err == nil && keyInt != 0 && bytes.Compare(key, MaxKey) == -1 {
      validPair = true
    }
  }

  return &Key{
    Private,
    byte(0),
    []byte{},
    []byte{},
    chainCode,
    key,
  }
}

func NewSeed() (*Seed, error) {
  s := make(Seed, 256)
  _, err := rand.Read([]byte(s))
  return &s, err
}
