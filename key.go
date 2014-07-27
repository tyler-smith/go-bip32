package bip32

import (
  "crypto/elliptic"
  "github.com/mndrix/btcutil"
  "math/big"
  // "encoding/binary"
  // "fmt"
)

// Create the standard bitcoin elliptic curve
var curve elliptic.Curve = btcutil.Secp256k1()

const (
    // We use compressed public keys so their length is 33; not 65
    PublicKeyCompressedLength = 33
)

type Key []byte

func (key *Key) ToPublicKey() Key {
    return SerializePublicKey(curve.ScalarBaseMult([]byte(*key)))
}

func SerializePublicKey(x *big.Int, y *big.Int) Key {
  // Create empty key
	key := make(Key, 0, PublicKeyCompressedLength)

  // Add header; 2 if Y is even; 3 if it's odd
  header := byte(0x2)
  if y.Bit(0) == 0 {
    header++
  }
  key = append(key, header)

  // Get bytes of X-value
  xBytes := x.Bytes()

  // Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
  padLength := PublicKeyCompressedLength - 1 - len(xBytes)
  for i := 0; i < padLength; i++ {
    key = append(key, 0)
  }

  // Finally append the x value
  key = append(key, xBytes...)

  return key
}
