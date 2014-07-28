package bip32

import (
	"crypto/elliptic"
	"github.com/mndrix/btcutil"
	"math/big"
  "bytes"
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
  var key bytes.Buffer

  // Write header; 0x2 for even y value; 0x3 for odd
  header := byte(0x2)
  if y.Bit(0) == 1 {
    header = byte(0x3)
  }
  key.WriteByte(header)

  // Get bytes of X-value
  xBytes := x.Bytes()

  // Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
  for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
    key.WriteByte(0x0)
  }

  key.Write(xBytes)

  return Key(key.Bytes())
}
