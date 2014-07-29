package bip32

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/cmars/basen"
	"github.com/mndrix/btcutil"
	"math/big"
)

// Create the standard bitcoin elliptic curve
var curve elliptic.Curve = btcutil.Secp256k1()

var BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

const (
	// We use compressed public keys so their length is 33; not 65
	PublicKeyCompressedLength = 33
)

func DoubleSha256(b []byte) []byte {
	hasher := sha256.New()
	hasher.Write(b)
	sum := hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(sum)
	return hasher.Sum(nil)
}

func Checksum(data []byte) []byte {
	return DoubleSha256(data)[:4]
}

func AddChecksum(data []byte) []byte {
	checksum := Checksum(data)
	return append(data, checksum...)
}

func Base58Encode(data []byte) []byte {
	return []byte(BitcoinBase58Encoding.EncodeToString(data))
}

func publicKeyForPrivateKey(key []byte) []byte {
	return compressPublicKey(curve.ScalarBaseMult([]byte(key)))
}

func compressPublicKey(x *big.Int, y *big.Int) []byte {
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

	return key.Bytes()
}
