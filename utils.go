package bip32

import (
	"crypto/sha256"
	"github.com/cmars/basen"
)

var BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

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
