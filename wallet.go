package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
)

// These are basically constants that require computation
var (
	PrivateWalletVersion []byte
	PublicWalletVersion  []byte
	MaxPrivateKey        []byte
)

// Setup constants that require computation
func init() {
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")

	maxPrivateKey := &big.Int{}
	maxPrivateKey, _ = maxPrivateKey.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	MaxPrivateKey = maxPrivateKey.Bytes()
}

type ExtendedKey struct {
	Version     []byte // 4 bytes
	Depth       byte   // 1 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Key         []byte // 33 bytes
	IsPrivate   bool   // unserialized
}

// Creates a new master extended key from a seed
func NewExtendedKey(seed []byte) (*ExtendedKey, error) {
	// Generate key and chaincode
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac.Write([]byte(seed))
	intermediary := hmac.Sum(nil)

	// Split it into our key and chain code
	key := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	keyInt, _ := binary.ReadVarint(bytes.NewBuffer(key))
	if keyInt == 0 || bytes.Compare(key, MaxPrivateKey) >= 0 {
		return nil, errors.New("Invalid seed")
	}

	// Create the key struct
	extendedKey := &ExtendedKey{
		Version:     PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         key,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}

	return extendedKey, nil
}

// Create public version of key or return a copy
func (extendedKey *ExtendedKey) Neuter() *ExtendedKey {
	key := extendedKey.Key

	if extendedKey.IsPrivate {
		key = publicKeyForPrivateKey(key)
	}

	return &ExtendedKey{
		Version:     PublicWalletVersion,
		Key:         key,
		Depth:       extendedKey.Depth,
		ChildNumber: extendedKey.ChildNumber,
		FingerPrint: extendedKey.FingerPrint,
		ChainCode:   extendedKey.ChainCode,
		IsPrivate:   false,
	}
}

// Serialized an ExtendedKey to a 78 byte byte slice
func (extendedKey *ExtendedKey) Serialize() []byte {
	// Private keys should be prepended with a single null byte
	key := extendedKey.Key
	if extendedKey.IsPrivate {
		key = append([]byte{0x0}, key...)
	}

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(extendedKey.Version)
	buffer.WriteByte(extendedKey.Depth)
	buffer.Write(extendedKey.FingerPrint)
	buffer.Write(extendedKey.ChildNumber)
	buffer.Write(extendedKey.ChainCode)
	buffer.Write(key)

	// Append the standard doublesha256 checksum
	serializedKey := AddChecksum(buffer.Bytes())

	return serializedKey
}

// Encode the ExtendedKey in the standard Bitcoin base58 encoding
func (extendedKey *ExtendedKey) String() string {
	return string(Base58Encode(extendedKey.Serialize()))
}

// Cryptographically secure seed
func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read([]byte(s))
	return s, err
}
