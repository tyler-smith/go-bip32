package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
)

const (
	FirstHardenedChild        = uint32(0x80000000)
	PublicKeyCompressedLength = 33
)

// These are basically constants that require computation
var (
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")
)


// Represents a bip32 extended key containing key data, chain code, parent information, and other meta data
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
	err := validatePrivateKey(key)
	if err != nil {
		return nil, err
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

// Derives a child key from a given parent as outlined by bip32
func (extendedKey *ExtendedKey) Child(childIdx uint32) (*ExtendedKey, error) {
	hardenedChild := childIdx >= FirstHardenedChild
	childIndexBytes := uint32Bytes(childIdx)

	// Fail early if trying to create hardned child from public key
	if !extendedKey.IsPrivate && hardenedChild {
		return nil, errors.New("Can't create hardened child for public key")
	}

	// Get intermediary to create key and chaincode from
	// Hardened children are based on the private key
	// NonHardened children are based on the public key
	var data []byte
	if hardenedChild {
		data = append([]byte{0x0}, extendedKey.Key...)
	} else {
		data = publicKeyForPrivateKey(extendedKey.Key)
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, extendedKey.ChainCode)
	hmac.Write(data)
	intermediary := hmac.Sum(nil)

	// Create child ExtendedKey with data common to all both scenarios
	childExtendedKey := &ExtendedKey{
		ChildNumber: childIndexBytes,
		ChainCode:   intermediary[32:],
		Depth:       extendedKey.Depth + 1,
		IsPrivate:   extendedKey.IsPrivate,
	}

	// Bip32 CKDpriv
	if extendedKey.IsPrivate {
		childExtendedKey.Version = PrivateWalletVersion
		childExtendedKey.FingerPrint = hash160(publicKeyForPrivateKey(extendedKey.Key))[:4]
		childExtendedKey.Key = addPrivateKeys(intermediary[:32], extendedKey.Key)

		// Validate key
		err := validatePrivateKey(childExtendedKey.Key)
		if err != nil {
			return nil, err
		}
		// Bip32 CKDpub
	} else {
		key := publicKeyForPrivateKey(intermediary[:32])

		// Validate key
		err := validateChildPublicKey(key)
		if err != nil {
			return nil, err
		}

		childExtendedKey.Version = PublicWalletVersion
		childExtendedKey.FingerPrint = hash160(extendedKey.Key)[:4]
		childExtendedKey.Key = addPublicKeys(key, extendedKey.Key)
	}

	return childExtendedKey, nil
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
	serializedKey := addChecksumToBytes(buffer.Bytes())

	return serializedKey
}

// Encode the ExtendedKey in the standard Bitcoin base58 encoding
func (extendedKey *ExtendedKey) String() string {
	return string(base58Encode(extendedKey.Serialize()))
}

// Cryptographically secure seed
func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read([]byte(s))
	return s, err
}
