package bip32

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

const (
	// FirstHardenedChild is the index of the firxt "harded" child key as per the
	// bip32 spec
	FirstHardenedChild = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	// PrivateWalletVersion is the version flag for serialized private keys
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicWalletVersion is the version flag for serialized private keys
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length
	ErrSerializedKeyWrongSize = errors.New("Serialized keys should by exactly 82 bytes")

	// ErrHardnedChildPublicKey is returned when trying to create a harded child
	// of the public key
	ErrHardnedChildPublicKey = errors.New("Can't create hardened child for public key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid
	ErrInvalidPrivateKey = errors.New("Invalid private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid
	ErrInvalidPublicKey = errors.New("Invalid public key")

	// ErrUnsupportedEd25519PublicKeyDerivation is returned when a public child key is derived with ed25519 curve.
	ErrUnsupportedEd25519PublicKeyDerivation = errors.New("Public key for ed25519 is not supported for normal derivation")
)

// The supported curves.
// @link SupportedCurves
const (
	Bitcoin Curve = iota // secp256k1
	Ed25519
)

// curvesSalt corresponds to the supported curves @SupportedCurves by the index.
var curvesSalt = [][]byte{
	[]byte("Bitcoin seed"),
	[]byte("ed25519 seed"),
}

// Curve defines the private key for the HMAC hash that generates the master key.
// https://github.com/satoshilabs/slips/blob/master/slip-0010.md#master-key-generation
type Curve byte

// Key represents a bip32 extended key
type Key struct {
	Key         []byte // 33 bytes
	Version     []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Depth       byte   // 1 byte
	IsPrivate   bool   // unserialized

	// The Deserialize function sets it bip32.Bitcoin by default.
	// see https://github.com/satoshilabs/slips/blob/master/slip-0132.md#registered-hd-version-bytes
	curve Curve
}

// NewMasterKeyWithCurve creates a new master extended key from a seed
// with a given curve algorithm.
func NewMasterKeyWithCurve(seed []byte, curve Curve) (*Key, error) {
	if int(curve) > len(curvesSalt) {
		panic("unsupported curve, only bip32.Bitcoin and bit32.Ed25519 are supported")
	}
	// Generate key and chaincode
	intermediary, err := hmac512(seed, curvesSalt[curve])
	if err != nil {
		return nil, err
	}

	// Split it into our key and chain code
	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	err = validatePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	// Create the key struct
	key := &Key{
		Version:     PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
		curve:       curve,
	}

	return key, nil
}

// NewMasterKey creates a new master extended key from a seed
// using the Bitcoin curve.
func NewMasterKey(seed []byte) (*Key, error) {
	return NewMasterKeyWithCurve(seed, Bitcoin)
}

// NewChildKey derives a child key from a given parent as outlined by bip32
func (key *Key) NewChildKey(childIdx uint32) (*Key, error) {
	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && childIdx >= FirstHardenedChild {
		return nil, ErrHardnedChildPublicKey
	}

	if key.curve == Ed25519 {
		if !key.IsPrivate {
			return nil, ErrUnsupportedEd25519PublicKeyDerivation
		}
		// With ed25519 curve all derivation-path indexes will be promoted to hardened indexes.
		if childIdx < FirstHardenedChild {
			childIdx += FirstHardenedChild
		}
	}

	intermediary, err := key.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &Key{
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
		curve:       key.curve,
	}

	// Bip32 CKDpriv
	if key.IsPrivate {
		childKey.Version = PrivateWalletVersion

		var publicKey []byte

		// https://github.com/satoshilabs/slips/blob/master/slip-0010.md#private-parent-key--private-child-key
		if childKey.curve == Ed25519 {
			childKey.Key = intermediary[:32]
			publicKey = publicKeyForPrivateKeyEd25519(key.Key)
		} else {
			childKey.Key = addPrivateKeys(intermediary[:32], key.Key)
			// Validate key
			if err := validatePrivateKey(childKey.Key); err != nil {
				return nil, err
			}
			publicKey = publicKeyForPrivateKeyBitcoin(key.Key)
		}

		fingerprint, err := hash160(publicKey)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]

		// Bip32 CKDpub
	} else {
		keyBytes := publicKeyForPrivateKeyBitcoin(intermediary[:32])

		// Validate key
		err := validateChildPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		childKey.Version = PublicWalletVersion
		fingerprint, err := hash160(key.Key)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = addPublicKeys(keyBytes, key.Key)
	}

	return childKey, nil
}

func (key *Key) getIntermediary(childIdx uint32) ([]byte, error) {
	// Get intermediary to create key and chaincode from
	// Hardened children are based on the private key
	// NonHardened children are based on the public key
	childIndexBytes := uint32Bytes(childIdx)

	var data []byte
	if childIdx >= FirstHardenedChild {
		data = append([]byte{0x0}, key.Key...)
	} else {
		if key.IsPrivate {
			data = publicKeyForPrivateKeyBitcoin(key.Key)
		} else {
			data = key.Key
		}
	}
	data = append(data, childIndexBytes...)

	return hmac512(data, key.ChainCode)
}

// PublicKey returns the public version of key or return a copy
// The 'Neuter' function from the bip32 spec
func (key *Key) PublicKey() *Key {
	keyBytes := key.Key

	if key.IsPrivate {
		if key.curve == Ed25519 {
			keyBytes = publicKeyForPrivateKeyEd25519(keyBytes)
		} else {
			keyBytes = publicKeyForPrivateKeyBitcoin(keyBytes)
		}
	}

	return &Key{
		Version:     PublicWalletVersion,
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
		curve:       key.curve,
	}
}

// Serialize a Key to a 78 byte byte slice
func (key *Key) Serialize() ([]byte, error) {
	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	if key.IsPrivate {
		keyBytes = append([]byte{0x0}, keyBytes...)
	}

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	// Append the standard doublesha256 checksum
	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return serializedKey, nil
}

// B58Serialize encodes the Key in the standard Bitcoin base58 encoding
func (key *Key) B58Serialize() string {
	serializedKey, err := key.Serialize()
	if err != nil {
		return ""
	}

	return base58Encode(serializedKey)
}

// String encodes the Key in the standard Bitcoin base58 encoding
func (key *Key) String() string {
	return key.B58Serialize()
}

// Deserialize a byte slice into a Key
func Deserialize(data []byte) (*Key, error) {
	if len(data) != 82 {
		return nil, ErrSerializedKeyWrongSize
	}
	var key = &Key{}
	key.Version = data[0:4]
	key.Depth = data[4]
	key.FingerPrint = data[5:9]
	key.ChildNumber = data[9:13]
	key.ChainCode = data[13:45]

	if data[45] == byte(0) {
		key.IsPrivate = true
		key.Key = data[46:78]
	} else {
		key.IsPrivate = false
		key.Key = data[45:78]
	}

	// validate checksum
	cs1, err := checksum(data[0 : len(data)-4])
	if err != nil {
		return nil, err
	}

	cs2 := data[len(data)-4:]
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			return nil, ErrInvalidChecksum
		}
	}
	return key, nil
}

// B58Deserialize deserializes a Key encoded in base58 encoding
func B58Deserialize(data string) (*Key, error) {
	b, err := base58Decode(data)
	if err != nil {
		return nil, err
	}
	return Deserialize(b)
}

// NewSeed returns a cryptographically secure seed
func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read(s)
	return s, err
}
