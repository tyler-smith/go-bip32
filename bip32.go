package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// FirstHardenedChild is the index of the firxt "harded" child key as per the
	// bip32 spec
	FirstHardenedChild = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33

	// NetworkTestNet is the string for BTC TestNet network
	NetworkTestNet = "testnet"

	// NetworkMainNet is the string for BTC MainNet network
	NetworkMainNet = "mainnet"
)

var (
	// BTCNetwork is the BTC network on which the wallet is valid (decides public/private version flags)
	BTCNetwork = NetworkMainNet

	// PrivateWalletVersion is the version flag for serialized private keys for set BTCNetwork
	PrivateWalletVersion []byte

	// PublicWalletVersion is the version flag for serialized public keys for set BTCNetwork
	PublicWalletVersion []byte

	// PrivateMainNetWalletVersion is the version flag for mainnet serialized private keys
	PrivateMainNetWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicMainNetWalletVersion is the version flag for mainnet serialized public keys
	PublicMainNetWalletVersion, _ = hex.DecodeString("0488B21E")

	// PrivateTestNetWalletVersion is the version flag for testnet serialized private keys
	PrivateTestNetWalletVersion, _ = hex.DecodeString("04358394")

	// PublicTestNetWalletVersion is the version flag for testnet serialized public keys
	PublicTestNetWalletVersion, _ = hex.DecodeString("043587cf")

	// ErrInvalidBTCNetwork is returned when trying to set a BTC network
	// which is not currently supported
	ErrInvalidBTCNetwork = errors.New("Invalid BTC network")

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
)

func init() {
	SetBTCNetwork(NetworkMainNet) // set default network
}

// SetBTCNetwork sets BTCNetwork to the given network string if supported
func SetBTCNetwork(network string) error {
	network = strings.ToLower(network)

	BTCNetwork = network

	switch network {
	case NetworkMainNet:
		PrivateWalletVersion = PrivateMainNetWalletVersion
		PublicWalletVersion = PublicMainNetWalletVersion

	case NetworkTestNet:
		PrivateWalletVersion = PrivateTestNetWalletVersion
		PublicWalletVersion = PublicTestNetWalletVersion

	default:
		return ErrInvalidBTCNetwork
	}

	return nil
}

// Key represents a bip32 extended key
type Key struct {
	Key         []byte // 33 bytes
	Version     []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Depth       byte   // 1 bytes
	IsPrivate   bool   // unserialized
}

// NewMasterKey creates a new master extended key from a seed
func NewMasterKey(seed []byte) (*Key, error) {
	// Generate key and chaincode
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	intermediary := hmac.Sum(nil)

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
	}

	return key, nil
}

// NewChildKey derives a child key from a given parent as outlined by bip32
func (key *Key) NewChildKey(childIdx uint32) (*Key, error) {
	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && childIdx >= FirstHardenedChild {
		return nil, ErrHardnedChildPublicKey
	}

	intermediary, err := key.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &Key{
		Version:     key.Version,
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
	}

	// Bip32 CKDpriv
	if key.IsPrivate {
		fingerprint, err := hash160(publicKeyForPrivateKey(key.Key))
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = addPrivateKeys(intermediary[:32], key.Key)

		// Validate key
		err = validatePrivateKey(childKey.Key)
		if err != nil {
			return nil, err
		}
		// Bip32 CKDpub
	} else {
		keyBytes := publicKeyForPrivateKey(intermediary[:32])

		// Validate key
		err := validateChildPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

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
			data = publicKeyForPrivateKey(key.Key)
		} else {
			data = key.Key
		}
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, key.ChainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

// PublicKey returns the public version of key or return a copy
// The 'Neuter' function from the bip32 spec
func (key *Key) PublicKey() *Key {
	keyBytes := key.Key

	if key.IsPrivate {
		keyBytes = publicKeyForPrivateKey(keyBytes)
	}

	return &Key{
		Version:     PublicWalletVersion,
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
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

// Address returns the BTC address of the key
func (key *Key) Address() (string, error) {
	// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

	// SHA-256( key )
	sha256Key, err := hashSha256(key.Key)
	if err != nil {
		return "", err
	}

	// RIPEMD-160( SHA-256(key) )
	r160SHA256Key, err := hashRipeMD160(sha256Key)
	if err != nil {
		return "", err
	}

	// Get network by key version
	network, err := getKeyVersionNetwork(key.Version)
	if err != nil {
		return "", err
	}

	// Set version prefix byte to prepend to RIPEMD-160( SHA-256(key) ) by network
	versionPrefixByte := 0x00 // mainnet

	switch network {
	case NetworkTestNet:
		versionPrefixByte = 0x6f
	}

	// Prepend version prefix byte to RIPEMD-160( SHA-256(key) )
	verR160SHA256Key := append([]byte{byte(versionPrefixByte)}, r160SHA256Key...)

	// SHA-256( SHA-256 ( VER_RIPEMD-160( SHA-256(key) ) ) )
	dblSHA256VerR160SHA256Key, err := hashDoubleSha256(verR160SHA256Key)
	if err != nil {
		return "", err
	}

	// First 4 bytes of SHA-256( SHA-256 ( VER_RIPEMD-160( SHA-256(key) ) ) )
	first4Bytes := dblSHA256VerR160SHA256Key[:4]

	// Append first 4 bytes to VER_RIPEMD-160( SHA-256(key) )
	verR160SHA256KeyF4B := append(verR160SHA256Key, first4Bytes...)

	// Base58 encode VER_RIPEMD-160( SHA-256(key) )_FIRST4BYTES
	return base58Encode(verR160SHA256KeyF4B), nil
}
