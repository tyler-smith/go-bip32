package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
)

var PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
var PublicWalletVersion, _ = hex.DecodeString("0488B21E")
var MaxPrivateKey, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

const (
	SerializedWalletLength = 78
)

type HDWallet struct {
	Version     []byte // 4 bytes
	Depth       byte   // 1 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Key         Key    // 33 bytes
}

func NewHDWallet(seed *Seed) *HDWallet {
	// Generate candiate keys until we find a valid one
	validKeyCandidate := false
	var keyCandidate []byte
	var chainCodeCandidate []byte

	for !validKeyCandidate {
		// Generate intermediary
		hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
		hmac.Write([]byte(*seed))
		intermediary := hmac.Sum(nil)

		// Split it into our key and chain code candidates
		keyCandidate = intermediary[:32]
		chainCodeCandidate = intermediary[32:]

		// Validate keyCandidate
		keyCandidateInt, err := binary.ReadVarint(bytes.NewBuffer(keyCandidate))
		if err == nil && keyCandidateInt != 0 && bytes.Compare(keyCandidate, MaxPrivateKey) == -1 {
			validKeyCandidate = true
		}
	}

	wallet := &HDWallet{
		Version:   PrivateWalletVersion,
		ChainCode: chainCodeCandidate,
		Key:       Key(keyCandidate),
	}

	wallet.Depth = 0x0
	wallet.ChildNumber = []byte{0x00, 0x00, 0x00, 0x00}
	wallet.FingerPrint = []byte{0x00, 0x00, 0x00, 0x00}

	return wallet
}

func (wallet *HDWallet) PublicWallet() *HDWallet {
	key := wallet.Key

	if wallet.IsPrivate() {
		key = key.ToPublicKey()
	}

	return &HDWallet{
		Version:     PublicWalletVersion,
		Depth:       wallet.Depth,
		ChildNumber: wallet.ChildNumber,
		FingerPrint: wallet.FingerPrint,
		ChainCode:   wallet.ChainCode,
		Key:         key,
	}
}

func (wallet *HDWallet) Serialize() []byte {
	var buffer bytes.Buffer

	key := wallet.Key
	if wallet.IsPrivate() {
		key = append([]byte{0x0}, key...)
	}

	buffer.Write(wallet.Version)
	buffer.WriteByte(wallet.Depth)
	buffer.Write(wallet.FingerPrint)
	buffer.Write(wallet.ChildNumber)
	buffer.Write(wallet.ChainCode)
	buffer.Write(key)

	return AddChecksum(buffer.Bytes())
}

func (wallet *HDWallet) String() string {
	return string(Base58Encode(wallet.Serialize()))
}

func (wallet *HDWallet) IsPublic() bool {
	if bytes.Compare(wallet.Version, PublicWalletVersion) == 0 {
		return true
	}

	return false
}

func (wallet *HDWallet) IsPrivate() bool {
	if bytes.Compare(wallet.Version, PrivateWalletVersion) == 0 {
		return true
	}

	return false
}
