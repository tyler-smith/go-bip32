package bip32

import (
  // "fmt"
  // "crypto/rand"
  "crypto/hmac"
  "crypto/sha512"
  "encoding/binary"
  "bytes"
  "encoding/hex"
)

// var curve elliptic.Curve = btcutil.Secp256k1()

var PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
var PublicWalletVersion, _ = hex.DecodeString("0488B21E")
var MaxPrivateKey, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

type HDWallet struct {
  Version []byte
  Depth byte
  ChildNumber []byte
  FingerPrint []byte
  ChainCode []byte
  Key Key
}

func NewHDWallet(seed *Seed) (*HDWallet) {
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

  return &HDWallet{
    Version: PrivateWalletVersion,
    ChainCode: chainCodeCandidate,
    Key: Key(keyCandidate),
  }
}

func (wallet *HDWallet) PublicWallet() *HDWallet {
  key := wallet.Key

  if wallet.IsPrivate() {
    key = key.ToPublicKey()
  }

  return &HDWallet{
    Version: PublicWalletVersion,
    Depth: wallet.Depth,
    ChildNumber: wallet.ChildNumber,
    FingerPrint: wallet.FingerPrint,
    ChainCode: wallet.ChainCode,
    Key: key,
  }
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
