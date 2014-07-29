package bip32_test

import (
	"bip32"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBip32TestVectors(t *testing.T) {
	vector1Seed := "000102030405060708090a0b0c0d0e0f"

	seed, _ := hex.DecodeString(vector1Seed)
	privWallet, _ := bip32.NewExtendedKey(seed)
	pubWallet := privWallet.Neuter()

	// m
	assert.Equal(t, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", privWallet.String())
	assert.Equal(t, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", pubWallet.String())
}
