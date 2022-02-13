package bip32

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testMasterKey struct {
	seed     string
	children []testChildKey
	privKey  string
	pubKey   string
}

type testChildKey struct {
	pathFragment uint32
	privKey      string
	pubKey       string
	hexPubKey    string
}

func TestBip32TestVectors_Bitcoin(t *testing.T) {
	hStart := FirstHardenedChild

	vector1 := testMasterKey{
		seed:    "000102030405060708090a0b0c0d0e0f",
		privKey: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		pubKey:  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		children: []testChildKey{
			{
				pathFragment: hStart,
				privKey:      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
				pubKey:       "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
			},
			{
				pathFragment: 1,
				privKey:      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
				pubKey:       "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
			},
			{
				pathFragment: 2 + hStart,
				privKey:      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
				pubKey:       "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			},
			{
				pathFragment: 2,
				privKey:      "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
				pubKey:       "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
			},
			{
				pathFragment: 1000000000,
				privKey:      "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
				pubKey:       "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
			},
		},
	}

	vector2 := testMasterKey{
		seed:    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		privKey: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
		pubKey:  "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		children: []testChildKey{
			{
				pathFragment: 0,
				privKey:      "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
				pubKey:       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
			},
			{
				pathFragment: 2147483647 + hStart,
				privKey:      "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
				pubKey:       "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
			},
			{
				pathFragment: 1,
				privKey:      "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
				pubKey:       "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
			},
			{
				pathFragment: 2147483646 + hStart,
				privKey:      "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
				pubKey:       "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
			},
			{
				pathFragment: 2,
				privKey:      "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
				pubKey:       "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
			},
		},
	}

	vector3 := testMasterKey{
		seed:    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
		privKey: "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
		pubKey:  "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
		children: []testChildKey{
			{
				pathFragment: hStart + 0,
				privKey:      "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
				pubKey:       "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
			},
		},
	}

	testVectorKeyPairs(t, vector1, Bitcoin)
	testVectorKeyPairs(t, vector2, Bitcoin)
	testVectorKeyPairs(t, vector3, Bitcoin)
}

func testVectorKeyPairs(t *testing.T, vector testMasterKey, curve Curve) {
	t.Helper()

	// Decode master seed into hex
	seed, _ := hex.DecodeString(vector.seed)

	// Generate a master private and public key
	privKey, err := NewMasterKeyWithCurve(seed, curve)
	assert.NoError(t, err)

	pubKey := privKey.PublicKey()

	assert.Equal(t, vector.privKey, privKey.String())
	assert.Equal(t, vector.pubKey, pubKey.String())

	// Iterate over the entire child chain and test the given keys
	for _, testChildKey := range vector.children {
		// Get the private key at the given key tree path
		privKey, err = privKey.NewChildKey(testChildKey.pathFragment)
		assert.NoError(t, err)

		// Get this private key's public key
		pubKey = privKey.PublicKey()

		// Assert correctness
		assert.Equal(t, testChildKey.privKey, privKey.String())
		assert.Equal(t, testChildKey.pubKey, pubKey.String())

		// Serialize and deserialize both keys and ensure they're the same
		assertKeySerialization(t, privKey, testChildKey.privKey)
		assertKeySerialization(t, pubKey, testChildKey.pubKey)
	}
}

type testKeyHex struct {
	fingerPrint string
	chainCode   string
	privateKey  string
	publicKey   string
}

func (tk *testKeyHex) Assert(t *testing.T, key *Key) {
	t.Helper()

	fingerPrint, _ := hex.DecodeString(tk.fingerPrint)
	assert.Equal(t, fingerPrint, key.FingerPrint, "finger print")

	chainCode, _ := hex.DecodeString(tk.chainCode)
	assert.Equal(t, chainCode, key.ChainCode, "chain code")

	privateKey, _ := hex.DecodeString(tk.privateKey)
	assert.Equal(t, privateKey, key.Key, "private key")

	publicKey, _ := hex.DecodeString(tk.publicKey)
	assert.Equal(t, publicKey, key.PublicKey().Key, "public key")
}

type testVector struct {
	path  uint32
	key   testKeyHex
	child *testVector
}

func TestBip32TestVectors_Ed25519(t *testing.T) {
	cases := []struct {
		seed   string
		vector testVector
	}{
		// https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			vector: testVector{
				key: testKeyHex{
					fingerPrint: "00000000",
					chainCode:   "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
					privateKey:  "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
					publicKey:   "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
				},
				child: &testVector{
					path: 0,
					key: testKeyHex{
						fingerPrint: "ddebc675",
						chainCode:   "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
						privateKey:  "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
						publicKey:   "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
					},
					child: &testVector{
						path: 1,
						key: testKeyHex{
							fingerPrint: "13dab143",
							chainCode:   "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
							privateKey:  "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
							publicKey:   "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
						},
						child: &testVector{
							path: 2,
							key: testKeyHex{
								fingerPrint: "ebe4cb29",
								chainCode:   "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
								privateKey:  "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
								publicKey:   "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
							},
							child: &testVector{
								path: 2,
								key: testKeyHex{
									fingerPrint: "316ec1c6",
									chainCode:   "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
									privateKey:  "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
									publicKey:   "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
								},
								child: &testVector{
									path: 1000000000,
									key: testKeyHex{
										fingerPrint: "d6322ccd",
										chainCode:   "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
										privateKey:  "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
										publicKey:   "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
									},
								},
							},
						},
					},
				},
			},
		},
		// https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			vector: testVector{
				key: testKeyHex{
					fingerPrint: "00000000",
					chainCode:   "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
					privateKey:  "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
					publicKey:   "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
				},
				child: &testVector{
					path: 0,
					key: testKeyHex{
						fingerPrint: "31981b50",
						chainCode:   "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
						privateKey:  "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
						publicKey:   "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
					},
					child: &testVector{
						path: 2147483647,
						key: testKeyHex{
							fingerPrint: "1e9411b1",
							chainCode:   "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
							privateKey:  "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
							publicKey:   "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
						},
						child: &testVector{
							path: 1,
							key: testKeyHex{
								fingerPrint: "fcadf38c",
								chainCode:   "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
								privateKey:  "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
								publicKey:   "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
							},
							child: &testVector{
								path: 2147483646,
								key: testKeyHex{
									fingerPrint: "aca70953",
									chainCode:   "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
									privateKey:  "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
									publicKey:   "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
								},
								child: &testVector{
									path: 2,
									key: testKeyHex{
										fingerPrint: "422c654b",
										chainCode:   "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
										privateKey:  "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
										publicKey:   "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.seed, func(t *testing.T) {
			seed, _ := hex.DecodeString(c.seed)

			masterKey, err := NewMasterKeyWithCurve(seed, Ed25519)
			require.NoError(t, err)

			c.vector.key.Assert(t, masterKey)

			key := masterKey

			path := "m"

			tc := c.vector.child
			for tc != nil {
				var err error
				path += fmt.Sprintf("/%d", tc.path)
				t.Run(path, func(t *testing.T) {
					key, err = key.NewChildKey(tc.path)
					require.NoError(t, err)

					tc.key.Assert(t, key)
				})

				tc = tc.child
			}
		})
	}
}

func TestPublicParentPublicChildDerivation(t *testing.T) {
	// Generated using https://iancoleman.io/bip39/
	// Root key:
	// xprv9s21ZrQH143K2Cfj4mDZBcEecBmJmawReGwwoAou2zZzG45bM6cFPJSvobVTCB55L6Ld2y8RzC61CpvadeAnhws3CHsMFhNjozBKGNgucYm
	// Derivation Path m/44'/60'/0'/0:
	// xprv9zy5o7z1GMmYdaeQdmabWFhUf52Ytbpe3G5hduA4SghboqWe7aDGWseN8BJy1GU72wPjkCbBE1hvbXYqpCecAYdaivxjNnBoSNxwYD4wHpW
	// xpub6DxSCdWu6jKqr4isjo7bsPeDD6s3J4YVQV1JSHZg12Eagdqnf7XX4fxqyW2sLhUoFWutL7tAELU2LiGZrEXtjVbvYptvTX5Eoa4Mamdjm9u
	extendedMasterPublic, err := B58Deserialize("xpub6DxSCdWu6jKqr4isjo7bsPeDD6s3J4YVQV1JSHZg12Eagdqnf7XX4fxqyW2sLhUoFWutL7tAELU2LiGZrEXtjVbvYptvTX5Eoa4Mamdjm9u")
	assert.NoError(t, err)

	expectedChildren := []testChildKey{
		{pathFragment: 0, hexPubKey: "0243187e1a2ba9ba824f5f81090650c8f4faa82b7baf93060d10b81f4b705afd46"},
		{pathFragment: 1, hexPubKey: "023790d11eb715c4320d8e31fba3a09b700051dc2cdbcce03f44b11c274d1e220b"},
		{pathFragment: 2, hexPubKey: "0302c5749c3c75cea234878ae3f4d8f65b75d584bcd7ed0943b016d6f6b59a2bad"},
		{pathFragment: 3, hexPubKey: "03f0440c94e5b14ea5b15875934597afff541bec287c6e65dc1102cafc07f69699"},
		{pathFragment: 4, hexPubKey: "026419d0d8996707605508ac44c5871edc7fe206a79ef615b74f2eea09c5852e2b"},
		{pathFragment: 5, hexPubKey: "02f63c6f195eea98bdb163c4a094260dea71d264b21234bed4df3899236e6c2298"},
		{pathFragment: 6, hexPubKey: "02d74709cd522081064858f393d009ead5a0ecd43ede3a1f57befcc942025cb5f9"},
		{pathFragment: 7, hexPubKey: "03e54bb92630c943d38bbd8a4a2e65fca7605e672d30a0e545a7198cbb60729ceb"},
		{pathFragment: 8, hexPubKey: "027e9d5acd14d39c4938697fba388cd2e8f31fc1c5dc02fafb93a10a280de85199"},
		{pathFragment: 9, hexPubKey: "02a167a9f0d57468fb6abf2f3f7967e2cadf574314753a06a9ef29bc76c54638d2"},

		{pathFragment: 100, hexPubKey: "020db9ba00ddf68428e3f5bfe54252bbcd75b21e42f51bf3bfc4172bf0e5fa7905"},
		{pathFragment: 101, hexPubKey: "0299e3790956570737d6164e6fcda5a3daa304065ca95ba46bc73d436b84f34d46"},
		{pathFragment: 102, hexPubKey: "0202e0732c4c5d2b1036af173640e01957998cfd4f9cdaefab6ffe76eb869e2c59"},
		{pathFragment: 103, hexPubKey: "03d050adbd996c0c5d737ff638402dfbb8c08e451fef10e6d62fb57887c1ac6cb2"},
		{pathFragment: 104, hexPubKey: "038d466399e2d68b4b16043ad4d88893b3b2f84fc443368729a973df1e66f4f530"},
		{pathFragment: 105, hexPubKey: "034811e2f0c8c50440c08c2c9799b99c911c036e877e8325386ff61723ae3ffdce"},
		{pathFragment: 106, hexPubKey: "026339fd5842921888e711a6ba9104a5f0c94cc0569855273cf5faefdfbcd3cc29"},
		{pathFragment: 107, hexPubKey: "02833705c1069fab2aa92c6b0dac27807290d72e9f52378d493ac44849ca003b22"},
		{pathFragment: 108, hexPubKey: "032d2639bde1eb7bdf8444bd4f6cc26a9d1bdecd8ea15fac3b992c3da68d9d1df5"},
		{pathFragment: 109, hexPubKey: "02479c6d4a64b93a2f4343aa862c938fbc658c99219dd7bebb4830307cbd76c9e9"},
	}

	for _, child := range expectedChildren {
		pubKey, err := extendedMasterPublic.NewChildKey(child.pathFragment)
		assert.NoError(t, err)
		assert.False(t, pubKey.IsPrivate)
		assert.Equal(t, child.hexPubKey, hex.EncodeToString(pubKey.Key))
	}
}

func TestNewSeed(t *testing.T) {
	for i := 0; i < 20; i++ {
		seed, err := NewSeed()
		assert.NoError(t, err)
		assert.Equal(t, 256, len(seed))
	}
}

func TestB58SerializeUnserialize(t *testing.T) {
	tests := []struct {
		seed   []byte
		base58 string
	}{
		{[]byte{}, "xprv9s21ZrQH143K4YUcKrp6cVxQaX59ZFkN6MFdeZjt8CHVYNs55xxQSvZpHWfojWMv6zgjmzopCyWPSFAnV4RU33J4pwCcnhsB4R4mPEnTsMC"},
		{[]byte{1}, "xprv9s21ZrQH143K3YSbAXLMPCzJso5QAarQksAGc5rQCyZCBfw4Rj2PqVLFNgezSBhktYkiL3Ta2stLPDF9yZtLMaxk6Spiqh3DNFG8p8MVeEC"},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, "xprv9s21ZrQH143K2hKT3jMKPFEcQLbx2XD55NtqQA7B4C5U9mTZY7gBeCdoFgurN4pxkQshzP8AQhBmUNgAo5djj5FzvUFh5pKH6wcRMSXVuc1"},
	}

	for _, test := range tests {
		key, err := NewMasterKey(test.seed)
		assert.NoError(t, err)
		assertKeySerialization(t, key, test.base58)
	}
}

func TestDeserializingInvalidStrings(t *testing.T) {
	tests := []struct {
		err    error
		base58 string
	}{
		{ErrSerializedKeyWrongSize, "xprv9s21ZrQH143K4YUcKrp6cVxQaX59ZFkN6MFdeZjt8CHVYNs55xxQSvZpHWfojWMv6zgjmzopCyWPSFAnV4RU33J4pwCcnhsB4R4mPEnTsM"},
		{ErrInvalidChecksum, "xprv9s21ZrQH143K3YSbAXLMPCzJso5QAarQksAGc5rQCyZCBfw4Rj2PqVLFNgezSBhktYkiL3Ta2stLPDF9yZtLMaxk6Spiqh3DNFG8p8MVeEc"},
	}

	for _, test := range tests {
		_, err := B58Deserialize(test.base58)
		assert.Equal(t, test.err, err)
	}

	_, err := B58Deserialize("notbase58iiiiiIIIIIbAXLMPCzJso5QAarQksAGc5rQCyZCBfw4Rj2PqVLFNgezSBhktYkiL3Ta2stLPDF9yZtLMaxk6Spiqh3DNFG8p8MVeEc")
	assert.NotNil(t, err)
}

func TestCantCreateHardenedPublicChild(t *testing.T) {
	key, err := NewMasterKey([]byte{})
	assert.NoError(t, err)

	// Test that it works for private keys
	_, err = key.NewChildKey(FirstHardenedChild - 1)
	assert.NoError(t, err)
	_, err = key.NewChildKey(FirstHardenedChild)
	assert.NoError(t, err)
	_, err = key.NewChildKey(FirstHardenedChild + 1)
	assert.NoError(t, err)

	// Test that it throws an error for public keys if hardened
	key = key.PublicKey()

	_, err = key.NewChildKey(FirstHardenedChild - 1)
	assert.NoError(t, err)
	_, err = key.NewChildKey(FirstHardenedChild)
	assert.Equal(t, ErrHardnedChildPublicKey, err)
	_, err = key.NewChildKey(FirstHardenedChild + 1)
	assert.Equal(t, ErrHardnedChildPublicKey, err)
}

func assertKeySerialization(t *testing.T, key *Key, knownBase58 string) {
	serializedBase58 := key.B58Serialize()
	assert.Equal(t, knownBase58, serializedBase58)

	unserializedBase58, err := B58Deserialize(serializedBase58)
	assert.NoError(t, err)
	assert.Equal(t, key, unserializedBase58)
}
