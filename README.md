# go-lib-eVESTX

`go-lib-crypto` is a unified crypto library for [VestXHybrid](https://vestxhybrid.com/).

This library meant to be used in client applications. That's why its API is relatively simple. 

The following could be done using the library:

* Calculation of a hash digest of various hash functions used by govrp
* Encoding and decoding of byte slices in BASE58 and BASE64 string representation
* Key pair generation from seed phrase
* GoVRP address generation and verification
* Random seed phrase generation and verification
* Signing of bytes message
* Verification of signed message

## Installation and import

```bash
go get -u github.com/eVESTXCOIN/go-lib-eVESTX
```
```go
import "github.com/eVESTXCOIN/go-lib-eVESTX"
```

## Short API reference with examples

### Instantiation

For the purpose of unification the API of the library made in form of the interface.
To instantiate the un-exported structure that implements the interface call the `NewVrpCrypto` function.

```go
crypto := vrpgo.NewVrpCrypto()
```

### Working with hashes

The three hash functions used by GoVRP are supported:

* SHA-256
* BLAKE2b-256
* Keccak-256 (legacy version)

Every hash functions accepts one parameter of type `Bytes`. The `Bytes` type wraps a slice of bytes.

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/eVESTXCOIN/go-lib-eVESTX"
)

func main() {
	bytes, _ := hex.DecodeString("fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989")
	c := vrpgo.NewVrpCrypto()
	blake := c.Blake2b(bytes)
	keccak := c.Keccak(bytes)
	sha := c.Sha256(bytes)
	fmt.Println("BLAKE2b-256:", hex.EncodeToString(blake))
	fmt.Println("Keccak-256:", hex.EncodeToString(keccak))
	fmt.Println("SHA-256:", hex.EncodeToString(sha))
}
```

The output should be like this:

```
BLAKE2b-256: c425f69e3be14c929d18b2808831cbaeb2733c9e6b9c5ed37c3601086f202396
Keccak-256: 14a0d0ee74865d8d721c4218768b7c39fd365b53f0359d6d28d82dc97450f583
SHA-256: 7ed1b5b6867c0d6c98097676adc00b6049882e473441ac5ff3613df48b69f9f3
```

### Seed and keys generation

One can create a new key pair from the seed phrase. Library defines types for `Seed`, `PrivateKey`, `PublicKey` (wrappers over `string`) and structure for `KeyPair` that combines the private and public keys.

The function `RandomSeed` creates a new random seed phrase of 15 words. The seed generation follows the [BIP39 standard](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). 

The keys generation functions `KeyPair`, `PublicKey` and `PrivateKey` accept the seed phrase as its parameters and produces a `KeyPair`, `PublicKey` or `PrivateKey` relatively. In latter two cases the whole key pair is produced, but only a part of it returned to the user.

```go
package main

import (
	"fmt"
	"github.com/eVESTXCOIN/go-lib-eVESTX"
)

func main() {
	c := vrpgo.NewVrpCrypto()
	seed := c.RandomSeed()
	fmt.Println("SEED:", seed)

	pair := c.KeyPair(seed)
	fmt.Println("PAIR:", "PRIVATE KEY:", pair.PrivateKey, "PUBLIC KEY:", pair.PublicKey)

	sk := c.PrivateKey(seed)
	fmt.Println("PRIVATE KEY:", sk)

	pk := c.PublicKey(seed)
	fmt.Println("PUBLIC KEY:", pk)
}
```

### eVESTX address generation

There is an `Address` type which wraps the string. An address could be created from `PublicKey` or `Seed` using functions `Address` or `AddressFromSeed`. In both cases the `VrpChainID` byte should be provided as second parameter. 
It is possible to verify the correctness of an Address string using functions `VerifyAddressChecksum` or `VerifyAddress`. The first function checks that the address has correct length and version and the built-in checksum is correct. The second one additionally checks that the address contains the correct `VrpChainID`.

```go
package main

import (
	"fmt"
	"github.com/eVESTXCOIN/go-lib-eVESTX"
)

func main() {
	c := vrpgo.NewVrpCrypto()
	seed := c.RandomSeed()
	fmt.Println("SEED:", seed)

	pair := c.KeyPair(seed)
	fmt.Println("PAIR:", "PRIVATE KEY:", pair.PrivateKey, "PUBLIC KEY:", pair.PublicKey)
	
	address := c.Address(pair.PublicKey, vrpgo.TestNet)
	fmt.Println("ADDRESS 1:", address)
	
	address2 := c.AddressFromSeed(seed, vrpgo.TestNet)
	fmt.Println("ADDRESS 2:", address2)
	
	fmt.Println("CHECKSUM OK:", c.VerifyAddressChecksum(address))
	fmt.Println("ADDRESS ON TESTNET OK:", c.VerifyAddress(address, vrpgo.TestNet))
	fmt.Println("ADDRESS ON MAINNET OK:", c.VerifyAddress(address, vrpgo.MainNet))
}
```

### Signing and verifying 

The library offers two functions to sign bytes (`SignBytes` and `SignBytesBySeed`) and one to verify a signature (`VerifySignature`). 


```go
package main

import (
	"fmt"
	"encoding/hex"
	"github.com/eVESTXCOIN/go-lib-eVESTX"
)

func main() {
	bytes, _ := hex.DecodeString("fd08be957bda07dc529ad8100df732f9ce12ae3e42bcda6acabe12c02dfd6989")
	other, _ := hex.DecodeString("54686520696e636f7272656374206d657373616765")

	c := vrpgo.NewVrpCrypto()
	seed := c.RandomSeed()
	fmt.Println("SEED:", seed)

	pair := c.KeyPair(seed)
	fmt.Println("PAIR:", "PRIVATE KEY:", pair.PrivateKey, "PUBLIC KEY:", pair.PublicKey)
	
	sig1 := c.SignBytes(bytes, pair.PrivateKey)
	fmt.Println("SIGNATURE 1:", hex.EncodeToString(sig1))
	sig2 := c.SignBytesBySeed(bytes, seed)
	fmt.Println("SIGNATURE 2:", hex.EncodeToString(sig2))
	
	fmt.Println("SIGNATURE 1 OK:", c.VerifySignature(pair.PublicKey, bytes, sig1))
	fmt.Println("SIGNATURE 2 OK:", c.VerifySignature(pair.PublicKey, bytes, sig2))

	fmt.Println("SIGNATURE 1 ON OTHER OK:", c.VerifySignature(pair.PublicKey, other, sig1))
	fmt.Println("SIGNATURE 2 ON OTHER OK:", c.VerifySignature(pair.PublicKey, other, sig2))
}
```

See more usage examples in the [crypto-test.go](https://github.com/eVESTXCOIN/go-lib-eVESTX/blob/master/crypto_test.go) file.