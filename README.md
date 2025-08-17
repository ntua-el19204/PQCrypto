# PQCrypto
Integrate post quantum digital signatures in goLang crypto package

This work inspired by buyobuyo404 (https://github.com/buyobuyo404/PQCrypto/tree/master) who tried to add post quantum signatures to goLang's crypto package.

Since his work (3 years ago), I need to make some changes so that current crypto package can support post quantum signatures.

I changed the public key type to a slice of bytes, I used the newest function to generate keys and I made a test suite to test the signatures. 

To run the tests, go to the pqc file and apply go test.

## Example Usage

### Dilithium2 Example:
```go
package main

import (
	"crypto/pqc/dilithium/dilithium2"
	"fmt"
)

func main() {
	defer dilithium2.Cleanup()
	
	privateKey, err := dilithium2.GenerateKey()
	if err != nil {
		panic(err)
	}

	message := []byte("Sign this message")
	signature, err := privateKey.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey
	if publicKey.Verify(message, signature) {
		fmt.Println("Signature verification passed")
	} else {
		fmt.Println("Signature verification failed")
	}

	message2 := []byte("Sign this new message")
	signature2, err := privateKey.Sign(nil, message2, nil)
	if err != nil {
		panic(err)
	}

	if publicKey.Verify(message2, signature2) {
		fmt.Println("Signature verification passed")
	} else {
		fmt.Println("Signature verification failed")
	}
}