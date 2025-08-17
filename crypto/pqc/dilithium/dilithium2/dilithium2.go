package dilithium2

import (
	"crypto"
	"crypto/liboqs-go/oqs"
	"crypto/subtle"
	"io"
	"log"
)

var signer = oqs.Signature{}
var verifier = oqs.Signature{}

const (
	sigName        = "Dilithium2"
	PublicKeySize  = 1312
	PrivateKeySize = 2528
)

type PublicKey []byte

type PrivateKey struct {
	PublicKey
	Sk []byte
}

func GenerateKey() (*PrivateKey, error) {

	//defer signer.Clean()

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	pk, err := signer.GenerateKeyPair()
	sk := signer.ExportSecretKey()

	privateKey := new(PrivateKey)

	privateKey.PublicKey = pk
	privateKey.Sk = sk

	return privateKey, err
}

// func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error)
func (priv *PrivateKey) SignPQC(msg []byte) (sig []byte, err error) {
	//defer signer.Clean()

	if err := signer.Init(sigName, priv.Sk); err != nil {
		log.Fatal(err)
	}

	sign, err := signer.Sign(msg)

	return sign, err
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignPQC(digest)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey
}

// func (pub *PublicKey) Verify(msg []byte, sig []byte) bool
func (pub PublicKey) Verify(msg []byte, signature []byte) bool {
	return Verify(pub, msg, signature)
}

func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pub, xx) == 1
}

func Verify(pubkey PublicKey, msg, signature []byte) bool {

	//defer verifier.Clean()

	if err := verifier.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	isValid, err := verifier.Verify(msg, signature, pubkey)
	if err != nil {
		log.Fatal(err)
	}

	return isValid
}

// cleanup functions
func Cleanup() {
	signer.Clean()
	verifier.Clean()
}

func CleanupSigner() {
	signer.Clean()
}

func CleanupVerifier() {
	verifier.Clean()
}
