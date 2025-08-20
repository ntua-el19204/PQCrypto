package main

import (
	"crypto"
	"testing"

	"crypto/pqc/dilithium/dilithium2"
	"crypto/pqc/dilithium/dilithium3"
	"crypto/pqc/dilithium/dilithium5"
	"crypto/pqc/falcon/falcon1024"
	"crypto/pqc/falcon/falcon512"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

func TestDilithium2SignVerify(t *testing.T) {
	defer dilithium2.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium2.GenerateKey()

	message := []byte("test message")
	sig, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if publicKey.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestDilithium3SignVerify(t *testing.T) {
	defer dilithium3.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium3.GenerateKey()

	message := []byte("test message")
	sig, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if publicKey.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestDilithium5SignVerify(t *testing.T) {
	defer dilithium5.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium5.GenerateKey()

	message := []byte("test message")
	sig, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if publicKey.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestFalcon512SignVerify(t *testing.T) {
	defer falcon512.Cleanup()
	var zero zeroReader
	privateKey, _ := falcon512.GenerateKey()

	message := []byte("test message")
	sig, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if publicKey.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestFalcon1024SignVerify(t *testing.T) {
	defer falcon1024.Cleanup()
	var zero zeroReader
	privateKey, _ := falcon1024.GenerateKey()

	message := []byte("test message")
	sig, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if publicKey.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestDilithium2CryptoSigner(t *testing.T) {
	defer dilithium2.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium2.GenerateKey()

	signer := crypto.Signer(privateKey)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(dilithium2.PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if len(public2) != dilithium2.PublicKeySize {
		t.Errorf("public key size mismatch")
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestDilithium3CryptoSigner(t *testing.T) {
	defer dilithium3.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium3.GenerateKey()

	signer := crypto.Signer(privateKey)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(dilithium3.PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if len(public2) != dilithium3.PublicKeySize {
		t.Errorf("public key size mismatch")
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestDilithium5CryptoSigner(t *testing.T) {
	defer dilithium5.Cleanup()
	var zero zeroReader
	privateKey, _ := dilithium5.GenerateKey()

	signer := crypto.Signer(privateKey)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(dilithium5.PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if len(public2) != dilithium5.PublicKeySize {
		t.Errorf("public key size mismatch")
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestFalcon512CryptoSigner(t *testing.T) {
	defer falcon512.Cleanup()
	var zero zeroReader
	privateKey, _ := falcon512.GenerateKey()

	signer := crypto.Signer(privateKey)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(falcon512.PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if len(public2) != falcon512.PublicKeySize {
		t.Errorf("public key size mismatch")
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestFalcon1024CryptoSigner(t *testing.T) {
	defer falcon1024.Cleanup()
	var zero zeroReader
	privateKey, _ := falcon1024.GenerateKey()

	signer := crypto.Signer(privateKey)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(falcon1024.PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if len(public2) != falcon1024.PublicKeySize {
		t.Errorf("public key size mismatch")
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	publicKey := privateKey.PublicKey
	if !publicKey.Verify(message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestDilithium2Equal(t *testing.T) {
	defer dilithium2.Cleanup()
	privateKey1, _ := dilithium2.GenerateKey()
	privateKey2, _ := dilithium2.GenerateKey()
	public1 := privateKey1.PublicKey
	public2 := privateKey2.PublicKey

	if !public1.Equal(public1) {
		t.Errorf("public key is not equal to itself")
	}
	if !public1.Equal(crypto.Signer(privateKey1).Public()) {
		t.Errorf("private.Public() is not Equal to public")
	}

	if public1.Equal(public2) {
		t.Errorf("different public keys are Equal")
	}
}

func TestDilithium3Equal(t *testing.T) {
	defer dilithium3.Cleanup()
	privateKey1, _ := dilithium3.GenerateKey()
	privateKey2, _ := dilithium3.GenerateKey()
	public1 := privateKey1.PublicKey
	public2 := privateKey2.PublicKey

	if !public1.Equal(public1) {
		t.Errorf("public key is not equal to itself")
	}
	if !public1.Equal(crypto.Signer(privateKey1).Public()) {
		t.Errorf("private.Public() is not Equal to public")
	}

	if public1.Equal(public2) {
		t.Errorf("different public keys are Equal")
	}
}

func TestDilithium5Equal(t *testing.T) {
	defer dilithium5.Cleanup()
	privateKey1, _ := dilithium5.GenerateKey()
	privateKey2, _ := dilithium5.GenerateKey()
	public1 := privateKey1.PublicKey
	public2 := privateKey2.PublicKey

	if !public1.Equal(public1) {
		t.Errorf("public key is not equal to itself")
	}
	if !public1.Equal(crypto.Signer(privateKey1).Public()) {
		t.Errorf("private.Public() is not Equal to public")
	}

	if public1.Equal(public2) {
		t.Errorf("different public keys are Equal")
	}
}

func TestFalcon512Equal(t *testing.T) {
	defer falcon512.Cleanup()
	privateKey1, _ := falcon512.GenerateKey()
	privateKey2, _ := falcon512.GenerateKey()
	public1 := privateKey1.PublicKey
	public2 := privateKey2.PublicKey

	if !public1.Equal(public1) {
		t.Errorf("public key is not equal to itself")
	}
	if !public1.Equal(crypto.Signer(privateKey1).Public()) {
		t.Errorf("private.Public() is not Equal to public")
	}

	if public1.Equal(public2) {
		t.Errorf("different public keys are Equal")
	}
}

func TestFalcon1024Equal(t *testing.T) {
	defer falcon1024.Cleanup()
	privateKey1, _ := falcon1024.GenerateKey()
	privateKey2, _ := falcon1024.GenerateKey()
	public1 := privateKey1.PublicKey
	public2 := privateKey2.PublicKey

	if !public1.Equal(public1) {
		t.Errorf("public key is not equal to itself")
	}
	if !public1.Equal(crypto.Signer(privateKey1).Public()) {
		t.Errorf("private.Public() is not Equal to public")
	}

	if public1.Equal(public2) {
		t.Errorf("different public keys are Equal")
	}
}

func BenchmarkDilithium2KeyGeneration(b *testing.B) {
	defer dilithium2.Cleanup()
	for i := 0; i < b.N; i++ {
		if _, err := dilithium2.GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDilithium2Signing(b *testing.B) {
	defer dilithium2.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privateKey.Sign(zero, message, nil)
	}
}

func BenchmarkDilithium2Verification(b *testing.B) {
	defer dilithium2.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey.Verify(message, signature)
	}
}

func BenchmarkDilithium3KeyGeneration(b *testing.B) {
	defer dilithium3.Cleanup()
	for i := 0; i < b.N; i++ {
		if _, err := dilithium3.GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDilithium3Signing(b *testing.B) {
	defer dilithium3.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium3.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privateKey.Sign(zero, message, nil)
	}
}

func BenchmarkDilithium3Verification(b *testing.B) {
	defer dilithium3.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium3.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey.Verify(message, signature)
	}
}

func BenchmarkDilithium5KeyGeneration(b *testing.B) {
	defer dilithium5.Cleanup()
	for i := 0; i < b.N; i++ {
		if _, err := dilithium5.GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDilithium5Signing(b *testing.B) {
	defer dilithium5.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium5.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privateKey.Sign(zero, message, nil)
	}
}

func BenchmarkDilithium5Verification(b *testing.B) {
	defer dilithium5.Cleanup()
	var zero zeroReader
	privateKey, err := dilithium5.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey.Verify(message, signature)
	}
}

func BenchmarkFalcon512KeyGeneration(b *testing.B) {
	defer falcon512.Cleanup()
	for i := 0; i < b.N; i++ {
		if _, err := falcon512.GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFalcon512Signing(b *testing.B) {
	defer falcon512.Cleanup()
	var zero zeroReader
	privateKey, err := falcon512.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privateKey.Sign(zero, message, nil)
	}
}

func BenchmarkFalcon512Verification(b *testing.B) {
	defer falcon512.Cleanup()
	var zero zeroReader
	privateKey, err := falcon512.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey.Verify(message, signature)
	}
}

func BenchmarkFalcon1024KeyGeneration(b *testing.B) {
	defer falcon1024.Cleanup()
	for i := 0; i < b.N; i++ {
		if _, err := falcon1024.GenerateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFalcon1024Signing(b *testing.B) {
	defer falcon1024.Cleanup()
	var zero zeroReader
	privateKey, err := falcon1024.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privateKey.Sign(zero, message, nil)
	}
}

func BenchmarkFalcon1024Verification(b *testing.B) {
	defer falcon1024.Cleanup()
	var zero zeroReader
	privateKey, err := falcon1024.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, _ := privateKey.Sign(zero, message, nil)
	publicKey := privateKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey.Verify(message, signature)
	}
}
