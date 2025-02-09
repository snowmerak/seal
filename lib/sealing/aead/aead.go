package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type Constructor func([]byte) (cipher.AEAD, error)

func NewAES256GCM(key []byte) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key length is less than 32 bytes")
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func NewAES192GCM(key []byte) (cipher.AEAD, error) {
	if len(key) < 24 {
		return nil, fmt.Errorf("key length is less than 64 bytes")
	}

	block, err := aes.NewCipher(key[:24])
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func NewAES128GCM(key []byte) (cipher.AEAD, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("key length is less than 16 bytes")
	}

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key length is less than 32 bytes")
	}

	return chacha20poly1305.New(key[:32])
}

func NewChaCha20Poly1305X(key []byte) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key length is less than 32 bytes")
	}

	return chacha20poly1305.NewX(key[:32])
}
