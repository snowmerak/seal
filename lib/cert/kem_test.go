package cert_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/snowmerak/seal/lib/cert"
)

func TestMasterKey(t *testing.T) {
	const password = "nzsNs2zqxM4SlsfI3MlaQ3QTYM1sEgbpPUv4"

	mk, err := cert.MakeMasterKey(password)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 6<<20) // 6 MiB
	rand.Read(data)

	encrypted := bytes.NewBuffer(nil)
	if err := mk.Encrypt(encrypted, bytes.NewReader(data), func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	}); err != nil {
		t.Fatal(err)
	}

	mk, err = cert.MakeMasterKey(password)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := bytes.NewBuffer(nil)
	if err := mk.Decrypt(decrypted, bytes.NewReader(encrypted.Bytes()), func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Fatal("decrypted data does not match original data")
	}
}
