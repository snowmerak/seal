package cert

import (
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"lukechampine.com/blake3"
)

type MasterKey struct {
	privateKey *mlkem.DecapsulationKey1024
}

func MakeMasterKey(key string) (*MasterKey, error) {
	hashed := blake3.Sum512([]byte(key))

	dk, err := mlkem.NewDecapsulationKey1024(hashed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	return &MasterKey{privateKey: dk}, nil
}

func (mk *MasterKey) deriveCipher(w io.Writer) ([]byte, error) {
	if mk.privateKey == nil {
		return nil, masterKeyIsNotSetError
	}

	sk, ct := mk.privateKey.EncapsulationKey().Encapsulate()

	buf := [8]byte{}
	binary.BigEndian.PutUint64(buf[:8], uint64(len(ct)))
	if _, err := w.Write(buf[:8]); err != nil {
		return nil, fmt.Errorf("failed to write cipher text length: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return nil, fmt.Errorf("failed to write cipher text: %w", err)
	}

	return sk, nil
}

func (mk *MasterKey) readCipher(r io.Reader) ([]byte, error) {
	if mk.privateKey == nil {
		return nil, masterKeyIsNotSetError
	}

	buf := [8]byte{}
	if _, err := r.Read(buf[:8]); err != nil {
		return nil, fmt.Errorf("failed to read cipher text length: %w", err)
	}

	ct := make([]byte, binary.BigEndian.Uint64(buf[:8]))
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, fmt.Errorf("failed to read cipher text: %w", err)
	}

	sk, err := mk.privateKey.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	return sk, nil
}

func (mk *MasterKey) Encrypt(w io.Writer, r io.Reader, aeadCon func([]byte) (cipher.AEAD, error)) error {
	sk, err := mk.deriveCipher(w)
	if err != nil {
		return fmt.Errorf("failed to derive cipher: %w", err)
	}

	aead, err := aeadCon(sk)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	lengthBuf := [8]byte{}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	binary.BigEndian.PutUint64(lengthBuf[:8], uint64(len(nonce)))
	if _, err := w.Write(lengthBuf[:8]); err != nil {
		return fmt.Errorf("failed to write nonce length: %w", err)
	}
	if _, err := w.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	dataBuf := [4096]byte{}
	for {
		n, err := r.Read(dataBuf[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read: %w", err)
		}

		encrypted := aead.Seal(nil, nonce, dataBuf[:n], nil)
		binary.BigEndian.PutUint64(lengthBuf[:8], uint64(len(encrypted)))
		if _, err := w.Write(lengthBuf[:8]); err != nil {
			return fmt.Errorf("failed to write length: %w", err)
		}
		if _, err := w.Write(encrypted); err != nil {
			return fmt.Errorf("failed to write: %w", err)
		}

		nonce[0]++
	}

	return nil
}

func (mk *MasterKey) Decrypt(w io.Writer, r io.Reader, aeadCon func([]byte) (cipher.AEAD, error)) error {
	sk, err := mk.readCipher(r)
	if err != nil {
		return fmt.Errorf("failed to read cipher: %w", err)
	}

	aead, err := aeadCon(sk)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	lengthBuf := [8]byte{}
	if _, err := r.Read(lengthBuf[:8]); err != nil {
		return fmt.Errorf("failed to read nonce length: %w", err)
	}

	nonce := make([]byte, binary.BigEndian.Uint64(lengthBuf[:8]))
	if _, err := io.ReadFull(r, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	dataBuf := make([]byte, 4096)
loop:
	for {
		if _, err := r.Read(lengthBuf[:8]); err != nil {
			if err == io.EOF {
				break loop
			}
			return fmt.Errorf("failed to read length: %w", err)
		}

		length := binary.BigEndian.Uint64(lengthBuf[:8])
		if uint64(len(dataBuf)) < length {
			dataBuf = make([]byte, length)
		}
		if _, err := io.ReadFull(r, dataBuf[:length]); err != nil {
			return fmt.Errorf("failed to read: %w", err)
		}

		decrypted, err := aead.Open(nil, nonce, dataBuf[:length], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}

		if _, err := w.Write(decrypted); err != nil {
			return fmt.Errorf("failed to write: %w", err)
		}

		nonce[0]++
	}

	return nil
}
