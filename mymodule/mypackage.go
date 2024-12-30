package mymodule

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

func Encrypt(byte_text []byte, byte_key []byte) ([]byte, error) {
	c, err := aes.NewCipher(byte_key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}

	enc_byte_text := gcm.Seal(nonce, nonce, byte_text, nil)

	return enc_byte_text, nil
}

func Decrypt(byte_text []byte, byte_key []byte) ([]byte, error) {
	c, err := aes.NewCipher(byte_key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(byte_text) < nonceSize {
		return nil, fmt.Errorf("[!] Ciphertext is too short")
	}

	nonce, text := byte_text[:nonceSize], byte_text[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("[!] Decryption failed: %v", err)
	}

	return plaintext, nil
}

func Hash256(password string) []byte {
	// Hashing function 32 bytes
	pass := sha256.New()
	pass.Write([]byte(password))
	hash := pass.Sum(nil)
	return hash
}

func Hash512(password string) string {
	// Hashing function 64 bytes
	pass := sha512.New()
	pass.Write([]byte(password))
	hash := pass.Sum(nil)
	return string(hash)
}
