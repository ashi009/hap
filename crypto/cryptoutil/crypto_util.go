package cryptoutil

import (
	"crypto/cipher"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a key from a secret, salt, and info.
func DeriveKey(secret []byte, salt, info string) []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, secret, []byte(salt), []byte(info)), key); err != nil {
		panic(err)
	}
	return key
}

func MustNewChacha20Poly1305(key []byte) cipher.AEAD {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead
}
