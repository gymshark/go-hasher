package hasher

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
)

type Hash []byte

func encode(b []byte, fn func(src []byte) string) string {
	return fn(b)
}

// Encode allows users to pass their own custom stringer func
func (h Hash) Encode(fn func(src []byte) string) string {
	return encode(h, fn)
}

// Base64 returns a string representation of the hash in base64 encoding
func (h Hash) Base64() string {
	return encode(h, base64.StdEncoding.EncodeToString)
}

// Base64UrlSafe returns a string representation of the hash in Base64UrlSafe encoding
func (h Hash) Base64UrlSafe() string {
	return encode(h, base64.URLEncoding.EncodeToString)
}

// Hex returns a string representation of the hash in Hex (base16) encoding
func (h Hash) Hex() string {
	return encode(h, hex.EncodeToString)
}

// Base32 returns a string representation of the hash in base32 encoding
func (h Hash) Base32() string {
	return encode(h, base32.StdEncoding.EncodeToString)
}
