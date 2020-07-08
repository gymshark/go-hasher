// Copyright 2020 Gymshark Ltd.

// A hashing wrapper around some common hashing functions with customizable encoding
//
// Supported encodings
//
// Base64, Base64UrlSafe, Base32, Hex
//
// If an encoding is supplied that is not recognised an "unsupported encoding" error will be returned with
// an empty string in the hash value, so it is recommended to use the constants supplied with this package
package hasher

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"golang.org/x/crypto/sha3"
)

// Sha512 returns a sha2-512 checksum string
func Sha512(data []byte, e encoding) (string, error) {
	sum := sha512.Sum512(data)
	return encode(sum[:], e)
}

// Sha256 returns a sha2-256 checksum string
func Sha256(data []byte, e encoding) (string, error) {
	sum := sha256.Sum256(data)
	return encode(sum[:], e)
}

// Sha1 returns a sha1 checksum string
func Sha1(data []byte, e encoding) (string, error) {
	sum := sha1.Sum(data)
	return encode(sum[:], e)
}

// Sha3 returns a sha3-256 checksum string using the ShakeSum256 function
func Sha3(data []byte, e encoding) (string, error) {
	sum := make([]byte, 64)
	sha3.ShakeSum256(sum, data)
	return encode(sum, e)
}

// Md5 returns a md5 checksum string
func Md5(data []byte, e encoding) (string, error) {
	sum := md5.Sum(data)
	return encode(sum[:], e)
}

// Hmac returns a new HMAC hash using the given hash.Hash type and key.
func Hmac(data []byte, secret string, a func() hash.Hash, e encoding) (string, error) {
	h := hmac.New(a, []byte(secret))
	h.Write(data)
	return encode(h.Sum(nil), e)
}

// Equal compares two hashes for equality without leaking timing information.
func Equal(h1, h2 []byte) bool {
	return subtle.ConstantTimeCompare(h1, h2) == 1
}
