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
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

// Sha512 returns a sha2-512 checksum
func Sha512(data []byte) Hash {
	sum := sha512.Sum512(data)
	return sum[:]
}

// Sha256 returns a sha2-256 checksum
func Sha256(data []byte) Hash {
	sum := sha256.Sum256(data)
	return sum[:]
}

// Sha1 returns a sha1 checksum
func Sha1(data []byte) Hash {
	sum := sha1.Sum(data)
	return sum[:]
}

// Sha3 returns a sha3-256 checksum using the ShakeSum256 function
func Sha3(data []byte) Hash {
	sum := make([]byte, 64)
	sha3.ShakeSum256(sum, data)
	return sum
}

// Md5 returns a md5 checksum
func Md5(data []byte) Hash {
	sum := md5.Sum(data)
	return sum[:]
}

// Equal compares two hashes for equality without leaking timing information.
func Equal(h1, h2 []byte) bool {
	return subtle.ConstantTimeCompare(h1, h2) == 1
}
