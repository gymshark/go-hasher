package hasher

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// HmacMd5 returns a new HMAC hash using md5.
func HmacMd5(data []byte, secret string) Hash {
	return mac(data, secret, md5.New)
}

// HmacSha1 returns a new HMAC hash using sha1.
func HmacSha1(data []byte, secret string) Hash {
	return mac(data, secret, sha1.New)
}

// HmacSha256 returns a new HMAC hash using sha256.
func HmacSha256(data []byte, secret string) Hash {
	return mac(data, secret, sha256.New)
}

// HmacSha512 returns a new HMAC hash using sha512.
func HmacSha512(data []byte, secret string) Hash {
	return mac(data, secret, sha512.New)
}

func mac(data []byte, secret string, a func() hash.Hash) Hash {
	h := hmac.New(a, []byte(secret))
	_, _ = h.Write(data)
	return h.Sum(nil)
}
