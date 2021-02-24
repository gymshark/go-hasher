package hasher

type Hash []byte

func (h Hash) to(e encoding) (string, error) {
	return encode(h, e)
}

// Base64 returns a string representation of the hash in base64 encoding
func (h Hash) Base64() (string, error) {
	return h.to(Base64)
}

// Base64UrlSafe returns a string representation of the hash in Base64UrlSafe encoding
func (h Hash) Base64UrlSafe() (string, error) {
	return h.to(Base64UrlSafe)
}

// Hex returns a string representation of the hash in Hex (base16) encoding
func (h Hash) Hex() (string, error) {
	return h.to(Hex)
}

// Base32 returns a string representation of the hash in base32 encoding
func (h Hash) Base32() (string, error) {
	return h.to(Base32)
}
