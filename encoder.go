// Copyright 2020 Gymshark Ltd.

package hasher

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

type encoding int

const (
	// encoding type helpers
	Base64 encoding = iota
	Base64UrlSafe
	Base32
	Hex
)

type strFn func([]byte) string

var (
	strFns = [...]strFn{
		Base64:        base64.StdEncoding.EncodeToString,
		Base64UrlSafe: base64.URLEncoding.EncodeToString,
		Base32:        base32.StdEncoding.EncodeToString,
		Hex:           hex.EncodeToString,
	}

	// Errors returned by encoding functions
	ErrUnsupportedEncoding = errors.New("unsupported encoding")
)

func encode(b []byte, e encoding) (string, error) {
	if int(e) >= len(strFns) {
		return "", ErrUnsupportedEncoding
	}

	return strFns[e](b), nil
}
