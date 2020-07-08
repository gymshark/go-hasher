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
	Base64 encoding = iota
	Base64UrlSafe
	Base32
	Hex
)

var strFuncs = [...]func([]byte) string{
	Base64:        base64.StdEncoding.EncodeToString,
	Base64UrlSafe: base64.URLEncoding.EncodeToString,
	Base32:        base32.StdEncoding.EncodeToString,
	Hex:           hex.EncodeToString,
}

func encode(b []byte, e encoding) (string, error) {
	if int(e) >= len(strFuncs) {
		return "", errors.New("unsupported encoding")
	}

	return strFuncs[e](b), nil
}
