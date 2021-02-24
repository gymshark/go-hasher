package hasher

import (
	"testing"
)

type hashTest struct {
	name          string
	raw           string
	base64        string
	base64UrlSafe string
	base32        string
	hex           string
}

var hashTests = []hashTest{
	{
		"text",
		"Before software can be reusable it first has to be usable.",
		"QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg==",
		"QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg==",
		"IJSWM33SMUQHG33GOR3WC4TFEBRWC3RAMJSSA4TFOVZWCYTMMUQGS5BAMZUXE43UEBUGC4ZAORXSAYTFEB2XGYLCNRSS4===",
		"4265666f726520736f6674776172652063616e206265207265757361626c652069742066697273742068617320746f20626520757361626c652e",
	},
	/// RFC 3548 examples
	{
		"bytes",
		"\x14\xfb\x9c\x03\xd9\x7e",
		"FPucA9l+",
		"FPucA9l-",
		"CT5ZYA6ZPY======",
		"14fb9c03d97e",
	},
	{
		"bytes-2",
		"\x14\xfb\x9c\x03\xd9",
		"FPucA9k=",
		"FPucA9k=",
		"CT5ZYA6Z",
		"14fb9c03d9",
	},
	{
		"bytes-3",
		"\x14\xfb\x9c\x03",
		"FPucAw==",
		"FPucAw==",
		"CT5ZYAY=",
		"14fb9c03",
	},
	// RFC 4648 example
	{
		"empty string",
		"",
		"",
		"",
		"",
		"",
	},
	{
		"f",
		"f",
		"Zg==",
		"Zg==",
		"MY======",
		"66",
	},
	{
		"fo",
		"fo",
		"Zm8=",
		"Zm8=",
		"MZXQ====",
		"666f",
	},
	{
		"foo",
		"foo",
		"Zm9v",
		"Zm9v",
		"MZXW6===",
		"666f6f",
	},
	{
		"foob",
		"foob",

		"Zm9vYg==",
		"Zm9vYg==",
		"MZXW6YQ=",
		"666f6f62",
	},
	{
		"fooba",
		"fooba",

		"Zm9vYmE=",
		"Zm9vYmE=",
		"MZXW6YTB",
		"666f6f6261",
	},
	{
		"foobar",
		"foobar",
		"Zm9vYmFy",
		"Zm9vYmFy",
		"MZXW6YTBOI======",
		"666f6f626172",
	},
}

func TestHash_Hex(t *testing.T) {
	for _, ht := range hashTests {
		h := Hash(ht.raw)
		runHashTest(t, ht.name+":hex", ht.hex, h.Hex)
	}
}

func TestHash_Base32(t *testing.T) {
	for _, ht := range hashTests {
		h := Hash(ht.raw)
		runHashTest(t, ht.name+":base32", ht.base32, h.Base32)
	}
}

func TestHash_Base64(t *testing.T) {
	for _, ht := range hashTests {
		h := Hash(ht.raw)
		runHashTest(t, ht.name+":base64", ht.base64, h.Base64)
	}
}

func TestHash_Base64UrlSafe(t *testing.T) {
	for _, ht := range hashTests {
		h := Hash(ht.raw)
		runHashTest(t, ht.name+":base64UrlSafe", ht.base64UrlSafe, h.Base64UrlSafe)
	}
}

func runHashTest(t *testing.T, name string, expected string, fn func() (string, error)) {
	t.Run(name, func(t *testing.T) {
		result, err := fn()
		if err != nil {
			t.Errorf("Did not expect error: %v", err)
		}
		if result != expected {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})
}
