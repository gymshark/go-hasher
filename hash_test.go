package hasher

import (
	"fmt"
	"testing"
)

type hashTest struct {
	name          string
	raw           string
	base64        string
	base64UrlSafe string
	base32        string
	hex           string
	binary        string
}

var hashTests = []hashTest{
	{
		"text",
		"Before software can be reusable it first has to be usable.",
		"QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg==",
		"QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg==",
		"IJSWM33SMUQHG33GOR3WC4TFEBRWC3RAMJSSA4TFOVZWCYTMMUQGS5BAMZUXE43UEBUGC4ZAORXSAYTFEB2XGYLCNRSS4===",
		"4265666f726520736f6674776172652063616e206265207265757361626c652069742066697273742068617320746f20626520757361626c652e",
		"[01000010 01100101 01100110 01101111 01110010 01100101 00100000 01110011 01101111 01100110 01110100 01110111 01100001 01110010 01100101 00100000 01100011 01100001 01101110 00100000 01100010 01100101 00100000 01110010 01100101 01110101 01110011 01100001 01100010 01101100 01100101 00100000 01101001 01110100 00100000 01100110 01101001 01110010 01110011 01110100 00100000 01101000 01100001 01110011 00100000 01110100 01101111 00100000 01100010 01100101 00100000 01110101 01110011 01100001 01100010 01101100 01100101 00101110]",
	},
	/// RFC 3548 examples
	{
		"bytes",
		"\x14\xfb\x9c\x03\xd9\x7e",
		"FPucA9l+",
		"FPucA9l-",
		"CT5ZYA6ZPY======",
		"14fb9c03d97e",
		"[00010100 11111011 10011100 00000011 11011001 01111110]",
	},
	{
		"bytes-2",
		"\x14\xfb\x9c\x03\xd9",
		"FPucA9k=",
		"FPucA9k=",
		"CT5ZYA6Z",
		"14fb9c03d9",
		"[00010100 11111011 10011100 00000011 11011001]",
	},
	{
		"bytes-3",
		"\x14\xfb\x9c\x03",
		"FPucAw==",
		"FPucAw==",
		"CT5ZYAY=",
		"14fb9c03",
		"[00010100 11111011 10011100 00000011]",
	},
	// RFC 4648 example
	{
		"empty string",
		"",
		"",
		"",
		"",
		"",
		"[]",
	},
	{
		"f",
		"f",
		"Zg==",
		"Zg==",
		"MY======",
		"66",
		"[01100110]",
	},
	{
		"fo",
		"fo",
		"Zm8=",
		"Zm8=",
		"MZXQ====",
		"666f",
		"[01100110 01101111]",
	},
	{
		"foo",
		"foo",
		"Zm9v",
		"Zm9v",
		"MZXW6===",
		"666f6f",
		"[01100110 01101111 01101111]",
	},
	{
		"foob",
		"foob",
		"Zm9vYg==",
		"Zm9vYg==",
		"MZXW6YQ=",
		"666f6f62",
		"[01100110 01101111 01101111 01100010]",
	},
	{
		"fooba",
		"fooba",
		"Zm9vYmE=",
		"Zm9vYmE=",
		"MZXW6YTB",
		"666f6f6261",
		"[01100110 01101111 01101111 01100010 01100001]",
	},
	{
		"foobar",
		"foobar",
		"Zm9vYmFy",
		"Zm9vYmFy",
		"MZXW6YTBOI======",
		"666f6f626172",
		"[01100110 01101111 01101111 01100010 01100001 01110010]",
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

func TestHash_Encode(t *testing.T) {
	binaryFunc := func(b []byte) string {
		return fmt.Sprintf("%08b", b)
	}

	for _, ht := range hashTests {
		h := Hash(ht.raw)
		t.Run(ht.name+":custom-bin-func", func(t *testing.T) {
			result := h.Encode(binaryFunc)
			if result != ht.binary {
				t.Errorf("Expected %v, got %v", ht.binary, result)
			}
		})
	}
}

func runHashTest(t *testing.T, name string, expected string, fn func() string) {
	t.Run(name, func(t *testing.T) {
		result := fn()
		if result != expected {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})
}

func ExampleHash_Encode() {
	binaryFunc := func(b []byte) string {
		return fmt.Sprintf("%08b", b)
	}

	h := Sha512([]byte("hello")).Encode(binaryFunc)
	fmt.Println(h)
}

func ExampleHash_Hex() {
	h := Sha512([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleHash_Base32() {
	h := Sha1([]byte("hello")).Base32()
	fmt.Println(h)
}

func ExampleHash_Base64() {
	h := Sha512([]byte("hello")).Base64()
	fmt.Println(h)
}

func ExampleHash_Base64UrlSafe() {
	h := Sha512([]byte("hello")).Base64UrlSafe()
	fmt.Println(h)
}
