package hasher

import (
	"testing"
)

type testCase struct {
	decoded string
	pairs   []encodingPair
}

type encodingPair struct {
	encoding encoding
	encoded  string
}

var names = map[encoding]string{
	Base64:        "Base64",
	Base64UrlSafe: "Base64UrlSafe",
	Base32:        "Base32",
	Hex:           "Hex",
}

var testCases = []testCase{
	{
		"Before software can be reusable it first has to be usable.",
		[]encodingPair{
			{Base64, "QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg=="},
			{Base64UrlSafe, "QmVmb3JlIHNvZnR3YXJlIGNhbiBiZSByZXVzYWJsZSBpdCBmaXJzdCBoYXMgdG8gYmUgdXNhYmxlLg=="},
			{Base32, "IJSWM33SMUQHG33GOR3WC4TFEBRWC3RAMJSSA4TFOVZWCYTMMUQGS5BAMZUXE43UEBUGC4ZAORXSAYTFEB2XGYLCNRSS4==="},
			{Hex, "4265666f726520736f6674776172652063616e206265207265757361626c652069742066697273742068617320746f20626520757361626c652e"},
		},
	},
	/// RFC 3548 examples
	{
		"\x14\xfb\x9c\x03\xd9\x7e",
		[]encodingPair{
			{Base64, "FPucA9l+"},
			{Base64UrlSafe, "FPucA9l-"},
			{Base32, "CT5ZYA6ZPY======"},
			{Hex, "14fb9c03d97e"},
		},
	},
	{
		"\x14\xfb\x9c\x03\xd9",
		[]encodingPair{
			{Base64, "FPucA9k="},
			{Base64UrlSafe, "FPucA9k="},
			{Base32, "CT5ZYA6Z"},
			{Hex, "14fb9c03d9"},
		},
	},
	{
		"\x14\xfb\x9c\x03",
		[]encodingPair{
			{Base64, "FPucAw=="},
			{Base64UrlSafe, "FPucAw=="},
			{Base32, "CT5ZYAY="},
			{Hex, "14fb9c03"},
		},
	},
	// RFC 4648 example
	{
		"",
		[]encodingPair{
			{Base64, ""},
			{Base64UrlSafe, ""},
			{Base32, ""},
			{Hex, ""},
		},
	},
	{
		"f",
		[]encodingPair{
			{Base64, "Zg=="},
			{Base64UrlSafe, "Zg=="},
			{Base32, "MY======"},
			{Hex, "66"},
		},
	},
	{
		"fo",
		[]encodingPair{
			{Base64, "Zm8="},
			{Base64UrlSafe, "Zm8="},
			{Base32, "MZXQ===="},
			{Hex, "666f"},
		},
	},
	{
		"foo",
		[]encodingPair{
			{Base64, "Zm9v"},
			{Base64UrlSafe, "Zm9v"},
			{Base32, "MZXW6==="},
			{Hex, "666f6f"},
		},
	},
	{
		"foob",
		[]encodingPair{
			{Base64, "Zm9vYg=="},
			{Base64UrlSafe, "Zm9vYg=="},
			{Base32, "MZXW6YQ="},
			{Hex, "666f6f62"},
		},
	},
	{
		"fooba",
		[]encodingPair{
			{Base64, "Zm9vYmE="},
			{Base64UrlSafe, "Zm9vYmE="},
			{Base32, "MZXW6YTB"},
			{Hex, "666f6f6261"},
		},
	},
	{
		"foobar",
		[]encodingPair{
			{Base64, "Zm9vYmFy"},
			{Base64UrlSafe, "Zm9vYmFy"},
			{Base32, "MZXW6YTBOI======"},
			{Hex, "666f6f626172"},
		},
	},
}

func TestEncode(t *testing.T) {
	t.Parallel()
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.decoded, func(t *testing.T) {
			for _, p := range tc.pairs {
				result, _ := encode([]byte(tc.decoded), p.encoding)
				t.Log(names[p.encoding], result)
				if result != p.encoded {
					t.Errorf("Expected %s, got %v", p.encoded, result)
				}
			}
		})
	}
}
