package hasher

import (
	"bytes"
	"fmt"
	"testing"
)

type hmacTest struct {
	name    string
	decoded string
	md5,
	sha1,
	sha256,
	sha512 []byte
}

var hmacTests = []hmacTest{
	{
		"text",
		"Before software can be reusable it first has to be usable.",
		[]byte{168, 203, 132, 101, 133, 119, 68, 5, 85, 11, 26, 141, 144, 4, 89, 11},
		[]byte{106, 138, 105, 81, 193, 219, 254, 173, 186, 24, 60, 53, 136, 122, 10, 86, 147, 24, 252, 218},
		[]byte{174, 118, 165, 181, 236, 184, 149, 229, 166, 237, 39, 82, 34, 44, 193, 108, 66, 151, 174, 102, 30, 10, 219, 222, 228, 141, 204, 191, 241, 39, 47, 154},
		[]byte{213, 110, 204, 119, 143, 94, 193, 197, 111, 190, 141, 215, 248, 80, 120, 65, 229, 92, 234, 175, 58, 35, 87, 173, 81, 1, 138, 82, 148, 161, 147, 73, 46, 144, 180, 60, 250, 20, 171, 70, 171, 39, 43, 22, 10, 71, 8, 94, 143, 153, 220, 177, 163, 143, 242, 82, 184, 204, 131, 164, 150, 154, 74, 223},
	},
	//Random bytes
	{
		"random bytes",
		"\x35\x5e\x56\xe0\xc6\x29\x38\xf4\x81\x00\xab\x81\x7e\xd7\x08\x95\x62\x20\xa7\xda\x64\xa2\xce\xb3\xc5",
		[]byte{171, 74, 153, 184, 147, 173, 110, 5, 88, 161, 190, 67, 105, 13, 99, 167},
		[]byte{1, 180, 186, 170, 210, 47, 193, 137, 218, 176, 161, 6, 231, 224, 58, 63, 232, 48, 67, 124},
		[]byte{43, 152, 103, 54, 66, 33, 167, 1, 202, 189, 137, 146, 46, 243, 59, 84, 74, 156, 88, 147, 183, 15, 153, 172, 50, 196, 244, 111, 185, 3, 75, 7},
		[]byte{109, 130, 32, 229, 190, 91, 65, 233, 144, 254, 213, 216, 123, 155, 161, 184, 31, 102, 200, 229, 116, 158, 70, 73, 79, 136, 100, 47, 112, 243, 72, 123, 124, 23, 54, 40, 245, 79, 77, 65, 156, 146, 25, 56, 222, 225, 80, 11, 161, 151, 255, 105, 84, 94, 83, 74, 247, 31, 176, 189, 35, 20, 158, 118},
	},
	{
		"empty string",
		"",
		[]byte{106, 235, 180, 29, 67, 102, 194, 121, 70, 135, 225, 217, 231, 174, 227, 7},
		[]byte{252, 133, 8, 116, 82, 105, 110, 91, 203, 227, 183, 167, 31, 222, 0, 227, 32, 175, 44, 202},
		[]byte{173, 113, 20, 140, 121, 242, 26, 185, 238, 197, 30, 165, 199, 221, 43, 102, 135, 146, 247, 192, 211, 83, 74, 230, 107, 34, 247, 28, 97, 82, 63, 179},
		[]byte{1, 145, 123, 248, 91, 224, 201, 152, 89, 138, 35, 50, 247, 92, 47, 230, 246, 98, 192, 144, 13, 67, 145, 18, 60, 162, 188, 97, 240, 115, 237, 227, 96, 175, 143, 58, 253, 110, 93, 63, 40, 223, 244, 181, 124, 194, 40, 144, 170, 123, 116, 152, 207, 68, 31, 50, 166, 246, 231, 138, 202, 60, 175, 232},
	},
}

func TestHmacMd5(t *testing.T) {
	for _, ht := range hmacTests {
		runHmacTest(t, ht.name+":hmac-md5", ht.decoded, ht.md5, HmacMd5)
	}
}

func TestHmacSha1(t *testing.T) {
	for _, ht := range hmacTests {
		runHmacTest(t, ht.name+":hmac-sha1", ht.decoded, ht.sha1, HmacSha1)
	}
}

func TestHmacSha256(t *testing.T) {
	for _, ht := range hmacTests {
		runHmacTest(t, ht.name+":hmac-sha256", ht.decoded, ht.sha256, HmacSha256)
	}
}

func TestHmacSha512(t *testing.T) {
	for _, ht := range hmacTests {
		runHmacTest(t, ht.name+":hmac-sha512", ht.decoded, ht.sha512, HmacSha512)
	}
}

func runHmacTest(t *testing.T, name string, decoded string, encoded []byte, fn func(data []byte, secret string) Hash) {
	t.Run(name, func(t *testing.T) {
		var secretKey = "test"
		result := fn([]byte(decoded), secretKey)
		if !bytes.Equal(result, encoded) {
			t.Errorf("Expected %v, got %v", encoded, result)
		}
	})
}

func ExampleHmacMd5() {
	h := HmacMd5([]byte("hello"), "secretKey").Base64()
	fmt.Println(h)
}

func ExampleHmacSha1() {
	h := HmacSha1([]byte("hello"), "secretKey").Base64()
	fmt.Println(h)
}

func ExampleHmacSha256() {
	h := HmacSha256([]byte("hello"), "secretKey").Base64()
	fmt.Println(h)
}

func ExampleHmacSha512() {
	h := HmacSha512([]byte("hello"), "secretKey").Base64()
	fmt.Println(h)
}
