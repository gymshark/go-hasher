package hasher

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
)

type hasherTest struct {
	name    string
	decoded string
	md5,
	sha1,
	sha256,
	sha512,
	sha3,
	hmac256,
	hmac512,
	ripemd160 []byte
}

var hasherTests = []hasherTest{
	{
		"text",
		"Before software can be reusable it first has to be usable.",
		[]byte{174, 77, 84, 251, 132, 202, 65, 3, 43, 10, 177, 124, 248, 26, 81, 246},
		[]byte{14, 60, 143, 105, 182, 142, 31, 215, 23, 240, 135, 247, 231, 210, 80, 229, 195, 182, 45, 28},
		[]byte{156, 225, 23, 254, 61, 19, 114, 251, 248, 149, 239, 194, 28, 0, 140, 18, 55, 23, 75, 170, 178, 56, 248, 129, 90, 154, 59, 181, 141, 37, 154, 6},
		[]byte{62, 88, 52, 200, 79, 110, 176, 227, 228, 159, 145, 45, 99, 87, 16, 160, 124, 188, 30, 86, 149, 253, 176, 85, 59, 193, 1, 148, 251, 3, 12, 83, 252, 148, 112, 62, 212, 155, 218, 55, 182, 102, 136, 6, 58, 54, 155, 173, 2, 120, 26, 155, 159, 158, 243, 52, 212, 118, 181, 206, 246, 213, 143, 165},
		[]byte{149, 69, 160, 3, 20, 191, 64, 2, 233, 127, 218, 137, 83, 83, 34, 105, 184, 211, 12, 107, 40, 245, 159, 205, 67, 3, 248, 92, 181, 213, 33, 127, 75, 30, 8, 43, 135, 91, 97, 220, 205, 40, 11, 217, 217, 244, 208, 90, 204, 93, 217, 94, 212, 17, 49, 24, 50, 92, 183, 84, 57, 112, 111, 94},
		[]byte{174, 118, 165, 181, 236, 184, 149, 229, 166, 237, 39, 82, 34, 44, 193, 108, 66, 151, 174, 102, 30, 10, 219, 222, 228, 141, 204, 191, 241, 39, 47, 154},
		[]byte{213, 110, 204, 119, 143, 94, 193, 197, 111, 190, 141, 215, 248, 80, 120, 65, 229, 92, 234, 175, 58, 35, 87, 173, 81, 1, 138, 82, 148, 161, 147, 73, 46, 144, 180, 60, 250, 20, 171, 70, 171, 39, 43, 22, 10, 71, 8, 94, 143, 153, 220, 177, 163, 143, 242, 82, 184, 204, 131, 164, 150, 154, 74, 223},
		[]byte{161, 26, 149, 100, 194, 180, 171, 109, 233, 12, 188, 169, 95, 1, 27, 165, 33, 57, 92, 138},
	},
	//Random bytes
	{
		"random bytes",
		"\x35\x5e\x56\xe0\xc6\x29\x38\xf4\x81\x00\xab\x81\x7e\xd7\x08\x95\x62\x20\xa7\xda\x64\xa2\xce\xb3\xc5",
		[]byte{124, 54, 46, 122, 250, 104, 9, 49, 155, 31, 11, 100, 241, 120, 150, 198},
		[]byte{65, 57, 117, 238, 162, 16, 219, 6, 191, 53, 165, 254, 239, 22, 30, 172, 113, 228, 235, 99},
		[]byte{181, 250, 217, 205, 205, 70, 124, 163, 8, 42, 177, 239, 223, 5, 234, 130, 203, 45, 239, 111, 46, 199, 24, 28, 169, 198, 198, 82, 92, 99, 162, 203},
		[]byte{114, 193, 86, 181, 71, 181, 149, 136, 125, 127, 157, 229, 38, 251, 103, 231, 6, 203, 249, 221, 128, 201, 28, 187, 66, 176, 96, 35, 99, 69, 112, 101, 140, 230, 122, 153, 22, 64, 192, 103, 52, 74, 189, 146, 211, 99, 127, 176, 157, 38, 139, 144, 151, 53, 130, 43, 237, 223, 245, 26, 218, 178, 14, 22},
		[]byte{254, 33, 54, 247, 72, 170, 38, 38, 75, 0, 124, 64, 45, 129, 120, 26, 79, 221, 216, 236, 197, 120, 51, 232, 61, 51, 48, 53, 94, 232, 31, 239, 121, 20, 134, 4, 44, 101, 14, 53, 9, 77, 219, 94, 218, 240, 189, 190, 206, 158, 5, 195, 167, 120, 85, 192, 106, 81, 161, 33, 65, 43, 255, 208},
		[]byte{43, 152, 103, 54, 66, 33, 167, 1, 202, 189, 137, 146, 46, 243, 59, 84, 74, 156, 88, 147, 183, 15, 153, 172, 50, 196, 244, 111, 185, 3, 75, 7},
		[]byte{109, 130, 32, 229, 190, 91, 65, 233, 144, 254, 213, 216, 123, 155, 161, 184, 31, 102, 200, 229, 116, 158, 70, 73, 79, 136, 100, 47, 112, 243, 72, 123, 124, 23, 54, 40, 245, 79, 77, 65, 156, 146, 25, 56, 222, 225, 80, 11, 161, 151, 255, 105, 84, 94, 83, 74, 247, 31, 176, 189, 35, 20, 158, 118},
		[]byte{24, 231, 125, 165, 30, 140, 22, 80, 158, 239, 205, 145, 45, 110, 101, 94, 131, 30, 79, 81},
	},
	{
		"empty string",
		"",
		[]byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126},
		[]byte{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9},
		[]byte{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85},
		[]byte{207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62},
		[]byte{70, 185, 221, 43, 11, 168, 141, 19, 35, 59, 63, 235, 116, 62, 235, 36, 63, 205, 82, 234, 98, 184, 27, 130, 181, 12, 39, 100, 110, 213, 118, 47, 215, 93, 196, 221, 216, 192, 242, 0, 203, 5, 1, 157, 103, 181, 146, 246, 252, 130, 28, 73, 71, 154, 180, 134, 64, 41, 46, 172, 179, 183, 196, 190},
		[]byte{173, 113, 20, 140, 121, 242, 26, 185, 238, 197, 30, 165, 199, 221, 43, 102, 135, 146, 247, 192, 211, 83, 74, 230, 107, 34, 247, 28, 97, 82, 63, 179},
		[]byte{1, 145, 123, 248, 91, 224, 201, 152, 89, 138, 35, 50, 247, 92, 47, 230, 246, 98, 192, 144, 13, 67, 145, 18, 60, 162, 188, 97, 240, 115, 237, 227, 96, 175, 143, 58, 253, 110, 93, 63, 40, 223, 244, 181, 124, 194, 40, 144, 170, 123, 116, 152, 207, 68, 31, 50, 166, 246, 231, 138, 202, 60, 175, 232},
		[]byte{156, 17, 133, 165, 197, 233, 252, 84, 97, 40, 8, 151, 126, 232, 245, 72, 178, 37, 141, 49},
	},
}

func TestMd5(t *testing.T) {
	for _, ht := range hasherTests {
		runHasherTest(t, ht.name+":md5", ht.decoded, ht.md5, Md5)
	}
}

func TestSha1(t *testing.T) {
	for _, ht := range hasherTests {
		runHasherTest(t, ht.name+":sha1", ht.decoded, ht.sha1, Sha1)
	}
}

func TestSha256(t *testing.T) {
	for _, ht := range hasherTests {
		runHasherTest(t, ht.name+":sha256", ht.decoded, ht.sha256, Sha256)
	}
}

func TestSha512(t *testing.T) {
	for _, ht := range hasherTests {
		runHasherTest(t, ht.name+":sha512", ht.decoded, ht.sha512, Sha512)
	}
}

func TestSha3(t *testing.T) {
	for _, ht := range hasherTests {
		runHasherTest(t, ht.name+":sha3", ht.decoded, ht.sha3, Sha3)
	}
}

func TestHmac(t *testing.T) {
	t.Parallel()
	var secretKey = "test"

	for _, ht := range hasherTests {
		confs := []struct {
			name     string
			hashed   []byte
			hashAlgo func() hash.Hash
		}{
			{
				ht.name + ":hmac-sha256",
				ht.hmac256,
				sha256.New,
			},
			{
				ht.name + ":hmac-sha512",
				ht.hmac512,
				sha512.New,
			},
		}

		for _, conf := range confs {
			t.Run(conf.name, func(t *testing.T) {
				result := Hmac([]byte(ht.decoded), secretKey, conf.hashAlgo)
				if !bytes.Equal(result, conf.hashed) {
					t.Errorf("Expected %v\nGot %v", conf.hashed, result)
				}
			})
		}
	}
}

func runHasherTest(t *testing.T, name string, decoded string, encoded []byte, fn func(data []byte) Hash) {
	t.Run(name, func(t *testing.T) {
		result := fn([]byte(decoded))
		if !bytes.Equal(result, encoded) {
			t.Errorf("Expected %v, got %v", encoded, result)
		}
	})
}

func Example_hex() {
	h := Sha512([]byte("hello")).Hex()
	fmt.Println(h)
}

func Example_base64() {
	h := Sha512([]byte("hello")).Base64()
	fmt.Println(h)
}

func Example_base64UrlSafe() {
	h := Sha512([]byte("hello")).Base64UrlSafe()
	fmt.Println(h)
}

func ExampleMd5() {
	h := Md5([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleSha1() {
	h := Sha1([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleSha256() {
	h := Sha512([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleSha512() {
	h := Sha512([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleSha3() {
	h := Sha3([]byte("hello")).Hex()
	fmt.Println(h)
}

func ExampleHmac_sha256() {
	h := Hmac([]byte("hello"), "secretKey", sha256.New).Base64()
	fmt.Println(h)
}

func ExampleHmac_sha512() {
	h := Hmac([]byte("hello"), "secretKey", sha512.New).Base64()
	fmt.Println(h)
}

func ExampleEqual() {
	d := []byte("hello")
	h1 := Sha256(d).Hex()
	h2 := Sha512(d).Hex()

	eq := Equal([]byte(h1), []byte(h2))
	fmt.Println(eq)
	//Output: false
}
