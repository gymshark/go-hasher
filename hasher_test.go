package hasher

import (
	"bytes"
	"fmt"
	"testing"
)

type hasherTest struct {
	name    string
	decoded string
	md5,
	sha1,
	sha256,
	sha512,
	sha3 []byte
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
	},
	{
		"empty string",
		"",
		[]byte{212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126},
		[]byte{218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9},
		[]byte{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85},
		[]byte{207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62},
		[]byte{70, 185, 221, 43, 11, 168, 141, 19, 35, 59, 63, 235, 116, 62, 235, 36, 63, 205, 82, 234, 98, 184, 27, 130, 181, 12, 39, 100, 110, 213, 118, 47, 215, 93, 196, 221, 216, 192, 242, 0, 203, 5, 1, 157, 103, 181, 146, 246, 252, 130, 28, 73, 71, 154, 180, 134, 64, 41, 46, 172, 179, 183, 196, 190},
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

func runHasherTest(t *testing.T, name string, decoded string, encoded []byte, fn func(data []byte) Hash) {
	t.Run(name, func(t *testing.T) {
		result := fn([]byte(decoded))
		if !bytes.Equal(result, encoded) {
			t.Errorf("Expected %v, got %v", encoded, result)
		}
	})
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
	h := Sha256([]byte("hello")).Hex()
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

func ExampleEqual() {
	d := []byte("hello")
	h1 := Sha256(d).Hex()
	h2 := Sha512(d).Hex()

	eq := Equal([]byte(h1), []byte(h2))
	fmt.Println(eq)
	//Output: false
}
