package hasher

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
)

type hashTest struct {
	name, decoded, md5, sha1, sha256, sha512, sha3, hmac256, hmac512 string
}

var hashTests = []hashTest{
	{
		"text",
		"Before software can be reusable it first has to be usable.",
		"ae4d54fb84ca41032b0ab17cf81a51f6",
		"0e3c8f69b68e1fd717f087f7e7d250e5c3b62d1c",
		"9ce117fe3d1372fbf895efc21c008c1237174baab238f8815a9a3bb58d259a06",
		"3e5834c84f6eb0e3e49f912d635710a07cbc1e5695fdb0553bc10194fb030c53fc94703ed49bda37b66688063a369bad02781a9b9f9ef334d476b5cef6d58fa5",
		"9545a00314bf4002e97fda8953532269b8d30c6b28f59fcd4303f85cb5d5217f4b1e082b875b61dccd280bd9d9f4d05acc5dd95ed4113118325cb75439706f5e",
		"ae76a5b5ecb895e5a6ed2752222cc16c4297ae661e0adbdee48dccbff1272f9a",
		"d56ecc778f5ec1c56fbe8dd7f8507841e55ceaaf3a2357ad51018a5294a193492e90b43cfa14ab46ab272b160a47085e8f99dcb1a38ff252b8cc83a4969a4adf",
	},
	// Random bytes
	{
		"random bytes",
		"\x35\x5e\x56\xe0\xc6\x29\x38\xf4\x81\x00\xab\x81\x7e\xd7\x08\x95\x62\x20\xa7\xda\x64\xa2\xce\xb3\xc5",
		"7c362e7afa6809319b1f0b64f17896c6",
		"413975eea210db06bf35a5feef161eac71e4eb63",
		"b5fad9cdcd467ca3082ab1efdf05ea82cb2def6f2ec7181ca9c6c6525c63a2cb",
		"72c156b547b595887d7f9de526fb67e706cbf9dd80c91cbb42b06023634570658ce67a991640c067344abd92d3637fb09d268b909735822beddff51adab20e16",
		"fe2136f748aa26264b007c402d81781a4fddd8ecc57833e83d3330355ee81fef791486042c650e35094ddb5edaf0bdbece9e05c3a77855c06a51a121412bffd0",
		"2b9867364221a701cabd89922ef33b544a9c5893b70f99ac32c4f46fb9034b07",
		"6d8220e5be5b41e990fed5d87b9ba1b81f66c8e5749e46494f88642f70f3487b7c173628f54f4d419c921938dee1500ba197ff69545e534af71fb0bd23149e76",
	},
	{
		"empty string",
		"",
		"d41d8cd98f00b204e9800998ecf8427e",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
		"ad71148c79f21ab9eec51ea5c7dd2b668792f7c0d3534ae66b22f71c61523fb3",
		"01917bf85be0c998598a2332f75c2fe6f662c0900d4391123ca2bc61f073ede360af8f3afd6e5d3f28dff4b57cc22890aa7b7498cf441f32a6f6e78aca3cafe8",
	},
}

func TestMd5(t *testing.T) {
	for _, ht := range hashTests {
		runHashTest(t, ht.name+":md5", ht.decoded, ht.md5, Md5)
	}
}

func TestSha1(t *testing.T) {
	for _, ht := range hashTests {
		runHashTest(t, ht.name+":sha1", ht.decoded, ht.sha1, Sha1)
	}
}

func TestSha256(t *testing.T) {
	for _, ht := range hashTests {
		runHashTest(t, ht.name+":sha256", ht.decoded, ht.sha256, Sha256)
	}
}

func TestSha512(t *testing.T) {
	for _, ht := range hashTests {
		runHashTest(t, ht.name+":sha512", ht.decoded, ht.sha512, Sha512)
	}
}

func TestSha3(t *testing.T) {
	for _, ht := range hashTests {
		runHashTest(t, ht.name+":sha3", ht.decoded, ht.sha3, Sha3)
	}
}

func TestHmac(t *testing.T) {
	t.Parallel()
	var secretKey = "test"

	for _, ht := range hashTests {
		confs := []struct {
			name,
			encoded string
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
			t.Run(ht.name, func(t *testing.T) {
				result, _ := Hmac([]byte(ht.decoded), secretKey, conf.hashAlgo, Hex)
				t.Log(ht.name, result)
				if result != conf.encoded {
					t.Errorf("Expected %s, got %v", conf.encoded, result)
				}
			})
		}
	}
}

func runHashTest(t *testing.T, name, decoded, encoded string, fn func(data []byte, e encoding) (string, error)) {
	result, _ := fn([]byte(decoded), Hex)
	t.Log(name, result)
	if result != encoded {
		t.Errorf("Expected %s, got %v", encoded, result)
	}
}

func Example_hex() {
	hash, err := Sha512([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func Example_base64() {
	hash, err := Sha512([]byte("hello"), Base64)
	fmt.Println(hash, err)
}

func Example_base64UrlSafe() {
	hash, err := Sha512([]byte("hello"), Base64UrlSafe)
	fmt.Println(hash, err)
}

func ExampleMd5() {
	hash, err := Md5([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func ExampleSha1() {
	hash, err := Sha1([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func ExampleSha256() {
	hash, err := Sha512([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func ExampleSha512() {
	hash, err := Sha512([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func ExampleSha3() {
	hash, err := Sha3([]byte("hello"), Hex)
	fmt.Println(hash, err)
}

func ExampleHmac_sha256() {
	hash, err := Hmac([]byte("hello"), "secretKey", sha256.New, Base64)
	fmt.Println(hash, err)
}

func ExampleHmac_sha512() {
	hash, err := Hmac([]byte("hello"), "secretKey", sha512.New, Base64)
	fmt.Println(hash, err)
}

func ExampleEqual() {
	d := []byte("hello")
	h1, _ := Sha256(d, Hex)
	h2, _ := Sha512(d, Hex)

	eq := Equal([]byte(h1), []byte(h2))
	fmt.Println(eq)
	//Output: false
}
