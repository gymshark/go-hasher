# Go Hasher
A wrapper around some common hashing functions with customizable encoding

If any issues/bugs are found please raise an issue on github here: [Issue Tracker](https://github.com/gymshark/go-hasher/issues)

---
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/3b11a652b77e440da627d4bdcffafac1)](https://www.codacy.com/gh/gymshark/go-hasher/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=gymshark/go-hasher&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/3b11a652b77e440da627d4bdcffafac1)](https://www.codacy.com/gh/gymshark/go-hasher/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=gymshark/go-hasher&amp;utm_campaign=Badge_Coverage)

- [Docs](#docs)
- [Getting Started](#getting-started)
  - [Basic Usage](#basic-usage)
  - [Hmac Usage](#hmac-usage)
  - [Custom Encoder Usage](#custom-encoder)
- [Functions](#functions)
  - [Hash Functions](#hash-functions)
  - [Hmac Functions](#hmac-functions)
  - [Encoding Functions](#encoding-functions)

## Docs
Online: https://pkg.go.dev/github.com/gymshark/go-hasher

Local: `godoc -http=:6060`

## Getting started
`import "github.com/gymshark/go-hasher"`

### Basic usage
```go
import "github.com/gymshark/go-hasher"

func main() {
    h := hasher.Sha256([]byte("hello world.")).Base64()
    fmt.Println(h) //base64 encoded hash
}
```

### Hmac usage
```go
import "github.com/gymshark/go-hasher"

func main() {
    secretKey := "secretKey"
    hmac := hasher.HmacSha512([]byte("hello world."), secretKey).Base64()
    fmt.Println(hmac) //base64 encoded hmac
    
    //securely check for equality
    eq := hasher.Equal([]byte(hmac), []byte("random-invalid-hmac"))

    //Output: false
    fmt.Println(eq)
}
```

### Custom Encoder
This allows you to pass a func with the signature of `func ([]byte) string` to the encoder when the lib may not supply a helper function for your needs

```go
import "github.com/gymshark/go-hasher"

func main() {
	encodingFn := func(b []byte) string {
        //encode the bytes however you want
        encodedstring := string(b)
        return encodedstring
    }
	
    h := hasher.Sha1([]byte("hello world.")).Encode(encodingFn)
    fmt.Println(h) //encoded hash result of custom function
}
```

## Functions
### Hash functions
```go
Md5([]byte)
Sha1([]byte)
Sha256([]byte)
Sha512([]byte)
Sha3([]byte)
```

### Hmac functions
```go
HmacMd5([]byte, string)
HmacSha1([]byte, string)
HmacSha256([]byte, string)
HmacSha512([]byte)
```

There is no Sha3 hmac function due to Sha3 being resistant to length extension attacks, you can append your secret key to your data then use `Sha3([]byte)` to generate your hash data.

> 𝑚𝑎𝑐=SHA3(𝑘||𝑚) is a secure MAC if 𝑘 is a fixed-length key. This is an explicit design goal of SHA3.

### Encoding functions
```go
Hex() // base16
Base32()
Base64()
Base64UrlSafe()
Encode(func([]byte) string) //allows custom encoding
```