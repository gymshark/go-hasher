# Gymshark Hasher
`import "github.com/gymshark/go-hasher"`

A hashing wrapper around some common hashing functions with customizable encoding

If any issues/bugs are found please raise an issue on github here: https://github.com/gymshark/go-hasher/issues

## Docs
Online: https://pkg.go.dev/github.com/gymshark/go-hasher

Local: `godoc -http=:6060`

## Usage
Basic usage
```go
import "github.com/gymshark/go-hasher"

func main() {
    h := hasher.Sha256([]byte("hello world.")).Base64()
    fmt.Println(h)
}
```

### Hmac usage

```go
import "github.com/gymshark/go-hasher"

func main() {
    secretKey := "secretKey"
    hmac := hasher.Hmac([]byte("hello world."), secretKey, sha512.New).Base64()
    fmt.Println(hmac)
    
    //securely check for equality
    eq := hasher.Equal([]byte(hmac), []byte("random-token"))

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
    fmt.Println(h)
}
```