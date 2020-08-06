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
    h, err := hasher.Sha256([]byte("hello world."), hasher.Base64) 

    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(h)
}
```

Hmac usage

```go
import "github.com/gymshark/go-hasher"

func main() {
	hmac, err := hasher.Hmac([]byte("hello world."), "secretKey", sha512.New, hasher.Base64)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hmac)
}
```
