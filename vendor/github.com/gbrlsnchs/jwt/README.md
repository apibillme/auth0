# jwt (JSON Web Token for Go)
[![JWT Compatible](https://jwt.io/img/badge.svg)](https://jwt.io)

[![Build status](https://travis-ci.org/gbrlsnchs/jwt.svg?branch=master)](https://travis-ci.org/gbrlsnchs/jwt)
[![Build status](https://ci.appveyor.com/api/projects/status/wqao7uvucce71jja/branch/master?svg=true)](https://ci.appveyor.com/project/gbrlsnchs/jwt/branch/master)
[![Sourcegraph](https://sourcegraph.com/github.com/gbrlsnchs/jwt/-/badge.svg)](https://sourcegraph.com/github.com/gbrlsnchs/jwt?badge)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Minimal version](https://img.shields.io/badge/minimal%20version-go1.11%2B-5272b4.svg)](https://golang.org/doc/go1.11) [![Join the chat at https://gitter.im/gbrlsnchs/jwt](https://badges.gitter.im/gbrlsnchs/jwt.svg)](https://gitter.im/gbrlsnchs/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## About
This package is a JWT signer, verifier and validator for [Go](https://golang.org) (or Golang).

Although there are many JWT packages out there for Go, many lack support for some signing, verifying or validation methods and, when they don't, they're overcomplicated. This package tries to mimic the ease of use from [Node JWT library](https://github.com/auth0/node-jsonwebtoken)'s API while following the [Effective Go](https://golang.org/doc/effective_go.html) guidelines.

Support for [JWE](https://tools.ietf.org/html/rfc7516) isn't provided. Instead, [JWS](https://tools.ietf.org/html/rfc7515) is used, narrowed down to the [JWT specification](https://tools.ietf.org/html/rfc7519).


## Warning
`v2` is guaranteed to work with `go1.11` or after. Nevertheless, it might work with `go1.10` by using [vgo](https://github.com/golang/vgo).  
Also, branch `master` contains bleeding edge code, therefore it sometimes may introduce breaking changes.

### `v1` vs. `v2`
#### `v1` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  200000	      7962 ns/op	    3457 B/op	      50 allocs/op
BenchmarkVerify-4   	  100000	     13087 ns/op	    3825 B/op	      80 allocs/op
```

#### `v2` on  Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
```
BenchmarkSign-4     	  300000	      3923 ns/op	    1344 B/op	      11 allocs/op
BenchmarkVerify-4   	  200000	      8078 ns/op	    1696 B/op	      28 allocs/op
```

## Usage
Full documentation [here](https://godoc.org/github.com/gbrlsnchs/jwt).

### Installing
`go get -u github.com/gbrlsnchs/jwt/v2`

### Importing
```go
import (
	// ...

	github.com/gbrlsnchs/jwt/v2
)
```

## Example
### Signing a simple JWT
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &jwt.JWT{
	Issuer:         "gbrlsnchs",
	Subject:        "someone",
	Audience:       "gophers",
	ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
	NotBefore:      now.Add(30 * time.Minute).Unix(),
	IssuedAt:       now.Unix(),
	ID:             "foobar",
}
jot.SetAlgorithm(hs256)
jot.SetKeyID("kid")
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Printf("token = %s", token)
```

### Signing a JWT with public claims
#### First, create a custom type and embed a JWT pointer in it
```go
type Token struct {
	*jwt.JWT
	IsLoggedIn  bool   `json:"isLoggedIn"`
	CustomField string `json:"customField,omitempty"`
}
```

#### Now initialize, marshal and sign it
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
jot := &Token{
	JWT: &jwt.JWT{
		Issuer:         "gbrlsnchs",
		Subject:        "someone",
		Audience:       "gophers",
		ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
		NotBefore:      now.Add(30 * time.Minute).Unix(),
		IssuedAt:       now.Unix(),
		ID:             "foobar",
	},
	IsLoggedIn:  true,
	CustomField: "myCustomField",
}
jot.SetAlgorithm(hs256)
jot.SetKeyID("kid")
payload, err := jwt.Marshal(jot)
if err != nil {
	// handle error
}
token, err := hs256.Sign(payload)
if err != nil {
	// handle error
}
log.Printf("token = %s", token)
```

### Verifying and validating a JWT
```go
// Timestamp the beginning.
now := time.Now()
// Define a signer.
hs256 := jwt.NewHS256("secret")
// This is a mocked token for demonstration purposes only.
token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.lZ1zDoGNAv3u-OclJtnoQKejE8_viHlMtGlAxE8AE0Q"

// First, extract the payload and signature.
// This enables unmarshaling the JWT first and
// verifying it later or vice versa.
payload, sig, err := jwt.Parse(token)
if err != nil {
	// handle error
}
var jot Token
if err = jwt.Unmarshal(payload, &jot); err != nil {
	// handle error
}
if err = hs256.Verify(payload, sig); err != nil {
	// handle error
}

// Validate fields.
iatValidator := jwt.IssuedAtValidator(now)
expValidator := jwt.ExpirationTimeValidator(now)
audValidator := jwt.AudienceValidator("admin")
if err = jot.Validate(algValidator, expValidator, audValidator); err != nil {
	switch err {
	case jwt.ErrIatValidation:
		// handle "iat" validation error
	case jwt.ErrExpValidation:
		// handle "exp" validation error
	case jwt.ErrAudValidation:
		// handle "aud" validation error
	}
}
```

## Contributing
### How to help:
- Pull Requests
- Issues
- Opinions
