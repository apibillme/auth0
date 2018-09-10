# auth0-middleware - for net/http and fasthttp

[![Go Report](https://goreportcard.com/badge/github.com/apibillme/auth0-middleware)](https://goreportcard.com/report/github.com/apibillme/auth0-middleware) [![GolangCI](https://golangci.com/badges/github.com/apibillme/auth0-middleware.svg)](https://golangci.com/r/github.com/apibillme/auth0-middleware) [![Travis](https://travis-ci.org/apibillme/auth0-middleware.svg?branch=master)](https://travis-ci.org/apibillme/auth0-middleware#) [![codecov](https://codecov.io/gh/apibillme/auth0-middleware/branch/master/graph/badge.svg)](https://codecov.io/gh/apibillme/auth0-middleware) ![License](https://img.shields.io/github/license/mashape/apistatus.svg) ![Maintenance](https://img.shields.io/maintenance/yes/2018.svg) [![GoDoc](https://godoc.org/github.com/apibillme/auth0-middleware?status.svg)](https://godoc.org/github.com/apibillme/auth0-middleware)


## Features:
* Full authentication for Auth0 - or with any JWKs endpoint
* Works with [net/http](https://golang.org/pkg/net/http/) and [fasthttp](https://github.com/valyala/fasthttp)
* About 100 LOC
* In-memory key (token) caching with [BuntDB](https://github.com/tidwall/buntdb)

```bash
go get github.com/apibillme/auth0-middleware
```

## Example

Check out [gorestserve](https://github.com/apibillme/gorestserve)

```go
func main() {
    db, err := buntdb.Open(":memory:")
    if err != nil {
        log.Panic(err)
    }
    defer db.Close()

    app := gorestserve.New()

    app.Use("/", func(ctx *fasthttp.RequestCtx, next func(error)) {
        jwkEndpoint := "https://example.auth0.com/.well-known/jwks.json"
        audience := "https://httpbin.org/"
        _, err := auth0.Validate(db, jwkEndpoint, audience, ctx)
        if err != nil {
            ctx.SetStatusCode(401)
            ctx.SetBodyString(`{"error":"` + cast.ToString(err) + `"}`)
        } else {
            next(nil)
        }
    })

    app.Use("/hello", func(ctx *fasthttp.RequestCtx, next func(error)) {
        ctx.SetStatusCode(200)
        ctx.SetBodyString(`{"hello": "foobar"}`)
    })
}
```

## TODO
* Tests (waiting for my version of VCR)