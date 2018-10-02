# Auth0 authentication for net/http and fasthttp

[![Go Report](https://goreportcard.com/badge/github.com/apibillme/auth0)](https://goreportcard.com/report/github.com/apibillme/auth0) [![GolangCI](https://golangci.com/badges/github.com/apibillme/auth0.svg)](https://golangci.com/r/github.com/apibillme/auth0) [![Travis](https://travis-ci.org/apibillme/auth0.svg?branch=master)](https://travis-ci.org/apibillme/auth0#) [![codecov](https://codecov.io/gh/apibillme/auth0/branch/master/graph/badge.svg)](https://codecov.io/gh/apibillme/auth0) ![License](https://img.shields.io/github/license/mashape/apistatus.svg) ![Maintenance](https://img.shields.io/maintenance/yes/2018.svg) [![GoDoc](https://godoc.org/github.com/apibillme/auth0?status.svg)](https://godoc.org/github.com/apibillme/auth0)

## Features:
* Full authentication for Auth0 - or with any JWKs endpoint
* Works with [net/http](https://golang.org/pkg/net/http/) and [fasthttp](https://github.com/valyala/fasthttp)
* About 200 LOC
* In-memory key (token) caching
* Conforms to [IETF JWT Current Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-02#section-3)

```bash
go get github.com/apibillme/auth0-middleware
```