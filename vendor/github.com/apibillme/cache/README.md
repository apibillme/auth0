# cache - In-memory cache for Go (golang) with TTL and LRU.

[![Go Report](https://goreportcard.com/badge/github.com/apibillme/cache)](https://goreportcard.com/report/github.com/apibillme/cache) [![GolangCI](https://golangci.com/badges/github.com/apibillme/cache.svg)](https://golangci.com/r/github.com/apibillme/cache) [![Travis](https://travis-ci.org/apibillme/cache.svg?branch=master)](https://travis-ci.org/apibillme/cache#) [![codecov](https://codecov.io/gh/apibillme/cache/branch/master/graph/badge.svg)](https://codecov.io/gh/apibillme/cache) ![License](https://img.shields.io/github/license/apibillme/cache.svg) ![Maintenance](https://img.shields.io/maintenance/yes/2018.svg) [![GoDoc](https://godoc.org/github.com/apibillme/cache?status.svg)](https://godoc.org/github.com/apibillme/cache)

cache provides a simple, goroutine safe, cache with a fixed number of entries. Each entry has a per-cache defined TTL. This TTL is reset on both modification and access of the value. As a result, if the cache is full, and no items have expired, when adding a new item, the item with the soonest expiration will be evicted.

It is based on the LRU implementation in golang-lru:
[github.com/hashicorp/golang-lru](http://godoc.org/github.com/hashicorp/golang-lru)

Which in turn is based on the LRU implementation in groupcache:
[github.com/golang/groupcache/lru](http://godoc.org/github.com/golang/groupcache/lru)

```go
 import (
     "github.com/apibillme/cache"
 )

l := New(128, WithTTL(2*time.Second)) // create new cache with ttl and fixed size of 128 keys
l.Set(1, 1) // set key
l.Get(1) // get key
l.Del(1) // delete key

```

For more methods read the GoDoc.
