# Migrating from v0.0.2 to v0.1.0

v0.0.2 is a temporary bridge release for the v0.1.0 blobs and `quicconn`
renames. It contains the v0.1.0 implementation plus deprecated compatibility
names. Do not use it as a long-term target: migrate to v0.1.0 after applying
the available fixes and reviewing the remaining call sites.

Use Go 1.26 or later to preview and apply the safe source-level fixes:

```sh
go get github.com/tmc/go-iroh@v0.0.2
go fix -diff ./...
go fix ./...
```

The built-in fixer rewrites these declarations:

- `blobs.BytesMap` to `blobs.MemStore`
- `blobs.BytesEntry` to `blobs.MemBlob`
- `blobs.MapEntry` to `blobs.Blob`
- `blobs.NewBytesMap` to `blobs.NewMemStore`
- `http3` types and `http3.NewConn` to `quicconn`

Then upgrade and test:

```sh
go get github.com/tmc/go-iroh@v0.1.0
go mod tidy
go test ./...
```

## Required manual review

`go fix` intentionally declines to inline the old `Get` and `GetBlob` methods:
their result conventions require control flow, and interface methods have no
body to inline. Update them manually.

```go
// Before
entry, ok, err := store.Get(ctx, hash)
data, ok := store.GetBlob(hash)

// After
blob, err := store.Open(ctx, hash)
data, err := blobs.ReadBlob(ctx, store, hash)
```

Use `errors.Is(err, blobs.ErrBlobNotFound)` for missing blobs. Close every
reader returned by `Blob.DataReader` or `Blob.Outboard`.
