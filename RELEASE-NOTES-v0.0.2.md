# go-iroh v0.0.2

v0.0.2 is a temporary migration bridge to v0.1.0. It carries the v0.1.0
blobs implementation while retaining deprecated compatibility names for one
upgrade cycle.

Use Go 1.26 or later to apply the safe, source-level fixes:

```sh
go get github.com/tmc/go-iroh@v0.0.2
go fix -diff ./...
go fix ./...
```

The built-in fixer migrates `BytesMap`, `BytesEntry`, `MapEntry`,
`NewBytesMap`, and the former `http3` adapter package to their v0.1 names.

Then upgrade to v0.1.0 and run tests:

```sh
go get github.com/tmc/go-iroh@v0.1.0
go mod tidy
go test ./...
```

`Get` and `GetBlob` remain deprecated compatibility methods in v0.0.2, but
Go's safe inliner does not rewrite them: they require control flow and can be
called through an interface. Migrate them manually to `Open` and `ReadBlob`,
respectively. Check missing blobs with `errors.Is(err, blobs.ErrBlobNotFound)`
and close all `DataReader` and `Outboard` values.

See [MIGRATING-v0.0.2.md](MIGRATING-v0.0.2.md) for examples and limits.
