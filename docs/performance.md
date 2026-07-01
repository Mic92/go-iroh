# Performance Baselines

These numbers were gathered on darwin/arm64, Apple M4 Max, on 2026-07-01.
Benchmark output lives under `/tmp`; it is not committed.

## Go Hot Paths

Command:

```sh
go test ./blobs ./endpointticket ./internal/postcard ./internal/qng/quicvarint ./internal/relayproto ./key ./iroh -run '^$' -bench 'Benchmark(Hash|BAO|FSStore|Ticket|Marshal|AppendParse|RelayFrame|RelayHandshake|SignVerify|RelayConn)' -benchmem > /tmp/go-iroh-perf-workstream1-baseline.txt
```

| Benchmark | Time | Throughput | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkHash` | 434856 ns/op | 2411.32 MB/s | 48667 | 171 |
| `BenchmarkBAOEncodeDecode/encode` | 1811662 ns/op | 578.79 MB/s | 1077256 | 130 |
| `BenchmarkBAOEncodeDecode/decode` | 1886161 ns/op | 555.93 MB/s | 2097248 | 10 |
| `BenchmarkFSStorePutGet/put` | 12714175 ns/op | 5.15 MB/s | 20647 | 40 |
| `BenchmarkFSStorePutGet/get` | 114727 ns/op | 571.23 MB/s | 116805 | 46 |
| `BenchmarkTicketEncodeDecode/encode` | 1037 ns/op | n/a | 896 | 10 |
| `BenchmarkTicketEncodeDecode/decode` | 6500 ns/op | n/a | 840 | 11 |
| `BenchmarkMarshalUnmarshal/marshal` | 330.8 ns/op | 196.48 MB/s | 200 | 5 |
| `BenchmarkMarshalUnmarshal/unmarshal` | 371.8 ns/op | 174.82 MB/s | 184 | 5 |
| `BenchmarkAppendParse/append` | 1.888-3.350 ns/op | n/a | 0 | 0 |
| `BenchmarkAppendParse/parse` | 1.742-3.369 ns/op | n/a | 0 | 0 |
| `BenchmarkRelayFrameEncodeDecode/encode` | 37.78 ns/op | 32665.81 MB/s | 0 | 0 |
| `BenchmarkRelayFrameEncodeDecode/decode` | 5579 ns/op | 221.18 MB/s | 1280 | 1 |
| `BenchmarkRelayHandshake/sign` | 30345 ns/op | n/a | 6528 | 6 |
| `BenchmarkRelayHandshake/verify` | 63744 ns/op | n/a | 6528 | 6 |
| `BenchmarkSignVerify/sign` | 23752 ns/op | n/a | 0 | 0 |
| `BenchmarkSignVerify/verify` | 106918 ns/op | n/a | 0 | 0 |
| `BenchmarkRelayConnSetupLatency` | 1432521 ns/op | n/a | 553653 | 3828 |
| `BenchmarkRelayConnStreamThroughput` | 614192 ns/op | 106.70 MB/s | 943657 | 5181 |

Direct stream throughput:

```sh
go test ./iroh -run '^$' -bench 'BenchmarkConnStreamThroughput$' -benchmem > /tmp/go-iroh-direct-stream.txt
```

| Benchmark | Time | Throughput | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkConnStreamThroughput` | 188824 ns/op | 347.07 MB/s | 63 | 0 |

## Rust iroh Comparison

Rust checkout: `/Users/tmc/go/src/github.com/n0-computer/iroh` at
`ee8b6a3d93608df683fb0110d885c9521d31169b`.

Build output was isolated from the Rust checkout:

```sh
CARGO_TARGET_DIR=/tmp/go-iroh-rust-target cargo run --manifest-path /Users/tmc/go/src/github.com/n0-computer/iroh/iroh/bench/Cargo.toml --locked --release --features local-relay -- iroh --clients 1 --streams 1 --max_streams 1 --download-size 64M > /tmp/go-iroh-rust-direct-bulk.txt
```

| Path | Command Shape | Result |
| --- | --- | ---: |
| Rust direct endpoint stream | 1 client, 1 stream, 64 MiB download | 231.02 MiB/s |
| Go direct endpoint stream | 64 KiB writes over one stream | 347.07 MB/s |

The direct stream comparison is useful but not exact. The Rust tool reports a
single 64 MiB download stream, including its client/server setup and first-byte
delay in the printed result. The Go benchmark reports repeated 64 KiB writes on
an already-connected stream and excludes setup from the timed loop.

The closest Rust local-relay run was attempted with:

```sh
CARGO_TARGET_DIR=/tmp/go-iroh-rust-target cargo run --manifest-path /Users/tmc/go/src/github.com/n0-computer/iroh/iroh/bench/Cargo.toml --locked --release --features local-relay -- iroh --clients 1 --streams 1 --max_streams 1 --download-size 64M --only-relay > /tmp/go-iroh-rust-relay-bulk.txt
```

That run built, but panicked before measurement because the benchmark cleared IP
transports and then indexed `bound_sockets()[0]` while constructing the server
address. No Rust relay-only number is reported from that run.
