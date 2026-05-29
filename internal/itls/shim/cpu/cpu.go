// Package cpu is a minimal shim for the GOROOT-private internal/cpu, exposing
// just the feature flags the vendored crypto/tls reads. All flags are false,
// which selects the portable code paths (correct, if not hardware-accelerated).
package cpu

// X86 mirrors the fields crypto/tls reads on amd64.
var X86 struct {
	HasAES, HasPCLMULQDQ, HasSSE41, HasSSSE3 bool
}

// ARM64 mirrors the fields crypto/tls reads on arm64.
var ARM64 struct {
	HasAES, HasPMULL bool
}

// S390X mirrors the fields crypto/tls reads on s390x.
var S390X struct {
	HasAES, HasAESCTR, HasGHASH bool
}
