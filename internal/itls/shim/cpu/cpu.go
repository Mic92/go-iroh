// Package cpu is a minimal shim for the GOROOT-private internal/cpu, exposing
// just the feature flags the vendored crypto/tls reads.
package cpu

import syscpu "golang.org/x/sys/cpu"

// X86 mirrors the fields crypto/tls reads on amd64.
var X86 struct {
	HasAES, HasPCLMULQDQ, HasSSE41, HasSSSE3 bool
} = struct {
	HasAES, HasPCLMULQDQ, HasSSE41, HasSSSE3 bool
}{
	HasAES:       syscpu.X86.HasAES,
	HasPCLMULQDQ: syscpu.X86.HasPCLMULQDQ,
	HasSSE41:     syscpu.X86.HasSSE41,
	HasSSSE3:     syscpu.X86.HasSSSE3,
}

// ARM64 mirrors the fields crypto/tls reads on arm64.
var ARM64 struct {
	HasAES, HasPMULL bool
} = struct {
	HasAES, HasPMULL bool
}{
	HasAES:   syscpu.ARM64.HasAES,
	HasPMULL: syscpu.ARM64.HasPMULL,
}

// S390X mirrors the fields crypto/tls reads on s390x.
var S390X struct {
	HasAES, HasAESCTR, HasGHASH bool
} = struct {
	HasAES, HasAESCTR, HasGHASH bool
}{
	HasAES:    syscpu.S390X.HasAES,
	HasAESCTR: syscpu.S390X.HasAESCTR,
	HasGHASH:  syscpu.S390X.HasGHASH,
}
