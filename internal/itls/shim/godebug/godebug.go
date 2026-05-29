// Package godebug is a minimal shim for the GOROOT-private internal/godebug,
// providing just the Setting API that the vendored crypto/tls uses.
package godebug

import "os"

// Setting is a GODEBUG setting.
type Setting struct{ name string }

// New returns the Setting for the given GODEBUG key.
func New(name string) *Setting { return &Setting{name: name} }

// Value returns the value of the setting from the GODEBUG environment variable,
// or "" if unset. This is sufficient for crypto/tls's default-path checks.
func (s *Setting) Value() string {
	v := os.Getenv("GODEBUG")
	for v != "" {
		var kv string
		if i := indexByte(v, ','); i >= 0 {
			kv, v = v[:i], v[i+1:]
		} else {
			kv, v = v, ""
		}
		if eq := indexByte(kv, '='); eq >= 0 && kv[:eq] == s.name {
			return kv[eq+1:]
		}
	}
	return ""
}

// IncNonDefault is a no-op (metrics-only in the original).
func (s *Setting) IncNonDefault() {}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
