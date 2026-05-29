package base

import (
	"fmt"
	"net/url"
	"strings"
)

// RelayUrl is a URL identifying a relay server.
//
// It wraps a parsed URL and is cheap to copy. It is encouraged to use a
// fully-qualified DNS domain name (one ending in a ".", e.g. "relay.example.com.")
// so that local DNS search domains do not interfere with resolution.
//
// The zero value is not usable; construct a RelayUrl with [ParseRelayUrl] or
// [RelayUrlFromURL].
type RelayUrl struct {
	url *url.URL
}

// ParseRelayUrl parses s into a RelayUrl. It returns an error wrapping
// [ErrParseRelayUrl] if s is not a valid URL.
func ParseRelayUrl(s string) (RelayUrl, error) {
	u, err := url.Parse(s)
	if err != nil {
		return RelayUrl{}, fmt.Errorf("%w: %v", ErrParseRelayUrl, err)
	}
	return RelayUrlFromURL(u), nil
}

// RelayUrlFromURL wraps an already-parsed URL as a RelayUrl, normalizing it so
// that equivalent URLs compare equal (see [RelayUrl.String]).
func RelayUrlFromURL(u *url.URL) RelayUrl {
	c := *u
	return RelayUrl{url: normalizeURL(&c)}
}

// ErrParseRelayUrl is returned (wrapped) when a relay URL cannot be parsed.
var ErrParseRelayUrl = fmt.Errorf("failed to parse relay URL")

// URL returns a copy of the underlying parsed URL.
func (r RelayUrl) URL() *url.URL {
	if r.url == nil {
		return nil
	}
	c := *r.url
	return &c
}

// String returns the normalized string form of the URL. An empty path is
// rendered as "/", matching the WHATWG URL serialization used by the Rust
// reference implementation (e.g. "https://example.com" -> "https://example.com/").
func (r RelayUrl) String() string {
	if r.url == nil {
		return ""
	}
	return r.url.String()
}

// Host returns the host (without port) of the relay URL.
func (r RelayUrl) Host() string {
	if r.url == nil {
		return ""
	}
	return r.url.Hostname()
}

// IsZero reports whether r is the unusable zero value.
func (r RelayUrl) IsZero() bool { return r.url == nil }

// Equal reports whether r and other are the same relay URL.
func (r RelayUrl) Equal(other RelayUrl) bool { return r.String() == other.String() }

// Compare returns -1, 0, or +1 comparing r and other by their normalized
// string form, giving RelayUrl a total order.
func (r RelayUrl) Compare(other RelayUrl) int {
	return strings.Compare(r.String(), other.String())
}

// MarshalText implements encoding.TextMarshaler.
func (r RelayUrl) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *RelayUrl) UnmarshalText(text []byte) error {
	parsed, err := ParseRelayUrl(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// normalizeURL applies the small subset of WHATWG URL normalization that the
// reference implementation relies on: a special scheme (http/https/ws/wss) with
// an empty path serializes with a "/" path, and the host is lower-cased.
func normalizeURL(u *url.URL) *url.URL {
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" && isSpecialScheme(u.Scheme) {
		u.Path = "/"
	}
	return u
}

func isSpecialScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss", "ftp", "file":
		return true
	}
	return false
}
