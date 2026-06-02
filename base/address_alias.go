package base

import (
	"net/url"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// RelayUrl is a URL identifying a relay server.
//
// Deprecated: use [netaddr.RelayUrl].
type RelayUrl = netaddr.RelayUrl

// TransportAddr is a network-level address at which an endpoint may be reached.
//
// Deprecated: use [netaddr.TransportAddr].
type TransportAddr = netaddr.TransportAddr

// RelayAddr is a TransportAddr reachable via a relay server.
//
// Deprecated: use [netaddr.RelayAddr].
type RelayAddr = netaddr.RelayAddr

// IPAddr is a TransportAddr reachable at an IP socket address.
//
// Deprecated: use [netaddr.IPAddr].
type IPAddr = netaddr.IPAddr

// CustomAddr is a custom transport address.
//
// Deprecated: use [netaddr.CustomAddr].
type CustomAddr = netaddr.CustomAddr

// EndpointAddr combines an endpoint id with the network-level addresses at
// which it may be reached.
//
// Deprecated: use [netaddr.EndpointAddr].
type EndpointAddr = netaddr.EndpointAddr

var (
	// ErrParseRelayUrl is returned when a relay URL cannot be parsed.
	//
	// Deprecated: use [netaddr.ErrParseRelayUrl].
	ErrParseRelayUrl = netaddr.ErrParseRelayUrl
	// ErrCustomAddrMissingSeparator is returned when a custom address is
	// missing its "_" separator.
	//
	// Deprecated: use [netaddr.ErrCustomAddrMissingSeparator].
	ErrCustomAddrMissingSeparator = netaddr.ErrCustomAddrMissingSeparator
	// ErrCustomAddrInvalidId is returned when a custom address id is invalid.
	//
	// Deprecated: use [netaddr.ErrCustomAddrInvalidId].
	ErrCustomAddrInvalidId = netaddr.ErrCustomAddrInvalidId
	// ErrCustomAddrInvalidData is returned when custom address data is invalid.
	//
	// Deprecated: use [netaddr.ErrCustomAddrInvalidData].
	ErrCustomAddrInvalidData = netaddr.ErrCustomAddrInvalidData
	// ErrCustomAddrTooShort is returned when custom address data is too short.
	//
	// Deprecated: use [netaddr.ErrCustomAddrTooShort].
	ErrCustomAddrTooShort = netaddr.ErrCustomAddrTooShort
)

// ParseRelayUrl parses s into a RelayUrl.
//
// Deprecated: use [netaddr.ParseRelayUrl].
func ParseRelayUrl(s string) (RelayUrl, error) { return netaddr.ParseRelayUrl(s) }

// RelayUrlFromURL wraps an already-parsed URL as a RelayUrl.
//
// Deprecated: use [netaddr.RelayUrlFromURL].
func RelayUrlFromURL(u *url.URL) RelayUrl { return netaddr.RelayUrlFromURL(u) }

// NewCustomAddr creates a CustomAddr from a transport id and raw address data.
//
// Deprecated: use [netaddr.NewCustomAddr].
func NewCustomAddr(id uint64, data []byte) CustomAddr { return netaddr.NewCustomAddr(id, data) }

// ParseCustomAddr parses a CustomAddr from its string form.
//
// Deprecated: use [netaddr.ParseCustomAddr].
func ParseCustomAddr(s string) (CustomAddr, error) { return netaddr.ParseCustomAddr(s) }

// CustomAddrFromBytes parses a CustomAddr from its binary encoding.
//
// Deprecated: use [netaddr.CustomAddrFromBytes].
func CustomAddrFromBytes(data []byte) (CustomAddr, error) {
	return netaddr.CustomAddrFromBytes(data)
}

// ParseTransportAddr parses a TransportAddr from its string form.
//
// Deprecated: use [netaddr.ParseTransportAddr].
func ParseTransportAddr(s string) (TransportAddr, error) { return netaddr.ParseTransportAddr(s) }

// NewEndpointAddr creates an EndpointAddr with the given id and no addresses.
//
// Deprecated: use [netaddr.NewEndpointAddr].
func NewEndpointAddr(id key.EndpointId) EndpointAddr { return netaddr.NewEndpointAddr(id) }

// EndpointAddrFromParts creates an EndpointAddr from an id and transport
// addresses.
//
// Deprecated: use [netaddr.EndpointAddrFromParts].
func EndpointAddrFromParts(id key.EndpointId, addrs ...TransportAddr) EndpointAddr {
	return netaddr.EndpointAddrFromParts(id, addrs...)
}
