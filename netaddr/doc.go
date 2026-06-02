// Package netaddr provides endpoint and transport addresses for go-iroh.
//
// An [EndpointAddr] combines a key.EndpointId with the network-level
// [TransportAddr] values at which the endpoint may be reached. A transport
// address is a [RelayAddr], [IPAddr], or [CustomAddr]. A [RelayUrl] identifies
// an iroh relay server.
package netaddr
