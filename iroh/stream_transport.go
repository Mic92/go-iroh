package iroh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// TransportLinkClass names the physical or logical link a stream transport uses.
type TransportLinkClass string

const (
	TransportLinkRDMA        TransportLinkClass = "rdma"
	TransportLinkLoopback    TransportLinkClass = "loopback"
	TransportLinkThunderbolt TransportLinkClass = "thunderbolt"
	TransportLinkAWDL        TransportLinkClass = "awdl"
	TransportLinkWiredLAN    TransportLinkClass = "wired-lan"
	TransportLinkWiFiLAN     TransportLinkClass = "wifi-lan"
	TransportLinkLAN         TransportLinkClass = "lan"
	TransportLinkUnknown     TransportLinkClass = "unknown"
)

// StreamOpenToken authorizes one TCP-like side-channel open.
type StreamOpenToken struct {
	LocalID     string
	RemoteID    string
	ALPN        string
	StableID    uint64
	TransportID uint64
	Purpose     string
	Nonce       string
	Expiry      time.Time
}

// StreamOptions configures a TCP-like side-channel open.
type StreamOptions struct {
	ConnectionID uint64
	Purpose      string
	Token        StreamOpenToken
}

// StreamAccept is one accepted TCP-like side-channel stream.
type StreamAccept struct {
	Conn  net.Conn
	Token StreamOpenToken
}

// StreamTransport is a TCP-like bulk transport for LAN-class links.
type StreamTransport interface {
	ID() uint64
	LocalAddrs(context.Context) ([]netaddr.CustomAddr, error)
	DialStream(context.Context, netaddr.CustomAddr, StreamOptions) (net.Conn, error)
	ListenStreams(context.Context, func(StreamAccept) error) error
}

// NewStreamOpenToken returns a token bound to c and transportID.
func (c *Conn) NewStreamOpenToken(transportID uint64, purpose string, ttl time.Duration) (StreamOpenToken, error) {
	if c == nil {
		return StreamOpenToken{}, errors.New("iroh: nil connection")
	}
	if ttl <= 0 {
		return StreamOpenToken{}, errors.New("iroh: non-positive stream token ttl")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return StreamOpenToken{}, err
	}
	return StreamOpenToken{
		RemoteID:    c.remoteID.String(),
		ALPN:        c.alpn,
		StableID:    c.stableID,
		TransportID: transportID,
		Purpose:     purpose,
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce[:]),
		Expiry:      time.Now().Add(ttl),
	}, nil
}

// ValidateStreamOpenToken reports whether tok is bound to c and still valid.
func (c *Conn) ValidateStreamOpenToken(tok StreamOpenToken, now time.Time) error {
	if c == nil {
		return errors.New("iroh: nil connection")
	}
	if now.After(tok.Expiry) {
		return errors.New("iroh: stream token expired")
	}
	if tok.RemoteID != c.remoteID.String() {
		return errors.New("iroh: stream token endpoint mismatch")
	}
	if tok.ALPN != c.alpn {
		return errors.New("iroh: stream token alpn mismatch")
	}
	if tok.StableID == 0 {
		return errors.New("iroh: stream token missing stable id")
	}
	if tok.TransportID == 0 {
		return errors.New("iroh: stream token missing transport id")
	}
	if tok.Nonce == "" {
		return errors.New("iroh: stream token missing nonce")
	}
	return nil
}
