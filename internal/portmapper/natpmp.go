// Package portmapper is a minimal NAT-PMP (RFC 6886) client for requesting a
// UDP port mapping from a home gateway.
package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	natPMPPort       = 5351
	natPMPVersion    = 0
	natPMPPublicAddr = 0
	natPMPMapUDP     = 1
	natPMPResponse   = 0x80
)

// NATPMPClient is a minimal NAT-PMP client.
type NATPMPClient struct {
	Gateway netip.Addr
	Port    uint16
	Timeout time.Duration
}

// Mapping is a UDP port mapping returned by a gateway.
type Mapping struct {
	ExternalAddr netip.AddrPort
	Lifetime     time.Duration
}

// MapUDP maps internalPort through the NAT-PMP gateway, requesting the given
// lifetime. A lifetime of 0 deletes the mapping (RFC 6886 §3.4): the gateway
// removes any mapping for internalPort and returns a zero Mapping.
func (c NATPMPClient) MapUDP(ctx context.Context, internalPort uint16, suggestedExternalPort uint16, lifetime time.Duration) (Mapping, error) {
	if internalPort == 0 {
		return Mapping{}, errors.New("portmapper: zero internal port")
	}
	seconds := uint32(lifetime / time.Second)
	public, err := c.ExternalIPv4(ctx)
	if err != nil {
		return Mapping{}, err
	}
	req := make([]byte, 12)
	req[0] = natPMPVersion
	req[1] = natPMPMapUDP
	binary.BigEndian.PutUint16(req[4:6], internalPort)
	binary.BigEndian.PutUint16(req[6:8], suggestedExternalPort)
	binary.BigEndian.PutUint32(req[8:12], seconds)
	resp, err := c.roundTrip(ctx, req, 16)
	if err != nil {
		return Mapping{}, err
	}
	if resp[1] != natPMPResponse|natPMPMapUDP {
		return Mapping{}, fmt.Errorf("portmapper: unexpected nat-pmp opcode %d", resp[1])
	}
	if err := natPMPResult(resp[2:4]); err != nil {
		return Mapping{}, err
	}
	if got := binary.BigEndian.Uint16(resp[8:10]); got != internalPort {
		return Mapping{}, fmt.Errorf("portmapper: mapped internal port %d, want %d", got, internalPort)
	}
	externalPort := binary.BigEndian.Uint16(resp[10:12])
	gotLifetime := time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second
	return Mapping{
		ExternalAddr: netip.AddrPortFrom(public, externalPort),
		Lifetime:     gotLifetime,
	}, nil
}

// ExternalIPv4 returns the public IPv4 address reported by the gateway.
func (c NATPMPClient) ExternalIPv4(ctx context.Context) (netip.Addr, error) {
	resp, err := c.roundTrip(ctx, []byte{natPMPVersion, natPMPPublicAddr}, 12)
	if err != nil {
		return netip.Addr{}, err
	}
	if resp[1] != natPMPResponse|natPMPPublicAddr {
		return netip.Addr{}, fmt.Errorf("portmapper: unexpected nat-pmp opcode %d", resp[1])
	}
	if err := natPMPResult(resp[2:4]); err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte(resp[8:12])), nil
}

func (c NATPMPClient) roundTrip(ctx context.Context, req []byte, want int) ([]byte, error) {
	gateway := c.Gateway
	if !gateway.IsValid() || !gateway.Is4() {
		return nil, errors.New("portmapper: invalid nat-pmp gateway")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	port := c.Port
	if port == 0 {
		port = natPMPPort
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", netip.AddrPortFrom(gateway, port).String())
	if err != nil {
		return nil, fmt.Errorf("portmapper: dial nat-pmp gateway: %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("portmapper: write nat-pmp request: %w", err)
	}
	resp := make([]byte, want)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("portmapper: read nat-pmp response: %w", err)
	}
	if n != want {
		return nil, fmt.Errorf("portmapper: short nat-pmp response %d, want %d", n, want)
	}
	if resp[0] != natPMPVersion {
		return nil, fmt.Errorf("portmapper: unexpected nat-pmp version %d", resp[0])
	}
	return resp, nil
}

func natPMPResult(b []byte) error {
	code := binary.BigEndian.Uint16(b)
	if code == 0 {
		return nil
	}
	return fmt.Errorf("portmapper: nat-pmp result code %d", code)
}
