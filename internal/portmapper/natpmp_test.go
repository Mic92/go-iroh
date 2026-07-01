package portmapper

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestNATPMPMapUDP(t *testing.T) {
	server := newNATPMPTestServer(t)
	client := NATPMPClient{
		Gateway: netip.MustParseAddr("127.0.0.1"),
		Port:    server.port,
		Timeout: time.Second,
	}

	mapping, err := client.MapUDP(context.Background(), 1234, 1234, time.Hour)
	if err != nil {
		t.Fatalf("MapUDP: %v", err)
	}
	if mapping.ExternalAddr != netip.MustParseAddrPort("203.0.113.10:4321") {
		t.Fatalf("external addr = %s, want 203.0.113.10:4321", mapping.ExternalAddr)
	}
	if mapping.Lifetime != time.Hour {
		t.Fatalf("lifetime = %s, want 1h", mapping.Lifetime)
	}
	internal, suggested, lifetime := server.lastRequest()
	if internal != 1234 || suggested != 1234 || lifetime != 3600 {
		t.Fatalf("request = internal %d suggested %d lifetime %d", internal, suggested, lifetime)
	}
}

func TestNATPMPMapUDPDelete(t *testing.T) {
	server := newNATPMPTestServer(t)
	client := NATPMPClient{Gateway: netip.MustParseAddr("127.0.0.1"), Port: server.port, Timeout: time.Second}

	if _, err := client.MapUDP(context.Background(), 1234, 0, 0); err != nil {
		t.Fatalf("delete MapUDP: %v", err)
	}
	_, _, lifetime := server.lastRequest()
	if lifetime != 0 {
		t.Fatalf("delete lifetime = %d, want 0", lifetime)
	}
}

func TestNATPMPInvalidGateway(t *testing.T) {
	client := NATPMPClient{Gateway: netip.MustParseAddr("2001:db8::1"), Timeout: time.Millisecond}
	if _, err := client.MapUDP(context.Background(), 1234, 0, time.Hour); err == nil {
		t.Fatal("MapUDP invalid gateway error = nil")
	}
}

type natPMPTestServer struct {
	conn          *net.UDPConn
	port          uint16
	mu            sync.Mutex
	lastInternal  uint16
	lastSuggested uint16
	lastLifetime  uint32
}

func newNATPMPTestServer(t *testing.T) *natPMPTestServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	s := &natPMPTestServer{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve(t)
	return s
}

func (s *natPMPTestServer) serve(t *testing.T) {
	t.Helper()
	buf := make([]byte, 64)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		switch {
		case len(req) == 2 && req[0] == natPMPVersion && req[1] == natPMPPublicAddr:
			resp := make([]byte, 12)
			resp[1] = natPMPResponse | natPMPPublicAddr
			copy(resp[8:12], []byte{203, 0, 113, 10})
			_, _ = s.conn.WriteToUDP(resp, addr)
		case len(req) == 12 && req[0] == natPMPVersion && req[1] == natPMPMapUDP:
			s.mu.Lock()
			s.lastInternal = binary.BigEndian.Uint16(req[4:6])
			s.lastSuggested = binary.BigEndian.Uint16(req[6:8])
			s.lastLifetime = binary.BigEndian.Uint32(req[8:12])
			s.mu.Unlock()
			resp := make([]byte, 16)
			resp[1] = natPMPResponse | natPMPMapUDP
			binary.BigEndian.PutUint16(resp[8:10], s.lastInternal)
			binary.BigEndian.PutUint16(resp[10:12], 4321)
			binary.BigEndian.PutUint32(resp[12:16], s.lastLifetime)
			_, _ = s.conn.WriteToUDP(resp, addr)
		default:
			t.Errorf("unexpected request %x", req)
		}
	}
}

func (s *natPMPTestServer) lastRequest() (internal, suggested uint16, lifetime uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastInternal, s.lastSuggested, s.lastLifetime
}
