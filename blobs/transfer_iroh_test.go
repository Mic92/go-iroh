package blobs_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestSingleLeafTransferIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data := []byte("single leaf over iroh")
	hash := blobs.NewHash(data)

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		blobs.ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			return blobs.ServeSingleLeaf(ctx, s, blobs.SingleLeafStoreFunc(func(got blobs.Hash) ([]byte, bool) {
				if got != hash {
					return nil, false
				}
				return append([]byte(nil), data...), true
			}))
		}),
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, blobs.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	got, err := blobs.GetSingleLeaf(ctx, s, hash)
	if err != nil {
		t.Fatalf("get single leaf: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("data = %q, want %q", got, data)
	}
}
