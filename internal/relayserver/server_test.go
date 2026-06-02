package relayserver

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestRelayServerForwardsDatagramAndPong(t *testing.T) {
	ts := httptest.NewServer(New())
	defer ts.Close()

	u, err := netaddr.ParseRelayUrl(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sk1, _ := key.GenerateSecretKey()
	c1, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk1})
	if err != nil {
		t.Fatalf("connect c1: %v", err)
	}
	defer c1.Close()

	sk2, _ := key.GenerateSecretKey()
	c2, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk2})
	if err != nil {
		t.Fatalf("connect c2: %v", err)
	}
	defer c2.Close()

	var ping [8]byte
	copy(ping[:], "pingpong")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	pong, err := c1.Recv(ctx)
	if err != nil {
		t.Fatalf("recv pong: %v", err)
	}
	if pong.Type != relayproto.FramePong || pong.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", pong)
	}

	payload := []byte("hello relay")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointId: sk2.Public(),
		Datagrams:     relayproto.DatagramsFromBytes(payload),
	}); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	got, err := c2.Recv(ctx)
	if err != nil {
		t.Fatalf("recv forwarded datagram: %v", err)
	}
	if got.Type != relayproto.FrameRelayToClientDatagram {
		t.Fatalf("type = %v, want datagram", got.Type)
	}
	if !got.RemoteEndpointId.Equal(sk1.Public()) {
		t.Fatalf("remote id = %s, want %s", got.RemoteEndpointId, sk1.Public())
	}
	if string(got.Datagrams.Contents) != string(payload) {
		t.Fatalf("datagram = %q, want %q", got.Datagrams.Contents, payload)
	}
}
